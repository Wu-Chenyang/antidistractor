mod ebpf;
mod ui;
mod control_server;
mod app_blocker;

use ebpf::EbpfManager;
use log::{info, warn, error};
use std::collections::HashSet;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use std::env;
use std::fs::File;
use simplelog::*;

fn get_default_interface() -> Option<String> {
    let output = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace().nth(4).map(|s| s.to_string())
}

/// Detect TUN/tun-like interfaces (e.g. Mihomo, clash, tun0).
/// These are POINTOPOINT interfaces that proxy traffic may use to bypass the
/// default network interface.
fn detect_tun_interfaces() -> Vec<String> {
    let output = match Command::new("ip").args(["-o", "link", "show", "type", "tun"]).output() {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ifaces = Vec::new();
    for line in stdout.lines() {
        // Format: "36: Mihomo: <POINTOPOINT,...> ..."
        if let Some(name) = line.split(':').nth(1) {
            let name = name.trim().to_string();
            if !name.is_empty() {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

/// Default blocklist domains
const DEFAULT_BLOCKLIST: &[&str] = &[
    "bilibili.com",
    "www.bilibili.com",
    "m.bilibili.com",
    "api.bilibili.com",
    "api.vc.bilibili.com",
    "app.bilibili.com",
    "live.bilibili.com",
    "t.bilibili.com",
    "space.bilibili.com",
    "search.bilibili.com",
    "member.bilibili.com",
    "passport.bilibili.com",
    "account.bilibili.com",
    "manga.bilibili.com",
    "hdslb.com",
    "www.hdslb.com",
    "i0.hdslb.com",
    "i1.hdslb.com",
    "i2.hdslb.com",
    "s1.hdslb.com",
    "bilivideo.com",
    "bilivideo.cn",
    "biliapi.net",
    "biliapi.com",
];

/// Interval for checking new TUN interfaces (seconds)
const TUN_POLL_INTERVAL_SECS: u64 = 10;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let daemon_mode = args.iter().any(|a| a == "--daemon" || a == "-d");

    // Try to create log file; if it fails (e.g. permission denied), continue without file logging
    if let Ok(log_file) = File::create("antidistractor.log") {
        let _ = WriteLogger::init(LevelFilter::Info, Config::default(), log_file);
    }

    std::panic::set_hook(Box::new(|info| {
        error!("PANIC OCCURRED: {:?}", info);
    }));

    info!("=== Antidistractor Session Started (daemon={}) ===", daemon_mode);

    // Get default interface: first non-flag argument, or auto-detect
    let default_iface = args.iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .or_else(get_default_interface)
        .unwrap_or_else(|| "eth0".to_string());

    // Collect all interfaces to attach: default + loopback + any detected TUN interfaces.
    // Loopback is needed to intercept TLS ClientHello sent to local proxy (e.g. Mihomo HTTP
    // proxy on 127.0.0.1:7890).
    let tun_ifaces = detect_tun_interfaces();
    let mut all_ifaces = vec!["lo", default_iface.as_str()];
    let tun_refs: Vec<&str> = tun_ifaces.iter().map(|s| s.as_str()).collect();
    all_ifaces.extend_from_slice(&tun_refs);
    // Deduplicate
    all_ifaces.sort();
    all_ifaces.dedup();

    info!("Target Interfaces: {:?}", all_ifaces);

    if daemon_mode {
        // Daemon mode: load eBPF, add default blocklist, watch for new TUN interfaces
        let ebpf_raw = EbpfManager::load(&all_ifaces)
            .map_err(|e| {
                error!("CRITICAL ERROR: BPF Load Failed: {}", e);
                e
            })?;

        info!("eBPF Program loaded successfully.");

        // Wrap in Arc<Mutex<>> for shared access across control server and main loop
        let ebpf = Arc::new(Mutex::new(ebpf_raw));
        let start_time = std::time::Instant::now();

        // Add default blocklist
        {
            let mut mgr = ebpf.lock().unwrap();
            for domain in DEFAULT_BLOCKLIST {
                if let Err(e) = mgr.add_domain(domain) {
                    error!("Failed to add domain '{}': {}", domain, e);
                } else {
                    info!("Blocked: {}", domain);
                }
            }
        }

        info!("Daemon running. Blocking {} domains on {} interface(s). Send SIGTERM to stop.",
              DEFAULT_BLOCKLIST.len(), all_ifaces.len());

        // Initialize app blocker (fanotify)
        let app_blocker = match app_blocker::AppBlocker::new() {
            Ok(b) => b,
            Err(e) => {
                error!("[app-blocker] Failed to initialize fanotify: {e}");
                return Err(e.into());
            }
        };
        let blocked_apps = Arc::clone(&app_blocker.blocked);

        // Spawn fanotify listener in a dedicated OS thread (NOT spawn_blocking).
        // Using a plain std thread ensures the fanotify loop is independent of
        // the tokio runtime, preventing any cross-exec deadlock where tokio itself
        // triggers an exec event that the same blocking thread needs to respond to.
        std::thread::spawn(move || {
            app_blocker.run();
        });

        // Spawn control server (Unix socket) in background
        let ebpf_ctl = Arc::clone(&ebpf);
        let blocked_apps_ctl = Arc::clone(&blocked_apps);
        tokio::spawn(async move {
            if let Err(e) = control_server::run_control_server(ebpf_ctl, blocked_apps_ctl, start_time).await {
                error!("[control-server] Fatal error: {}", e);
            }
        });

        // Track which interfaces we've already attached to
        let mut attached: HashSet<String> = all_ifaces.iter().map(|s| s.to_string()).collect();

        // Periodically check for new TUN interfaces (e.g. Mihomo started after us)
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(TUN_POLL_INTERVAL_SECS)
        );

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("=== Antidistractor Daemon Stopped ===");
                    break;
                }
                _ = interval.tick() => {
                    let current_tuns = detect_tun_interfaces();
                    for tun in &current_tuns {
                        if !attached.contains(tun) {
                            info!("New TUN interface detected: {}", tun);
                            let mut mgr = ebpf.lock().unwrap();
                            match mgr.attach_interface(tun) {
                                Ok(()) => {
                                    attached.insert(tun.clone());
                                    info!("Successfully attached eBPF to new TUN: {}", tun);
                                }
                                Err(e) => {
                                    warn!("Failed to attach eBPF to TUN '{}': {}", tun, e);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    } else {
        // Interactive TUI mode
        let (log_tx, log_rx) = mpsc::unbounded_channel();

        let ebpf = match EbpfManager::load(&all_ifaces) {
            Ok(manager) => {
                info!("eBPF Program loaded successfully.");
                Some(manager)
            },
            Err(e) => {
                error!("CRITICAL ERROR: BPF Load Failed: {}", e);
                let _ = log_tx.send(format!("BPF Load Error: {}", e));
                None
            }
        };

        let result = ui::run_ui(ebpf, log_rx).await;
        if let Err(e) = &result { error!("UI Error: {:?}", e); }
        info!("=== Antidistractor Session Ended ===\n");
        result
    }
}
