//! Antidistractor — Cross-platform distraction blocker.
//!
//! Platform support:
//!   Linux: eBPF TC classifier (kernel-level network blocking) + fanotify (app blocking)
//!   macOS: PF firewall + /etc/hosts (network blocking) + process polling (app blocking)
//!
//! Both platforms use:
//!   - ratatui TUI for interactive mode
//!   - Unix socket control server for daemon mode
//!   - SIGSTOP/SIGCONT for process freezing

// ─── Platform-specific module imports ──────────────────────────────────────

#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
mod app_blocker;

#[cfg(target_os = "macos")]
mod macos;

// ─── Cross-platform modules ──────────────────────────────────────────────────

mod ui;
mod control_server;
mod process_freezer;

// ─── Linux-only imports ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
use ebpf::EbpfManager;

// ─── Common imports ──────────────────────────────────────────────────────────

use log::{info, warn, error};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use std::env;
use std::fs::File;
use simplelog::*;

// ─── Default blocked domains ─────────────────────────────────────────────────

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

// ─── Linux-only helpers ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn get_default_interface() -> Option<String> {
    let output = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace().nth(4).map(|s| s.to_string())
}

/// Detect TUN/tun-like interfaces (e.g. Mihomo, clash, tun0).
#[cfg(target_os = "linux")]
fn detect_tun_interfaces() -> Vec<String> {
    let output = match Command::new("ip").args(["-o", "link", "show", "type", "tun"]).output() {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ifaces = Vec::new();
    for line in stdout.lines() {
        if let Some(name) = line.split(':').nth(1) {
            let name = name.trim().to_string();
            if !name.is_empty() {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

/// Interval for checking new TUN interfaces (seconds) — Linux only.
#[cfg(target_os = "linux")]
const TUN_POLL_INTERVAL_SECS: u64 = 10;

// ─── macOS-only helpers ──────────────────────────────────────────────────────

/// Detect TUN-like interfaces on macOS using ifconfig.
/// Returns interfaces of type POINTOPOINT (utun*, tun*).
#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn detect_tun_interfaces_macos() -> Vec<String> {
    let output = match Command::new("ifconfig").output() {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ifaces = Vec::new();

    let mut current_iface = String::new();
    for line in stdout.lines() {
        // Interface name lines: "utun0: flags=..."
        if !line.starts_with('\t') && !line.starts_with(' ') {
            if let Some(name) = line.split(':').next() {
                current_iface = name.to_string();
            }
        }
        // Look for POINTOPOINT flag (TUN interfaces)
        if line.contains("POINTOPOINT") && !current_iface.is_empty() {
            let name = current_iface.clone();
            if name.starts_with("utun") || name.starts_with("tun") {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

// ─── Main entry point ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let daemon_mode = args.iter().any(|a| a == "--daemon" || a == "-d");
    #[allow(unused_variables)]
    let screen_lock_daemon = args.iter().any(|a| a == "--screen-lock-daemon");

    // Try to create log file
    if let Ok(log_file) = File::create("antidistractor.log") {
        let _ = WriteLogger::init(LevelFilter::Info, Config::default(), log_file);
    }

    std::panic::set_hook(Box::new(|info| {
        error!("PANIC OCCURRED: {:?}", info);
    }));

    // macOS: screen lock daemon mode (launched by launchd for enforce-lock)
    #[cfg(target_os = "macos")]
    if screen_lock_daemon {
        info!("=== Antidistractor Screen Lock Daemon Started ===");
        macos::screen_lock::run_lock_daemon();
        return Ok(());
    }

    info!("=== Antidistractor Session Started (daemon={}, os={}) ===",
          daemon_mode, std::env::consts::OS);

    if daemon_mode {
        run_daemon(args).await
    } else {
        run_interactive(args).await
    }
}

// ─── Linux daemon mode ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_daemon(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Get default interface
    let default_iface = args.iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .or_else(get_default_interface)
        .unwrap_or_else(|| "eth0".to_string());

    let tun_ifaces = detect_tun_interfaces();
    let mut all_ifaces = vec!["lo", default_iface.as_str()];
    let tun_refs: Vec<&str> = tun_ifaces.iter().map(|s| s.as_str()).collect();
    all_ifaces.extend_from_slice(&tun_refs);
    all_ifaces.sort();
    all_ifaces.dedup();

    info!("Target Interfaces: {:?}", all_ifaces);

    let ebpf_raw = EbpfManager::load(&all_ifaces)
        .map_err(|e| {
            error!("CRITICAL ERROR: BPF Load Failed: {}", e);
            e
        })?;

    info!("eBPF Program loaded successfully.");

    let ebpf = Arc::new(Mutex::new(ebpf_raw));
    let start_time = std::time::Instant::now();

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

    std::thread::spawn(move || {
        app_blocker.run();
    });

    let freezer = Arc::new(Mutex::new(process_freezer::FreezerState::default()));

    let ebpf_ctl = Arc::clone(&ebpf);
    let blocked_apps_ctl = Arc::clone(&blocked_apps);
    let freezer_ctl = Arc::clone(&freezer);
    tokio::spawn(async move {
        if let Err(e) = control_server::run_control_server(
            ebpf_ctl, blocked_apps_ctl, freezer_ctl, start_time
        ).await {
            error!("[control-server] Fatal error: {}", e);
        }
    });

    let mut attached: HashSet<String> = all_ifaces.iter().map(|s| s.to_string()).collect();
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
}

// ─── macOS daemon mode ────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn run_daemon(_args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Antidistractor macOS Daemon Starting ===");
    info!("Using PF firewall + /etc/hosts for network blocking");

    let start_time = std::time::Instant::now();

    // Initialize PF blocker
    let pf_blocker = Arc::new(Mutex::new(macos::PfBlocker::new()));
    {
        let mut blocker = pf_blocker.lock().unwrap();
        if let Err(e) = blocker.enable() {
            error!("[pf-blocker] Failed to enable PF: {}. Continuing with hosts-only mode.", e);
        }

        for domain in DEFAULT_BLOCKLIST {
            if let Err(e) = blocker.add_domain(domain) {
                error!("Failed to block domain '{}': {}", domain, e);
            } else {
                info!("Blocked: {}", domain);
            }
        }
    }

    info!("Daemon running. Blocking {} domains via PF + hosts. Send SIGTERM to stop.",
          DEFAULT_BLOCKLIST.len());

    // Start DNS refresh background task
    macos::PfBlocker::start_dns_refresh_task(Arc::clone(&pf_blocker));

    // Initialize app watcher (process polling)
    let blocked_apps = Arc::new(Mutex::new(macos::BlockedSet::default()));
    let blocked_apps_watch = Arc::clone(&blocked_apps);
    std::thread::spawn(move || {
        macos::app_watcher::AppWatcher::run_shared(
            blocked_apps_watch,
            std::time::Duration::from_millis(500),
        );
    });

    // Initialize process freezer
    let freezer = Arc::new(Mutex::new(process_freezer::FreezerState::default()));

    // Spawn control server
    let pf_ctl = Arc::clone(&pf_blocker);
    let blocked_apps_ctl = Arc::clone(&blocked_apps);
    let freezer_ctl = Arc::clone(&freezer);
    tokio::spawn(async move {
        if let Err(e) = control_server::run_control_server_macos(
            pf_ctl, blocked_apps_ctl, freezer_ctl, start_time
        ).await {
            error!("[control-server] Fatal error: {}", e);
        }
    });

    // Wait for SIGTERM/Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("=== Antidistractor macOS Daemon Stopped ===");

    // Cleanup: disable PF anchor and remove hosts entries
    let mut blocker = pf_blocker.lock().unwrap();
    if let Err(e) = blocker.disable() {
        warn!("[pf-blocker] Error during cleanup: {}", e);
    }

    Ok(())
}

// ─── Interactive (TUI) mode — Linux ──────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_interactive(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let default_iface = args.iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .or_else(get_default_interface)
        .unwrap_or_else(|| "eth0".to_string());

    let tun_ifaces = detect_tun_interfaces();
    let mut all_ifaces = vec!["lo", default_iface.as_str()];
    let tun_refs: Vec<&str> = tun_ifaces.iter().map(|s| s.as_str()).collect();
    all_ifaces.extend_from_slice(&tun_refs);
    all_ifaces.sort();
    all_ifaces.dedup();

    info!("Target Interfaces: {:?}", all_ifaces);

    let (log_tx, log_rx) = mpsc::unbounded_channel();

    let ebpf = match EbpfManager::load(&all_ifaces) {
        Ok(manager) => {
            info!("eBPF Program loaded successfully.");
            Some(ui::BlockerBackend::Ebpf(manager))
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

// ─── Interactive (TUI) mode — macOS ──────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn run_interactive(_args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let (log_tx, log_rx) = mpsc::unbounded_channel();

    let pf_blocker = match macos::PfBlocker::new_and_enable() {
        Ok(b) => {
            info!("PF blocker initialized.");
            let _ = log_tx.send("PF + hosts blocking active".to_string());
            Some(ui::BlockerBackend::Pf(b))
        }
        Err(e) => {
            error!("Failed to initialize PF blocker: {}", e);
            let _ = log_tx.send(format!("PF init error: {} (running without blocking)", e));
            None
        }
    };

    let result = ui::run_ui(pf_blocker, log_rx).await;
    if let Err(e) = &result { error!("UI Error: {:?}", e); }
    info!("=== Antidistractor Session Ended ===\n");
    result
}
