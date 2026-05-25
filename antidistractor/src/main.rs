mod ebpf;
mod ui;

use ebpf::EbpfManager;
use log::{info, error};
use std::process::Command;
use tokio::sync::mpsc;
use std::env;
use std::fs::File;
use simplelog::*;

fn get_default_interface() -> Option<String> {
    let output = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace().nth(4).map(|s| s.to_string())
}

/// Default blocklist domains
const DEFAULT_BLOCKLIST: &[&str] = &[
    "www.bilibili.com",
    "bilibili.com",
];

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

    // Get interface: first non-flag argument, or auto-detect
    let iface = args.iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .or_else(get_default_interface)
        .unwrap_or_else(|| "eth0".to_string());
    info!("Target Interface: {}", iface);

    if daemon_mode {
        // Daemon mode: load eBPF, add default blocklist, sleep forever
        let mut ebpf = EbpfManager::load(&iface)
            .map_err(|e| {
                error!("CRITICAL ERROR: BPF Load Failed: {}", e);
                e
            })?;

        info!("eBPF Program loaded successfully.");

        // Add default blocklist
        for domain in DEFAULT_BLOCKLIST {
            if let Err(e) = ebpf.add_domain(domain) {
                error!("Failed to add domain '{}': {}", domain, e);
            } else {
                info!("Blocked: {}", domain);
            }
        }

        info!("Daemon running. Blocking {} domains. Send SIGTERM to stop.", DEFAULT_BLOCKLIST.len());

        // Wait forever (until SIGTERM from systemd)
        tokio::signal::ctrl_c().await?;
        info!("=== Antidistractor Daemon Stopped ===");
        Ok(())
    } else {
        // Interactive TUI mode
        let (log_tx, log_rx) = mpsc::unbounded_channel();

        let ebpf = match EbpfManager::load(&iface) {
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
