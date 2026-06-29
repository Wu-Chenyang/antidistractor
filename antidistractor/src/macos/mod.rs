//! macOS-specific implementation modules.
//!
//! This module provides macOS equivalents for Linux features:
//! - Network blocking: PF firewall + /etc/hosts (replaces eBPF TC classifier)
//! - App blocking: process polling + SIGKILL (replaces fanotify)
//! - Process freezing: SIGSTOP/SIGCONT with sysctl proc enumeration (replaces /proc scan)
//! - Screen lock: pmset/screensaver (replaces PAM + D-Bus)
//! - Notifications: osascript (replaces notify-send)
//! - Daemon: launchd (replaces systemd)

pub mod pf_blocker;
pub mod app_watcher;
pub mod process_utils;
pub mod screen_lock;
pub mod notifications;

pub use pf_blocker::PfBlocker;
pub use app_watcher::BlockedSet;
