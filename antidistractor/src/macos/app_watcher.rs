//! macOS app launch blocker using process polling + SIGKILL.
//!
//! Replaces Linux fanotify FAN_OPEN_EXEC_PERM. Since macOS lacks a kernel-level
//! exec interception API (without the Endpoint Security framework, which requires
//! entitlements and App Store distribution), we use a polling approach:
//!
//! 1. A background thread polls the process list every 500ms (configurable).
//! 2. When a blocked app is found running, it receives SIGKILL immediately.
//! 3. A macOS notification is sent to inform the user.
//!
//! Limitations vs Linux fanotify:
//! - Small window (~0-500ms) where the blocked app can run before being killed
//! - Higher CPU overhead from constant process enumeration
//! - Cannot prevent the app from launching, only terminate it quickly

use crate::macos::notifications;
use crate::macos::process_utils;
use log::info;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Set of blocked applications. Can be modified at runtime by the control server.
#[derive(Default)]
pub struct BlockedSet {
    /// Exact executable paths (e.g., "/Applications/WeChat.app/Contents/MacOS/WeChat")
    pub paths: HashSet<String>,
    /// Process name basenames (e.g., "WeChat", "Bilibili")
    pub names: HashSet<String>,
    /// Prefix wildcard patterns ending with '*' (e.g., "bilibili*").
    /// Matches any process whose basename starts with the given prefix (case-sensitive).
    pub patterns: HashSet<String>,
}

impl BlockedSet {
    /// Check if the given executable path matches any blocked entry.
    pub fn is_blocked(&self, exe_path: &str, comm: &str) -> bool {
        // Exact path match
        if self.paths.contains(exe_path) {
            return true;
        }

        // Basename match against exe path (exact + prefix wildcard)
        if !exe_path.is_empty() {
            if let Some(name) = std::path::Path::new(exe_path).file_name() {
                if let Some(s) = name.to_str() {
                    if self.names.contains(s) {
                        return true;
                    }
                    // Prefix wildcard: pattern ends with '*'
                    for pattern in &self.patterns {
                        if let Some(prefix) = pattern.strip_suffix('*') {
                            if s.starts_with(prefix) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Comm match (process name, may be truncated to 16 chars on macOS)
        if self.names.contains(comm) {
            return true;
        }
        // Comm prefix wildcard match
        for pattern in &self.patterns {
            if let Some(prefix) = pattern.strip_suffix('*') {
                if comm.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }
}

/// App watcher that polls processes and kills blocked applications.
#[allow(dead_code)]
pub struct AppWatcher {
    /// Set of blocked applications
    pub blocked: Arc<Mutex<BlockedSet>>,
    /// How often to poll the process list
    poll_interval: Duration,
}

impl AppWatcher {
    /// Create a new AppWatcher with default 500ms poll interval.
    pub fn new() -> Self {
        AppWatcher {
            blocked: Arc::new(Mutex::new(BlockedSet::default())),
            poll_interval: Duration::from_millis(500),
        }
    }

    /// Create an AppWatcher with a custom poll interval.
    pub fn with_interval(interval: Duration) -> Self {
        AppWatcher {
            blocked: Arc::new(Mutex::new(BlockedSet::default())),
            poll_interval: interval,
        }
    }

    /// Run the polling loop (blocking). Call this from a dedicated thread.
    ///
    /// Each iteration:
    /// 1. Enumerate all running processes
    /// 2. Check each against the blocked set
    /// 3. SIGKILL any blocked processes
    /// 4. Send a desktop notification for each kill
    pub fn run(self) {
        let my_pid = unsafe { libc::getpid() };
        info!("[app-watcher] Started polling for blocked apps (interval={}ms)",
              self.poll_interval.as_millis());

        loop {
            std::thread::sleep(self.poll_interval);
            self.check_and_kill(my_pid);
        }
    }

    /// Shared reference version for use from an Arc.
    pub fn run_shared(blocked: Arc<Mutex<BlockedSet>>, interval: Duration) {
        let my_pid = unsafe { libc::getpid() };
        info!("[app-watcher] Started polling for blocked apps (interval={}ms)",
              interval.as_millis());

        loop {
            std::thread::sleep(interval);
            let processes = process_utils::list_all_processes();

            let blocked_guard = blocked.lock().unwrap();
            let mut to_kill: Vec<(i32, String, String)> = Vec::new();

            for p in &processes {
                if p.pid == my_pid || p.pid <= 1 {
                    continue; // Never kill ourselves or launchd
                }

                // Get exe path lazily (only if comm matches something in names)
                let exe_path = if blocked_guard.names.contains(&p.comm)
                    || blocked_guard.paths.iter().any(|path| {
                        std::path::Path::new(path)
                            .file_name()
                            .map(|n| n.to_string_lossy() == p.comm.as_str())
                            .unwrap_or(false)
                    }) {
                    process_utils::get_exe_path(p.pid)
                } else {
                    p.exe_path.clone()
                };

                if blocked_guard.is_blocked(&exe_path, &p.comm) {
                    to_kill.push((p.pid, p.comm.clone(), exe_path));
                }
            }
            drop(blocked_guard);

            for (pid, comm, exe_path) in to_kill {
                let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
                if ret == 0 {
                    let name = if !exe_path.is_empty() {
                        std::path::Path::new(&exe_path)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| comm.clone())
                    } else {
                        comm.clone()
                    };
                    info!("[app-watcher] KILL pid={} name='{}'", pid, name);
                    // Notify in background to avoid blocking the poll loop
                    let name_clone = name.clone();
                    std::thread::spawn(move || {
                        notifications::send_app_blocked_notification(&name_clone);
                    });
                }
            }
        }
    }

    fn check_and_kill(&self, my_pid: i32) {
        let processes = process_utils::list_all_processes();
        let blocked = self.blocked.lock().unwrap();
        let mut to_kill: Vec<(i32, String, String)> = Vec::new();

        for p in &processes {
            if p.pid == my_pid || p.pid <= 1 {
                continue;
            }

            // Lazy exe path resolution
            let exe_path = if blocked.names.contains(&p.comm) || !blocked.paths.is_empty() {
                process_utils::get_exe_path(p.pid)
            } else {
                String::new()
            };

            if blocked.is_blocked(&exe_path, &p.comm) {
                to_kill.push((p.pid, p.comm.clone(), exe_path));
            }
        }
        drop(blocked);

        for (pid, comm, exe_path) in to_kill {
            let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
            if ret == 0 {
                let name = if !exe_path.is_empty() {
                    std::path::Path::new(&exe_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| comm.clone())
                } else {
                    comm.clone()
                };
                info!("[app-watcher] KILL pid={} name='{}'", pid, name);
                let name_clone = name.clone();
                std::thread::spawn(move || {
                    notifications::send_app_blocked_notification(&name_clone);
                });
            }
        }
    }
}

impl Default for AppWatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_set_path_match() {
        let mut set = BlockedSet::default();
        set.paths.insert("/Applications/WeChat.app/Contents/MacOS/WeChat".to_string());
        assert!(set.is_blocked("/Applications/WeChat.app/Contents/MacOS/WeChat", "WeChat"));
        assert!(!set.is_blocked("/Applications/Other.app/Contents/MacOS/Other", "Other"));
    }

    #[test]
    fn test_blocked_set_name_match() {
        let mut set = BlockedSet::default();
        set.names.insert("WeChat".to_string());
        assert!(set.is_blocked("/Applications/WeChat.app/Contents/MacOS/WeChat", "WeChat"));
        assert!(set.is_blocked("", "WeChat")); // comm match
        assert!(!set.is_blocked("/Applications/Other.app/Other", "Other"));
    }

    #[test]
    fn test_blocked_set_basename_match() {
        let mut set = BlockedSet::default();
        set.names.insert("WeChat".to_string());
        assert!(set.is_blocked("/opt/wechat/WeChat", "WeChat"));
        assert!(!set.is_blocked("/opt/wechat/wechat", "wechat")); // case-sensitive
    }
}
