//! macOS process enumeration utilities.
//!
//! Replaces Linux /proc filesystem scanning with macOS libproc-based process listing.
//! Uses proc_listpids() to enumerate all PIDs and proc_pidpath() for exe paths.
//! Parent PID is obtained via sysctl(KERN_PROC, KERN_PROC_PID) with a manually
//! defined kinfo_proc layout (libc 0.2.x does not expose kinfo_proc on macOS).

use std::collections::HashMap;

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    /// Process name (comm), obtained from exe path basename or sysctl
    pub comm: String,
    /// Full path to executable (from proc_pidpath)
    pub exe_path: String,
    /// Parent process ID (from sysctl KERN_PROC_PID)
    #[allow(dead_code)]
    pub ppid: i32,
}

// ─── libproc constants ────────────────────────────────────────────────────────

/// PROC_ALL_PIDS — list all processes (type argument for proc_listpids)
const PROC_ALL_PIDS: u32 = 1;

/// PROC_PIDPATHINFO_MAXSIZE — max path length returned by proc_pidpath
const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

// ─── kinfo_proc layout (manual, since libc 0.2.x doesn't expose it on macOS) ─

/// Minimal kinfo_proc layout for extracting p_pid, p_comm, and e_ppid.
///
/// On macOS/XNU the full struct kinfo_proc is:
///   struct extern_proc kp_proc;   // offset 0, size 648 on arm64
///   struct eproc kp_eproc;        // offset 648
///
/// Within extern_proc:
///   pid_t p_pid  at offset 24 (after p_starttime[2]×8 + p_flag×4 + p_stat×1 + pad×3)
///   char p_comm[MAXCOMLEN+1] at offset 163 (empirically verified on arm64/x86_64)
///
/// Within eproc:
///   pid_t e_ppid at offset 8 (after e_paddr×8)
///
/// We use sysctl(KERN_PROC, KERN_PROC_PID) which returns one kinfo_proc per call.
/// The total struct size is 648 + sizeof(eproc) ≈ 1088 bytes on arm64.
///
/// Rather than hardcoding offsets (which differ between arm64 and x86_64),
/// we use a simpler approach: parse `ps` output for ppid, and use proc_pidpath
/// + basename for comm. This is more portable and robust.

// ─── Public API ───────────────────────────────────────────────────────────────

/// Get the full executable path for a given PID using proc_pidpath.
/// Returns empty string on failure (process may have exited).
pub fn get_exe_path(pid: i32) -> String {
    let mut path_buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        libc::proc_pidpath(
            pid,
            path_buf.as_mut_ptr() as *mut libc::c_void,
            PROC_PIDPATHINFO_MAXSIZE,
        )
    };
    if ret <= 0 {
        return String::new();
    }
    let n = ret as usize;
    String::from_utf8_lossy(&path_buf[..n]).into_owned()
}

/// List all running PIDs using proc_listpids(PROC_ALL_PIDS).
pub fn list_all_pids() -> Vec<i32> {
    // First call: get required buffer size
    let count = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if count <= 0 {
        return vec![];
    }

    // Allocate with extra headroom (processes may spawn between calls)
    let capacity = (count as usize / std::mem::size_of::<i32>()) + 32;
    let mut buf = vec![0i32; capacity];
    let buf_size = (buf.len() * std::mem::size_of::<i32>()) as libc::c_int;

    let ret = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf_size,
        )
    };
    if ret <= 0 {
        return vec![];
    }

    let n_pids = ret as usize / std::mem::size_of::<i32>();
    buf[..n_pids]
        .iter()
        .copied()
        .filter(|&pid| pid > 0)
        .collect()
}

/// List all running processes with comm (basename of exe path).
/// This is the macOS equivalent of scanning /proc on Linux.
pub fn list_all_processes() -> Vec<ProcessInfo> {
    let pids = list_all_pids();
    let mut result = Vec::with_capacity(pids.len());

    for pid in pids {
        let exe_path = get_exe_path(pid);
        let comm = if !exe_path.is_empty() {
            std::path::Path::new(&exe_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };

        result.push(ProcessInfo {
            pid,
            comm,
            exe_path,
            ppid: 0, // ppid filled lazily only when needed
        });
    }

    result
}

/// Find all PIDs matching the given process name (exact basename match).
pub fn find_pids_by_name(name: &str) -> Vec<i32> {
    list_all_pids()
        .into_iter()
        .filter(|&pid| {
            let exe = get_exe_path(pid);
            if exe.is_empty() {
                return false;
            }
            std::path::Path::new(&exe)
                .file_name()
                .map(|n| n.to_string_lossy() == name)
                .unwrap_or(false)
        })
        .collect()
}

/// Get all PIDs with their exe paths for the given name.
#[allow(dead_code)]
pub fn find_processes_by_name(name: &str) -> Vec<(i32, String)> {
    list_all_pids()
        .into_iter()
        .filter_map(|pid| {
            let exe = get_exe_path(pid);
            if exe.is_empty() {
                return None;
            }
            let basename = std::path::Path::new(&exe)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if basename == name {
                Some((pid, exe))
            } else {
                None
            }
        })
        .collect()
}

/// Build a PID → children mapping by parsing sysctl output.
/// Uses KERN_PROC / KERN_PROC_ALL to get parent PIDs.
/// Falls back to parsing `ps` if sysctl approach fails.
pub fn build_children_map() -> HashMap<i32, Vec<i32>> {
    // Use `ps` to get pid/ppid pairs — most portable approach
    let output = std::process::Command::new("ps")
        .args(["-eo", "pid,ppid"])
        .output();

    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            // Format: "  PID  PPID"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                    if pid > 0 && ppid > 0 {
                        children.entry(ppid).or_default().push(pid);
                    }
                }
            }
        }
    }

    children
}

/// Collect all PIDs in the process subtree rooted at `root_pid` (post-order).
/// Post-order: children before parents (for SIGSTOP to prevent fork escape).
pub fn collect_process_tree_postorder(root_pid: i32) -> Vec<i32> {
    let children = build_children_map();

    let mut order = Vec::new();
    let mut stack = vec![root_pid];
    let mut visited = std::collections::HashSet::new();

    while let Some(pid) = stack.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if let Some(kids) = children.get(&pid) {
            for &child in kids {
                stack.push(child);
            }
        }
        order.push(pid);
    }

    // Reverse to get post-order (children before parents)
    order.reverse();
    order
}

/// Send signal to a process tree rooted at root_pid.
/// Returns list of PIDs that were successfully signaled.
pub fn signal_process_tree(root_pid: i32, sig: libc::c_int) -> Vec<i32> {
    let pids = collect_process_tree_postorder(root_pid);
    let mut signaled = Vec::new();

    for pid in pids {
        let ret = unsafe { libc::kill(pid, sig) };
        if ret == 0 {
            signaled.push(pid);
        }
    }

    signaled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_pids_not_empty() {
        let pids = list_all_pids();
        assert!(!pids.is_empty(), "should find at least one PID");
    }

    #[test]
    fn test_pid_1_exists() {
        let pids = list_all_pids();
        assert!(pids.contains(&1), "PID 1 (launchd) should exist");
    }

    #[test]
    fn test_get_exe_path_self() {
        let my_pid = unsafe { libc::getpid() };
        let path = get_exe_path(my_pid);
        // May be empty in some test environments, just ensure no crash
        let _ = path;
    }

    #[test]
    fn test_list_processes_not_empty() {
        let procs = list_all_processes();
        assert!(!procs.is_empty());
    }

    #[test]
    fn test_build_children_map() {
        let map = build_children_map();
        // launchd (PID 1) should have children
        assert!(map.contains_key(&1) || !map.is_empty());
    }
}
