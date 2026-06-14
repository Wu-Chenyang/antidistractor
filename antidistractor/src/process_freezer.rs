//! Process freezer — 通过 SIGSTOP/SIGCONT 冻结/恢复进程组。
//!
//! 按进程名（basename）在 /proc 中查找所有匹配的 PID，
//! 对每个 PID 及其同进程组的所有子进程发送信号。
//! SIGSTOP 不可被捕获或忽略，进程会立即挂起；SIGCONT 恢复。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// 当前被冻结的进程名集合（及其快照 PID 列表，用于精确 SIGCONT）
#[derive(Default)]
pub struct FreezerState {
    /// name → 冻结时捕获的 PID 集合（SIGCONT 时精确恢复）
    frozen: HashMap<String, HashSet<i32>>,
}

impl FreezerState {
    pub fn frozen_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.frozen.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn is_frozen(&self, name: &str) -> bool {
        self.frozen.contains_key(name)
    }
}

/// 在 /proc 中按进程名查找所有匹配的 PID。
/// 对每个 /proc/<pid>/comm 或 /proc/<pid>/exe basename 进行匹配。
fn find_pids_by_name(name: &str) -> Vec<i32> {
    let mut pids = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else { return pids };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        let Ok(pid) = fname.parse::<i32>() else { continue };

        // 方法1：读 /proc/<pid>/comm（最多16字节进程名）
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default();
        let comm = comm.trim();

        // 方法2：读 /proc/<pid>/exe basename（完整名称，解决 comm 截断问题）
        let exe_name = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();

        if comm == name || exe_name == name {
            pids.push(pid);
        }
    }
    pids
}

/// 向一个 PID 及其所有子进程（递归）发送信号。
/// 先冻结子进程再冻结父进程，避免父进程 fork 新子进程漏掉。
fn signal_process_tree(root_pid: i32, sig: libc::c_int) -> Vec<i32> {
    // 构建 PID → children 映射
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else { return vec![] };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Ok(pid) = fname.to_string_lossy().parse::<i32>() else { continue };
        // 读 /proc/<pid>/status 找 PPid
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap_or_default();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:\t") {
                if let Ok(ppid) = rest.trim().parse::<i32>() {
                    children.entry(ppid).or_default().push(pid);
                }
                break;
            }
        }
    }

    // DFS 收集整棵树（后序：子先于父）
    let mut order = Vec::new();
    let mut stack = vec![root_pid];
    let mut visited = HashSet::new();
    while let Some(pid) = stack.pop() {
        if !visited.insert(pid) { continue; }
        if let Some(kids) = children.get(&pid) {
            for &child in kids {
                stack.push(child);
            }
        }
        order.push(pid); // 收集到后序
    }

    // 后序发送信号（子先于父，防止 SIGSTOP 时父 fork 新子漏掉）
    let mut signaled = Vec::new();
    for pid in order.iter().rev() {
        let ret = unsafe { libc::kill(*pid, sig) };
        if ret == 0 {
            signaled.push(*pid);
        }
    }
    signaled
}

/// 冻结指定名称的所有进程（SIGSTOP）。
/// 返回 (frozen_count, already_frozen, pids)。
pub fn freeze(state: &Arc<Mutex<FreezerState>>, name: &str) -> (usize, bool, Vec<i32>) {
    {
        let s = state.lock().unwrap();
        if s.is_frozen(name) {
            return (0, true, vec![]);
        }
    }

    let pids = find_pids_by_name(name);
    if pids.is_empty() {
        return (0, false, vec![]);
    }

    let mut all_signaled = HashSet::new();
    for pid in &pids {
        let signaled = signal_process_tree(*pid, libc::SIGSTOP);
        all_signaled.extend(signaled);
    }

    let count = all_signaled.len();
    log::info!("[freezer] SIGSTOP '{name}': {} process(es) frozen", count);

    let mut s = state.lock().unwrap();
    s.frozen.insert(name.to_string(), all_signaled.into_iter().collect::<HashSet<_>>());

    (count, false, pids)
}

/// 恢复指定名称的所有进程（SIGCONT）。
pub fn thaw(state: &Arc<Mutex<FreezerState>>, name: &str) -> (usize, bool) {
    let frozen_pids = {
        let mut s = state.lock().unwrap();
        s.frozen.remove(name)
    };

    let Some(pids) = frozen_pids else {
        return (0, false); // 不在冻结列表中
    };

    let mut count = 0;
    for pid in &pids {
        let ret = unsafe { libc::kill(*pid, libc::SIGCONT) };
        if ret == 0 { count += 1; }
    }

    // 额外：再按名字扫一遍，防止 SIGSTOP 后又 fork 的子进程被漏掉
    let extra_pids = find_pids_by_name(name);
    for pid in extra_pids {
        if !pids.contains(&pid) {
            let ret = unsafe { libc::kill(pid, libc::SIGCONT) };
            if ret == 0 { count += 1; }
        }
    }

    log::info!("[freezer] SIGCONT '{name}': {} process(es) resumed", count);
    (count, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freezer_state_default() {
        let s = FreezerState::default();
        assert!(s.frozen_names().is_empty());
        assert!(!s.is_frozen("firefox"));
    }

    #[test]
    fn test_freezer_state_insert_remove() {
        let mut s = FreezerState::default();
        s.frozen.insert("WeChat".to_string(), [1234, 1235].into_iter().collect());
        assert!(s.is_frozen("WeChat"));
        assert!(!s.is_frozen("wechat")); // 大小写敏感
        assert_eq!(s.frozen_names(), vec!["WeChat"]);
        s.frozen.remove("WeChat");
        assert!(!s.is_frozen("WeChat"));
    }
}
