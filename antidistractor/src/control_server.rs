//! Control server — Unix domain socket server for runtime control.
//!
//! 监听 /var/run/antidistractor.sock，接受换行分隔的 JSON 命令。
//! Supports both Linux (eBPF) and macOS (PF) backends via conditional compilation.

use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};
use crate::process_freezer::FreezerState;
use std::os::unix::fs::PermissionsExt;

const SOCKET_PATH: &str = "/var/run/antidistractor.sock";

/// Inbound commands (shared between Linux and macOS)
#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlCmd {
    /// 添加域名到 blocklist
    Block { domains: Vec<String> },
    /// 从 blocklist 移除域名
    Unblock { domains: Vec<String> },
    /// 全量同步屏蔽集合（原子替换，acticat passive-block-engine 专用）
    /// 替换当前所有动态屏蔽域名和应用，实现原子 diff 语义。
    Sync {
        #[serde(default)]
        blocked_domains: Vec<String>,
        #[serde(default)]
        blocked_apps: Vec<String>,
    },
    /// 开启/关闭专注模式
    FocusMode {
        enabled: bool,
        #[serde(default)]
        domains: Vec<String>,
    },
    /// 阻止特定应用启动（通过路径或进程名）
    BlockApp {
        #[serde(default)]
        paths: Vec<String>,
        #[serde(default)]
        names: Vec<String>,
    },
    /// 取消阻止应用启动
    UnblockApp {
        #[serde(default)]
        paths: Vec<String>,
        #[serde(default)]
        names: Vec<String>,
    },
    /// 批量屏蔽应用（acticat 接口别名，apps 字段映射到 names）
    BlockApps {
        #[serde(default)]
        apps: Vec<String>,
    },
    /// 批量解除应用屏蔽（acticat 接口别名）
    UnblockApps {
        #[serde(default)]
        apps: Vec<String>,
    },
    /// 冻结进程（SIGSTOP）
    FreezeApp { names: Vec<String> },
    /// 解冻进程（SIGCONT）
    ThawApp { names: Vec<String> },
    /// 查询当前状态
    Status,
}

/// Response body
#[derive(Serialize)]
pub struct ControlResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusPayload>,
}

#[derive(Serialize)]
pub struct StatusPayload {
    pub focus_mode: bool,
    /// 当前动态屏蔽的域名（历史字段名，保留向后兼容）
    pub dynamic_blocked: Vec<String>,
    /// 当前动态屏蔽的域名（acticat 接口字段名，与 dynamic_blocked 内容相同）
    pub blocked_domains: Vec<String>,
    pub blocked_apps: BlockedAppsPayload,
    pub frozen_apps: Vec<String>,
    pub uptime_seconds: u64,
    pub platform: String,
}

#[derive(Serialize)]
pub struct BlockedAppsPayload {
    pub paths: Vec<String>,
    pub names: Vec<String>,
}

// ─── Linux control server ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
use crate::ebpf::EbpfManager;
#[cfg(target_os = "linux")]
use crate::app_blocker::BlockedSet;

#[cfg(target_os = "linux")]
pub async fn run_control_server(
    ebpf: Arc<Mutex<EbpfManager>>,
    blocked_apps: Arc<Mutex<BlockedSet>>,
    freezer: Arc<Mutex<FreezerState>>,
    start_time: std::time::Instant,
) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))?;
    log::info!("[control-server] Listening on {} (Linux/eBPF)", SOCKET_PATH);

    let dynamic_blocked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let focus_mode_active: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    loop {
        let (stream, _) = listener.accept().await?;
        let ebpf = Arc::clone(&ebpf);
        let dynamic_blocked = Arc::clone(&dynamic_blocked);
        let focus_mode_active = Arc::clone(&focus_mode_active);
        let blocked_apps = Arc::clone(&blocked_apps);
        let freezer = Arc::clone(&freezer);

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            let resp = if let Ok(Some(line)) = lines.next_line().await {
                handle_cmd_linux(&line, &ebpf, &dynamic_blocked, &focus_mode_active,
                                 &blocked_apps, &freezer, start_time)
            } else {
                ControlResp { ok: false, error: Some("empty input".into()), status: None }
            };

            let json = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false}"#.into());
            let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
        });
    }
}

#[cfg(target_os = "linux")]
fn handle_cmd_linux(
    line: &str,
    ebpf: &Arc<Mutex<EbpfManager>>,
    dynamic_blocked: &Arc<Mutex<Vec<String>>>,
    focus_mode_active: &Arc<Mutex<bool>>,
    blocked_apps: &Arc<Mutex<BlockedSet>>,
    freezer: &Arc<Mutex<FreezerState>>,
    start_time: std::time::Instant,
) -> ControlResp {
    let cmd: ControlCmd = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => return ControlResp { ok: false, error: Some(format!("parse error: {e}")), status: None },
    };

    match cmd {
        ControlCmd::Block { domains } => {
            let mut mgr = ebpf.lock().unwrap();
            let mut added = Vec::new();
            let mut errs = Vec::new();
            for d in &domains {
                match mgr.add_domain(d) {
                    Ok(_) => added.push(d.clone()),
                    Err(e) => errs.push(format!("{d}: {e}")),
                }
            }
            dynamic_blocked.lock().unwrap().extend(added);
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::Unblock { domains } => {
            let mut mgr = ebpf.lock().unwrap();
            let mut errs = Vec::new();
            for d in &domains {
                if let Err(e) = mgr.remove_domain(d) {
                    errs.push(format!("{d}: {e}"));
                }
            }
            let mut db = dynamic_blocked.lock().unwrap();
            db.retain(|d| !domains.contains(d));
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::Sync { blocked_domains, blocked_apps: new_app_names } => {
            // 原子替换：先清空所有动态屏蔽，再批量添加新集合
            let mut mgr = ebpf.lock().unwrap();
            let mut db = dynamic_blocked.lock().unwrap();
            // 清空现有域名屏蔽
            for d in db.iter() { let _ = mgr.remove_domain(d); }
            db.clear();
            // 添加新域名
            let mut errs = Vec::new();
            for d in &blocked_domains {
                match mgr.add_domain(d) {
                    Ok(_) => db.push(d.clone()),
                    Err(e) => errs.push(format!("{d}: {e}")),
                }
            }
            // 替换应用屏蔽集合（用 names 字段）
            let mut app_set = blocked_apps.lock().unwrap();
            app_set.names.clear();
            for n in new_app_names { app_set.names.insert(n); }
            drop(db); drop(app_set);
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::FocusMode { enabled, domains } => {
            let mut mgr = ebpf.lock().unwrap();
            let mut fm = focus_mode_active.lock().unwrap();
            if enabled {
                let mut db = dynamic_blocked.lock().unwrap();
                for d in &domains {
                    if mgr.add_domain(d).is_ok() {
                        db.push(d.clone());
                    }
                }
                *fm = true;
            } else {
                let mut db = dynamic_blocked.lock().unwrap();
                for d in db.iter() { let _ = mgr.remove_domain(d); }
                db.clear();
                *fm = false;
            }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::BlockApp { paths, names } => {
            let mut set = blocked_apps.lock().unwrap();
            for p in paths { set.paths.insert(p); }
            for n in names { set.names.insert(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::UnblockApp { paths, names } => {
            let mut set = blocked_apps.lock().unwrap();
            for p in &paths { set.paths.remove(p); }
            for n in &names { set.names.remove(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::BlockApps { apps } => {
            // acticat 接口别名：apps 字段映射到 names
            let mut set = blocked_apps.lock().unwrap();
            for n in apps { set.names.insert(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::UnblockApps { apps } => {
            // acticat 接口别名：apps 字段映射到 names
            let mut set = blocked_apps.lock().unwrap();
            for n in &apps { set.names.remove(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::FreezeApp { names } => {
            let mut errs = Vec::new();
            for name in &names {
                let (count, already, _) = crate::process_freezer::freeze(freezer, name);
                if already {
                    log::info!("[control-server] freeze_app '{name}': already frozen");
                } else if count == 0 {
                    errs.push(format!("{name}: no matching process found"));
                } else {
                    log::info!("[control-server] freeze_app '{name}': {count} process(es) frozen");
                }
            }
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::ThawApp { names } => {
            let mut errs = Vec::new();
            for name in &names {
                let (count, found) = crate::process_freezer::thaw(freezer, name);
                if !found {
                    errs.push(format!("{name}: not in frozen list"));
                } else {
                    log::info!("[control-server] thaw_app '{name}': {count} process(es) resumed");
                }
            }
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::Status => {
            let db = dynamic_blocked.lock().unwrap().clone();
            let fm = *focus_mode_active.lock().unwrap();
            let apps = blocked_apps.lock().unwrap();
            let mut paths: Vec<String> = apps.paths.iter().cloned().collect();
            let mut names: Vec<String> = apps.names.iter().cloned().collect();
            paths.sort(); names.sort();
            let frozen_apps = freezer.lock().unwrap().frozen_names();
            ControlResp {
                ok: true,
                error: None,
                status: Some(StatusPayload {
                    focus_mode: fm,
                    // blocked_domains 与 dynamic_blocked 内容相同，acticat 接口字段
                    blocked_domains: db.clone(),
                    dynamic_blocked: db,
                    blocked_apps: BlockedAppsPayload { paths, names },
                    frozen_apps,
                    uptime_seconds: start_time.elapsed().as_secs(),
                    platform: "linux/ebpf".to_string(),
                }),
            }
        }
    }
}

// ─── macOS control server ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
use crate::macos::{PfBlocker, app_watcher::BlockedSet};

#[cfg(target_os = "macos")]
pub async fn run_control_server_macos(
    pf: Arc<Mutex<PfBlocker>>,
    blocked_apps: Arc<Mutex<BlockedSet>>,
    freezer: Arc<Mutex<FreezerState>>,
    start_time: std::time::Instant,
) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))?;
    log::info!("[control-server] Listening on {} (macOS/PF)", SOCKET_PATH);

    let dynamic_blocked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let focus_mode_active: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    loop {
        let (stream, _) = listener.accept().await?;
        let pf = Arc::clone(&pf);
        let dynamic_blocked = Arc::clone(&dynamic_blocked);
        let focus_mode_active = Arc::clone(&focus_mode_active);
        let blocked_apps = Arc::clone(&blocked_apps);
        let freezer = Arc::clone(&freezer);

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            let resp = if let Ok(Some(line)) = lines.next_line().await {
                handle_cmd_macos(&line, &pf, &dynamic_blocked, &focus_mode_active,
                                 &blocked_apps, &freezer, start_time)
            } else {
                ControlResp { ok: false, error: Some("empty input".into()), status: None }
            };

            let json = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false}"#.into());
            let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
        });
    }
}

#[cfg(target_os = "macos")]
fn handle_cmd_macos(
    line: &str,
    pf: &Arc<Mutex<PfBlocker>>,
    dynamic_blocked: &Arc<Mutex<Vec<String>>>,
    focus_mode_active: &Arc<Mutex<bool>>,
    blocked_apps: &Arc<Mutex<BlockedSet>>,
    freezer: &Arc<Mutex<FreezerState>>,
    start_time: std::time::Instant,
) -> ControlResp {
    let cmd: ControlCmd = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => return ControlResp { ok: false, error: Some(format!("parse error: {e}")), status: None },
    };

    match cmd {
        ControlCmd::Block { domains } => {
            let mut blocker = pf.lock().unwrap();
            let mut added = Vec::new();
            let mut errs = Vec::new();
            for d in &domains {
                match blocker.add_domain(d) {
                    Ok(()) => added.push(d.clone()),
                    Err(e) => errs.push(format!("{d}: {e}")),
                }
            }
            dynamic_blocked.lock().unwrap().extend(added);
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::Unblock { domains } => {
            let mut blocker = pf.lock().unwrap();
            let mut errs = Vec::new();
            for d in &domains {
                if let Err(e) = blocker.remove_domain(d) {
                    errs.push(format!("{d}: {e}"));
                }
            }
            dynamic_blocked.lock().unwrap().retain(|d| !domains.contains(d));
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::Sync { blocked_domains, blocked_apps: new_app_names } => {
            // 原子替换：先清空所有动态屏蔽，再批量添加新集合
            let mut blocker = pf.lock().unwrap();
            let mut db = dynamic_blocked.lock().unwrap();
            // 清空现有域名屏蔽
            for d in db.iter() { let _ = blocker.remove_domain(d); }
            db.clear();
            // 添加新域名
            let mut errs = Vec::new();
            for d in &blocked_domains {
                match blocker.add_domain(d) {
                    Ok(()) => db.push(d.clone()),
                    Err(e) => errs.push(format!("{d}: {e}")),
                }
            }
            // 替换应用屏蔽集合（用 names 字段）
            let mut app_set = blocked_apps.lock().unwrap();
            app_set.names.clear();
            for n in new_app_names { app_set.names.insert(n); }
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::FocusMode { enabled, domains } => {
            let mut blocker = pf.lock().unwrap();
            let mut fm = focus_mode_active.lock().unwrap();
            if enabled {
                let mut db = dynamic_blocked.lock().unwrap();
                for d in &domains {
                    if blocker.add_domain(d).is_ok() {
                        db.push(d.clone());
                    }
                }
                *fm = true;
            } else {
                let mut db = dynamic_blocked.lock().unwrap();
                for d in db.iter() { let _ = blocker.remove_domain(d); }
                db.clear();
                *fm = false;
            }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::BlockApp { paths, names } => {
            let mut set = blocked_apps.lock().unwrap();
            for p in paths { set.paths.insert(p); }
            for n in names { set.names.insert(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::UnblockApp { paths, names } => {
            let mut set = blocked_apps.lock().unwrap();
            for p in &paths { set.paths.remove(p); }
            for n in &names { set.names.remove(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::BlockApps { apps } => {
            let mut set = blocked_apps.lock().unwrap();
            for n in apps { set.names.insert(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::UnblockApps { apps } => {
            let mut set = blocked_apps.lock().unwrap();
            for n in &apps { set.names.remove(n); }
            ControlResp { ok: true, error: None, status: None }
        }

        ControlCmd::FreezeApp { names } => {
            let mut errs = Vec::new();
            for name in &names {
                let (count, already, _) = crate::process_freezer::freeze(freezer, name);
                if already {
                    log::info!("[control-server] freeze_app '{name}': already frozen");
                } else if count == 0 {
                    errs.push(format!("{name}: no matching process found"));
                } else {
                    log::info!("[control-server] freeze_app '{name}': {count} process(es) frozen");
                }
            }
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::ThawApp { names } => {
            let mut errs = Vec::new();
            for name in &names {
                let (count, found) = crate::process_freezer::thaw(freezer, name);
                if !found {
                    errs.push(format!("{name}: not in frozen list"));
                } else {
                    log::info!("[control-server] thaw_app '{name}': {count} process(es) resumed");
                }
            }
            if errs.is_empty() {
                ControlResp { ok: true, error: None, status: None }
            } else {
                ControlResp { ok: false, error: Some(errs.join("; ")), status: None }
            }
        }

        ControlCmd::Status => {
            let db = dynamic_blocked.lock().unwrap().clone();
            let fm = *focus_mode_active.lock().unwrap();
            let blocker = pf.lock().unwrap();
            let _all_blocked: Vec<String> = {
                let mut v = blocker.blocked_domains();
                v.sort();
                v
            };
            drop(blocker);

            let apps = blocked_apps.lock().unwrap();
            let mut paths: Vec<String> = apps.paths.iter().cloned().collect();
            let mut names: Vec<String> = apps.names.iter().cloned().collect();
            paths.sort(); names.sort();
            let frozen_apps = freezer.lock().unwrap().frozen_names();

            ControlResp {
                ok: true,
                error: None,
                status: Some(StatusPayload {
                    focus_mode: fm,
                    blocked_domains: db.clone(),
                    dynamic_blocked: db,
                    blocked_apps: BlockedAppsPayload { paths, names },
                    frozen_apps,
                    uptime_seconds: start_time.elapsed().as_secs(),
                    platform: "macos/pf".to_string(),
                }),
            }
        }
    }
}

// ─── Tests (shared) ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<ControlCmd, serde_json::Error> {
        serde_json::from_str(s)
    }

    #[test]
    fn test_status() {
        assert!(matches!(parse(r#"{"cmd":"status"}"#).unwrap(), ControlCmd::Status));
    }

    #[test]
    fn test_block() {
        let cmd = parse(r#"{"cmd":"block","domains":["example.com","test.org"]}"#).unwrap();
        if let ControlCmd::Block { domains } = cmd {
            assert_eq!(domains, vec!["example.com", "test.org"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_unblock() {
        let cmd = parse(r#"{"cmd":"unblock","domains":["example.com"]}"#).unwrap();
        if let ControlCmd::Unblock { domains } = cmd {
            assert_eq!(domains, vec!["example.com"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_focus_mode_on() {
        let cmd = parse(r#"{"cmd":"focus_mode","enabled":true,"domains":["tiktok.com"]}"#).unwrap();
        if let ControlCmd::FocusMode { enabled, domains } = cmd {
            assert!(enabled);
            assert_eq!(domains, vec!["tiktok.com"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_focus_mode_off_no_domains() {
        let cmd = parse(r#"{"cmd":"focus_mode","enabled":false}"#).unwrap();
        if let ControlCmd::FocusMode { enabled, domains } = cmd {
            assert!(!enabled);
            assert!(domains.is_empty());
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_block_app_names() {
        let cmd = parse(r#"{"cmd":"block_app","names":["WeChat","steam"]}"#).unwrap();
        if let ControlCmd::BlockApp { paths, names } = cmd {
            assert!(paths.is_empty());
            assert_eq!(names.len(), 2);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_freeze_app_parse() {
        let cmd = parse(r#"{"cmd":"freeze_app","names":["code","WeChat"]}"#).unwrap();
        if let ControlCmd::FreezeApp { names } = cmd {
            assert_eq!(names, vec!["code", "WeChat"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_thaw_app_parse() {
        let cmd = parse(r#"{"cmd":"thaw_app","names":["code"]}"#).unwrap();
        if let ControlCmd::ThawApp { names } = cmd {
            assert_eq!(names, vec!["code"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_invalid_cmd() {
        assert!(parse(r#"{"cmd":"invalid"}"#).is_err());
    }

    #[test]
    fn test_not_json() {
        assert!(parse("not json").is_err());
    }

    #[test]
    fn test_resp_ok_serialization() {
        let r = ControlResp { ok: true, error: None, status: None };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"ok":true}"#);
    }

    #[test]
    fn test_resp_error_serialization() {
        let r = ControlResp { ok: false, error: Some("oops".into()), status: None };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""ok":false"#));
        assert!(s.contains(r#""error":"oops""#));
        assert!(!s.contains("status"));
    }

    // ── 新命令测试（acticat 集成接口）──

    #[test]
    fn test_sync_parse() {
        let cmd = parse(r#"{"cmd":"sync","blocked_domains":["bilibili.com","youtube.com"],"blocked_apps":["steam"]}"#).unwrap();
        if let ControlCmd::Sync { blocked_domains, blocked_apps } = cmd {
            assert_eq!(blocked_domains, vec!["bilibili.com", "youtube.com"]);
            assert_eq!(blocked_apps, vec!["steam"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_sync_empty() {
        let cmd = parse(r#"{"cmd":"sync","blocked_domains":[],"blocked_apps":[]}"#).unwrap();
        if let ControlCmd::Sync { blocked_domains, blocked_apps } = cmd {
            assert!(blocked_domains.is_empty());
            assert!(blocked_apps.is_empty());
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_sync_domains_only() {
        // blocked_apps 有默认值，可以省略
        let cmd = parse(r#"{"cmd":"sync","blocked_domains":["tiktok.com"]}"#).unwrap();
        if let ControlCmd::Sync { blocked_domains, blocked_apps } = cmd {
            assert_eq!(blocked_domains, vec!["tiktok.com"]);
            assert!(blocked_apps.is_empty());
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_block_apps_alias() {
        let cmd = parse(r#"{"cmd":"block_apps","apps":["WeChat","steam"]}"#).unwrap();
        if let ControlCmd::BlockApps { apps } = cmd {
            assert_eq!(apps.len(), 2);
            assert!(apps.contains(&"WeChat".to_string()));
            assert!(apps.contains(&"steam".to_string()));
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_unblock_apps_alias() {
        let cmd = parse(r#"{"cmd":"unblock_apps","apps":["steam"]}"#).unwrap();
        if let ControlCmd::UnblockApps { apps } = cmd {
            assert_eq!(apps, vec!["steam"]);
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_block_apps_empty() {
        let cmd = parse(r#"{"cmd":"block_apps","apps":[]}"#).unwrap();
        if let ControlCmd::BlockApps { apps } = cmd {
            assert!(apps.is_empty());
        } else { panic!("wrong variant"); }
    }

    #[test]
    fn test_status_payload_has_blocked_domains() {
        // StatusPayload 必须包含 blocked_domains 字段（acticat 接口要求）
        let payload = StatusPayload {
            focus_mode: false,
            dynamic_blocked: vec!["bilibili.com".to_string()],
            blocked_domains: vec!["bilibili.com".to_string()],
            blocked_apps: BlockedAppsPayload { paths: vec![], names: vec!["steam".to_string()] },
            frozen_apps: vec![],
            uptime_seconds: 42,
            platform: "linux/ebpf".to_string(),
        };
        let s = serde_json::to_string(&payload).unwrap();
        // 验证 blocked_domains 字段存在于序列化输出中
        assert!(s.contains(r#""blocked_domains""#), "blocked_domains field must be present");
        assert!(s.contains("bilibili.com"), "blocked domain must appear in output");
        // 验证 dynamic_blocked 也存在（向后兼容）
        assert!(s.contains(r#""dynamic_blocked""#), "dynamic_blocked field must be present for backward compat");
        // 验证 blocked_apps 结构
        assert!(s.contains(r#""blocked_apps""#), "blocked_apps field must be present");
        assert!(s.contains("steam"), "blocked app must appear in output");
    }
}
