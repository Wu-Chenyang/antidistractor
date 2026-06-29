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
    /// 开启/关闭专注模式
    FocusMode {
        enabled: bool,
        #[serde(default)]
        domains: Vec<String>,
    },
    /// 阻止特定应用启动
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
    pub dynamic_blocked: Vec<String>,
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
            // all_blocked includes both default and dynamic domains
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
}
