//! Control server — Unix domain socket server for runtime control.
//!
//! 监听 /var/run/antidistractor.sock，接受换行分隔的 JSON 命令。
//! 每个连接处理一条命令后关闭（无需保持长连接）。

use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};
use crate::ebpf::EbpfManager;
use std::os::unix::fs::PermissionsExt;

const SOCKET_PATH: &str = "/var/run/antidistractor.sock";

/// 入站命令
#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlCmd {
    /// 添加域名到 blocklist（立即生效，写入 eBPF Map）
    Block { domains: Vec<String> },
    /// 从 blocklist 移除域名
    Unblock { domains: Vec<String> },
    /// 开启/关闭专注模式（批量屏蔽/解除预设干扰域名列表）
    FocusMode {
        enabled: bool,
        /// 追加到默认屏蔽列表的自定义域名（仅 enabled=true 时生效）
        #[serde(default)]
        domains: Vec<String>,
    },
    /// 查询当前状态
    Status,
}

/// 响应体
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
    pub dynamic_blocked: Vec<String>,  // Guardian 动态屏蔽的域名（不含默认列表）
    pub uptime_seconds: u64,
}

/// 启动 control server（在 daemon 模式下 tokio::spawn 调用）。
/// ebpf 必须是 Arc<Mutex<EbpfManager>>，以便跨线程安全访问。
pub async fn run_control_server(
    ebpf: Arc<Mutex<EbpfManager>>,
    start_time: std::time::Instant,
) -> anyhow::Result<()> {
    // 清理残留 socket 文件
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)?;
    // 设置权限：仅 root 可写（由 sudo helper 脚本以 root 身份连接）
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))?;

    log::info!("[control-server] Listening on {}", SOCKET_PATH);

    // 记录 Guardian 动态屏蔽的域名（与默认列表分开管理，便于 FocusMode 解除时精确撤销）
    let dynamic_blocked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let focus_mode_active: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    loop {
        let (stream, _) = listener.accept().await?;
        let ebpf = Arc::clone(&ebpf);
        let dynamic_blocked = Arc::clone(&dynamic_blocked);
        let focus_mode_active = Arc::clone(&focus_mode_active);

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            let resp = if let Ok(Some(line)) = lines.next_line().await {
                handle_cmd(&line, &ebpf, &dynamic_blocked, &focus_mode_active, start_time)
            } else {
                ControlResp { ok: false, error: Some("empty input".into()), status: None }
            };

            let json = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false}"#.into());
            let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
        });
    }
}

fn handle_cmd(
    line: &str,
    ebpf: &Arc<Mutex<EbpfManager>>,
    dynamic_blocked: &Arc<Mutex<Vec<String>>>,
    focus_mode_active: &Arc<Mutex<bool>>,
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
                // 屏蔽追加域名（默认列表已由 EbpfManager 初始化时加载，此处只加用户自定义的）
                let mut db = dynamic_blocked.lock().unwrap();
                for d in &domains {
                    if mgr.add_domain(d).is_ok() {
                        db.push(d.clone());
                    }
                }
                *fm = true;
                ControlResp { ok: true, error: None, status: None }
            } else {
                // 只解除 Guardian 动态添加的域名，不动默认 blocklist
                let mut db = dynamic_blocked.lock().unwrap();
                for d in db.iter() {
                    let _ = mgr.remove_domain(d);
                }
                db.clear();
                *fm = false;
                ControlResp { ok: true, error: None, status: None }
            }
        }

        ControlCmd::Status => {
            let db = dynamic_blocked.lock().unwrap().clone();
            let fm = *focus_mode_active.lock().unwrap();
            ControlResp {
                ok: true,
                error: None,
                status: Some(StatusPayload {
                    focus_mode: fm,
                    dynamic_blocked: db,
                    uptime_seconds: start_time.elapsed().as_secs(),
                }),
            }
        }
    }
}
