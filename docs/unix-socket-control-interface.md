# Antidistractor Unix Socket 控制接口 — 实现规范

> 版本：0.1.0 · 状态：待实现（由熟悉 Rust/tokio 的开发者实现）

## 背景

antidistractor 目前只有 TUI 模式，blocklist 无法被外部程序动态修改。Guardian 系统需要通过 Unix domain socket 实时控制 antidistractor，实现专注模式的开关和域名屏蔽。

## 目标

在 daemon 模式下启动一个 Unix domain socket server，接受 JSON 命令，调用已有的 `EbpfManager` API。

---

## 实现位置

所有改动在 `antidistractor/antidistractor/src/` 目录下。

### 新增文件：`control_server.rs`

```rust
//! Control server — Unix domain socket server for runtime control.
//!
//! 监听 /var/run/antidistractor.sock，接受换行分隔的 JSON 命令。
//! 每个连接处理一条命令后关闭（无需保持长连接）。

use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};
use crate::ebpf::EbpfManager;

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
    std::fs::set_permissions(SOCKET_PATH, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    log::info!("[control-server] Listening on {}", SOCKET_PATH);

    // 记录 Guardian 动态屏蔽的域名（与默认列表分开管理，便于 FocusMode 解除时精确撤销）
    let dynamic_blocked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let focus_mode_active: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    loop {
        let (stream, _) = listener.accept().await?;
        let ebpf = Arc::clone(&ebpf);
        let dynamic_blocked = Arc::clone(&dynamic_blocked);
        let focus_mode_active = Arc::clone(&focus_mode_active);
        let start_time = start_time;

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
```

### 修改 `main.rs`

在 `main()` 的 daemon 分支中：

```rust
// 1. 将 ebpf 包装为 Arc<Mutex<>>（原来是裸 EbpfManager）
let ebpf = Arc::new(Mutex::new(ebpf));
let start_time = std::time::Instant::now();

// 2. tokio::spawn control server（与主 daemon loop 并行）
let ebpf_ctl = Arc::clone(&ebpf);
tokio::spawn(async move {
    if let Err(e) = run_control_server(ebpf_ctl, start_time).await {
        log::error!("[control-server] Error: {e}");
    }
});

// 3. 原 daemon loop 继续（信号处理等）
```

需要在 `Cargo.toml` 的 `[dependencies]` 新增：
```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

（aya/tokio 已经是现有依赖，无需重复添加）

---

## 控制脚本：`/usr/local/bin/antidistractor-ctl`

Guardian 系统通过此脚本与 socket 通信（Electron sudo helper）：

```bash
#!/bin/bash
# antidistractor-ctl — Guardian control helper
# 以 root 身份运行（sudoers NOPASSWD 配置），连接 Unix socket 发送单条 JSON 命令。
#
# 用法：antidistractor-ctl '{"cmd":"focus_mode","enabled":true}'
#       antidistractor-ctl '{"cmd":"status"}'

set -euo pipefail

SOCKET=/var/run/antidistractor.sock

if [ ! -S "$SOCKET" ]; then
  echo '{"ok":false,"error":"socket not found — is antidistractor running?"}' >&1
  exit 1
fi

if [ $# -ne 1 ]; then
  echo '{"ok":false,"error":"usage: antidistractor-ctl <json>"}' >&1
  exit 1
fi

# socat 发送命令并读回响应（超时 3 秒）
echo "$1" | socat -t3 - UNIX-CONNECT:"$SOCKET"
```

安装：
```bash
sudo install -m 755 scripts/antidistractor-ctl /usr/local/bin/
```

---

## sudoers 配置

```
# /etc/sudoers.d/antidistractor-ctl
# 允许 wucy 用户以 root 身份无密码执行 antidistractor-ctl
wucy ALL=(root) NOPASSWD: /usr/local/bin/antidistractor-ctl
```

安装：
```bash
echo 'wucy ALL=(root) NOPASSWD: /usr/local/bin/antidistractor-ctl' | \
  sudo tee /etc/sudoers.d/antidistractor-ctl
sudo chmod 440 /etc/sudoers.d/antidistractor-ctl
```

---

## 认证机制

**为什么不需要额外认证**：

antidistractor socket 的权限设置为 `0o600 root:root`，只有 root 进程才能连接。Electron 通过 `sudo antidistractor-ctl` 调用，sudoers 限制只有这一个特定脚本可以无密码执行。

攻击面分析：
- 非 root 用户无法直接连接 socket（权限拒绝）
- sudoers 只允许执行固定路径的脚本，不允许任意命令
- 脚本本身只做 socket 转发，不执行 shell 命令
- antidistractor-ctl 二进制由 root 安装，普通用户无法替换

**不需要**基于 token 的认证——OS 权限已经足够。如果未来需要多用户场景（多个用户各自控制不同的 blocking profile），再考虑加 token。

---

## 编译

```bash
cd /home/wucy/Workspace/antidistractor

# 重新编译 eBPF 程序（通常不需要，除非修改了 eBPF 代码）
make build-ebpf

# 编译用户态程序（包含 control server）
make build-user

# 或直接
cargo build --release -p antidistractor
```

编译后重启服务：
```bash
sudo systemctl restart antidistractor.service
```

验证 socket 已创建：
```bash
ls -la /var/run/antidistractor.sock
# 应该显示 srw------- root root

# 测试 status 命令
sudo /usr/local/bin/antidistractor-ctl '{"cmd":"status"}'
# 期望输出：{"ok":true,"status":{"focus_mode":false,"dynamic_blocked":[],"uptime_seconds":N}}
```

---

## 与 antidistractor-guard.sh 的关系

guard 脚本（10s 轮询自动修复）监控的是：
1. /etc/hosts 中的 bilibili block 是否被篡改
2. mihomo override 配置是否被修改
3. antidistractor.service 是否在运行

Guardian 动态屏蔽的域名（通过 socket 写入 eBPF Map）**不受 guard 脚本影响**——guard 只保护默认 blocklist，不管理动态域名。这是正确的：Guardian 需要动态开关专注模式，guard 不应该干扰这个过程。
