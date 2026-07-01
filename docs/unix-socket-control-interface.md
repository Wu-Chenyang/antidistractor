# Antidistractor Unix Socket 控制接口

> 适用平台：Linux、macOS  
> Socket 路径：`/var/run/antidistractor.sock`（权限 `0600 root:root`）

---

## 概述

antidistractor 在 daemon 模式下监听 Unix domain socket，接受换行分隔的 JSON 命令。每个连接处理一条命令后关闭。

iOS 和 Android 使用 HTTP API（`localhost:18964`），参见 [features.md](features.md#ios--android--本地-http-api)。

---

## 控制脚本

```bash
# 安装（Linux）
sudo install -m 755 scripts/antidistractor-ctl /usr/local/bin/

# 安装（macOS）
sudo cp scripts/antidistractor-ctl-macos /usr/local/bin/antidistractor-ctl
sudo chmod 755 /usr/local/bin/antidistractor-ctl
```

### sudoers 配置

```
# /etc/sudoers.d/antidistractor-ctl
<username> ALL=(root) NOPASSWD: /usr/local/bin/antidistractor-ctl
```

```bash
echo '<username> ALL=(root) NOPASSWD: /usr/local/bin/antidistractor-ctl' | \
  sudo tee /etc/sudoers.d/antidistractor-ctl
sudo chmod 440 /etc/sudoers.d/antidistractor-ctl
```

---

## 命令参考

### block — 追加域名屏蔽

```json
{"cmd": "block", "domains": ["tiktok.com", "youtube.com"]}
```

将域名追加到动态屏蔽集合。Linux 写入 eBPF BLOCKLIST map，macOS 写入 /etc/hosts。

**域名通配符**：传入以 `.` 开头的后缀键可屏蔽所有子域名（Linux eBPF 支持，macOS 忽略）：

```json
{"cmd": "block", "domains": [".bilibili.com", "bilibili.com"]}
```

上述命令在 Linux 上会屏蔽 `bilibili.com` 及 `api.bilibili.com`、`www.bilibili.com` 等所有子域名。

---

### unblock — 移除域名屏蔽

```json
{"cmd": "unblock", "domains": ["youtube.com"]}
```

---

### sync — 原子替换屏蔽集合

```json
{
  "cmd": "sync",
  "blocked_domains": [".bilibili.com", "bilibili.com", "tiktok.com"],
  "blocked_apps": ["WeChat", "bilibili*"]
}
```

**清空**当前所有动态屏蔽域名和应用，**批量写入**新集合。acticat passive-block-engine 使用此命令实现原子 diff 语义（避免增量 block/unblock 的竞态）。

- `blocked_domains`：域名列表，支持后缀键（`.` 开头，Linux eBPF 后缀匹配）
- `blocked_apps`：应用名列表，`*` 结尾为前缀通配符，其余为精确匹配

---

### focus_mode — 专注模式

```json
{"cmd": "focus_mode", "enabled": true, "domains": ["twitter.com"]}
{"cmd": "focus_mode", "enabled": false}
```

开启时追加指定域名到动态屏蔽；关闭时清除所有动态域名屏蔽（不影响默认 blocklist）。

---

### block_app / block_apps — 屏蔽应用

```json
{"cmd": "block_app", "names": ["WeChat", "bilibili*"], "paths": ["/usr/bin/steam"]}
{"cmd": "block_apps", "apps": ["WeChat", "bilibili*"]}
```

`block_apps` 是 `block_app`（`names` 字段）的别名，供 acticat 使用。

- 精确名称（无 `*`）→ 精确匹配进程名
- `*` 结尾 → 前缀通配符，匹配所有以该前缀开头的进程名

---

### unblock_app / unblock_apps — 解除应用屏蔽

```json
{"cmd": "unblock_app", "names": ["WeChat"], "paths": []}
{"cmd": "unblock_apps", "apps": ["bilibili*"]}
```

---

### freeze_app / thaw_app — 冻结/解冻进程

```json
{"cmd": "freeze_app", "names": ["code", "steam"]}
{"cmd": "thaw_app",   "names": ["code"]}
```

`freeze_app` 向匹配进程发送 SIGSTOP，`thaw_app` 发送 SIGCONT。

---

### status — 查询状态

```json
{"cmd": "status"}
```

响应：

```json
{
  "ok": true,
  "status": {
    "focus_mode": false,
    "blocked_domains": [".bilibili.com", "bilibili.com"],
    "dynamic_blocked": [".bilibili.com", "bilibili.com"],
    "blocked_apps": {
      "paths": ["/usr/bin/steam"],
      "names": ["WeChat", "bilibili*"]
    },
    "frozen_apps": ["code"],
    "uptime_seconds": 3600,
    "platform": "linux/ebpf"
  }
}
```

`blocked_domains` 和 `dynamic_blocked` 内容相同（`dynamic_blocked` 为向后兼容字段）。  
`blocked_apps.names` 包含精确名称和通配符模式（合并返回）。

---

## 通配符速查

### 域名（Linux eBPF 后缀键）

| 存储值 | 匹配的 SNI |
|--------|-----------|
| `bilibili.com` | `bilibili.com` |
| `.bilibili.com` | `api.bilibili.com`、`www.bilibili.com`、`live.bilibili.com` … |

macOS /etc/hosts 不支持通配符，`.` 开头的后缀键会被静默忽略。

### 应用（前缀通配符）

| 模式 | 匹配的进程名 |
|------|------------|
| `WeChat` | `WeChat`（精确） |
| `bilibili*` | `bilibili`、`bilibili-helper`、`bilibili-uploader` … |
| `com.tencent.*` | 仅 Android 包名前缀匹配 |

---

## 认证机制

Socket 权限设为 `0600 root:root`，只有 root 进程可连接。Electron 通过 `sudo antidistractor-ctl` 调用，sudoers 限制只有该固定路径的脚本可无密码执行，无需额外 token 认证。

---

## 完整功能文档

参见 [docs/features.md](features.md)。
