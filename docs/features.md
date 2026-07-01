# Antidistractor 功能文档

> 版本对应：当前 main 分支

---

## 目录

1. [平台支持矩阵](#1-平台支持矩阵)
2. [网站屏蔽](#2-网站屏蔽)
3. [应用屏蔽](#3-应用屏蔽)
4. [通配符匹配](#4-通配符匹配)
5. [进程冻结](#5-进程冻结)
6. [强制锁屏](#6-强制锁屏)
7. [控制接口](#7-控制接口)
8. [默认屏蔽列表](#8-默认屏蔽列表)
9. [限制与注意事项](#9-限制与注意事项)

---

## 1. 平台支持矩阵

| 功能 | Linux | macOS | iOS | Android |
|------|:-----:|:-----:|:---:|:-------:|
| 网站屏蔽 | ✅ eBPF TC（内核级） | ✅ /etc/hosts | ✅ ManagedSettings | ✅ DNS VPN |
| 域名通配符（`*.x.com`） | ✅ eBPF 后缀遍历 | ⚠️ 仅根域名 | ✅ WebDomain 自动覆盖 | ✅ 后缀匹配 |
| 应用屏蔽 | ✅ fanotify（内核拦截） | ✅ 进程轮询 + SIGKILL | ✅ FamilyControls | ✅ UsageStats 覆盖层 |
| 应用通配符（`app*`） | ✅ 前缀匹配 | ✅ 前缀匹配 | ❌ API 限制 | ✅ 前缀匹配 |
| 进程冻结（SIGSTOP） | ✅ | ✅ | ❌ | ❌ |
| 强制锁屏 | ✅ PAM + D-Bus | ✅ pmset + ScreenSaver | ❌ | ❌ |
| TUI 交互界面 | ✅ | ✅ | ❌ | ❌ |
| Unix socket 控制 | ✅ | ✅ | ❌ | ❌ |
| HTTP 控制 API | ❌ | ❌ | ✅ :18964 | ✅ :18964 |

---

## 2. 网站屏蔽

### Linux — eBPF TC Classifier

**原理**：eBPF 程序挂载在 TC（Traffic Control）egress 路径，对每个出站 TCP 包解析 TLS ClientHello 报文，提取 SNI 字段，命中 BLOCKLIST 则返回 `TC_ACT_SHOT` 丢弃。

- 拦截层级：内核网络栈，无法被用户态进程绕过
- 支持接口：自动检测默认路由接口 + 所有 TUN 接口（mihomo/clash 代理场景）
- 新 TUN 接口热插拔：每 10 秒扫描一次，自动 attach
- 仅拦截 TCP 443 端口的 HTTPS 流量（通过 SNI 识别域名）
- 不拦截 HTTP（80 端口）或使用硬编码 IP 的流量

**代理场景**：流量经过本地代理（如 mihomo）时，eBPF 看到的是代理连接而非原始 SNI，需在代理配置中额外添加 REJECT 规则：

```javascript
// mihomo override 示例
const rejectRules = blockedDomains.map(d => `DOMAIN-SUFFIX,${d},REJECT`)
config.rules = [...rejectRules, ...config.rules]
```

### macOS — /etc/hosts

**原理**：将屏蔽域名写入 `/etc/hosts`，映射到 `127.0.0.1` 和 `::1`，阻止 DNS 解析。写入后自动刷新 DNS 缓存（`dscacheutil -flushcache` + `killall -HUP mDNSResponder`）。

- 文件写入采用原子操作（临时文件 + rename），避免写入中断导致 hosts 损坏
- 屏蔽块以 `# BEGIN antidistractor` / `# END antidistractor` 标记，不影响其他条目
- 不使用 PF 防火墙 IP 规则（CDN 共享 IP 会造成误伤）

**通配符限制**：`/etc/hosts` 不支持通配符，`*.bilibili.com` 格式的后缀键（以 `.` 开头）会被静默忽略，只有根域名 `bilibili.com` 会被写入。

### iOS — ManagedSettings + FamilyControls

**原理**：通过 Apple `ManagedSettings` 框架的 `WebContentSettings.FilterPolicy` 设置域名黑名单，由系统在 Safari 和所有使用 `WKWebView` 的 App 中强制执行。

- 需要 `com.apple.developer.family-controls` entitlement（需向 Apple 申请）
- `WebDomain(domain: "bilibili.com")` 自动覆盖所有子域名（`api.bilibili.com`、`www.bilibili.com` 等），无需额外配置
- 屏蔽在所有 App 的 WebView 中生效，不仅限于 Safari
- 仅在真实设备上有效（模拟器不支持）

### Android — DNS VPN

**原理**：建立本地 TUN 虚拟网卡，将系统 DNS 服务器指向虚拟地址 `10.0.0.2`，拦截所有 UDP 53 端口的 DNS 查询。对被屏蔽域名返回 `127.0.0.1`，其余查询转发到上游 DNS（`8.8.8.8`）。

- 无需 root 权限，用户只需确认一次 VPN 弹窗
- 屏蔽所有 App 的网络请求（浏览器、B 站、抖音等）
- DNS 查询转发时绑定底层物理网络（WiFi/移动数据），避免路由循环
- 自动禁用系统 Private DNS（DoT），防止绕过拦截
- 通过广播（`ACTION_BLOCKLIST_UPDATED`）实时接收屏蔽列表更新，无需重启 VPN

**局限**：
- 与其他 VPN/代理冲突（Android 同时只能运行一个 VPN）
- 可被绕过：App 使用硬编码 IP 或 DoH（DNS over HTTPS）

---

## 3. 应用屏蔽

### Linux — fanotify FAN_OPEN_EXEC_PERM

**原理**：使用 `fanotify(7)` 的 `FAN_OPEN_EXEC_PERM` 事件，在整个文件系统（`FAN_MARK_FILESYSTEM`）上监听 exec 系统调用。命中屏蔽列表时回复 `FAN_DENY`，进程收到 `EACCES` 无法启动。

- 内核级拦截，进程根本无法启动（不是启动后再杀死）
- 自身进程（antidistractor 本身）的 exec 事件一律 ALLOW，防止死锁
- 命中时发送桌面通知（`notify-send`，非阻塞）
- 需要 root 权限（fanotify 需要 `CAP_SYS_ADMIN`）

**匹配方式**：
- 精确路径匹配：`/usr/bin/steam`
- 进程名匹配（basename）：`steam`、`WeChat`
- 前缀通配符匹配：`bilibili*`（匹配所有以 `bilibili` 开头的进程名）

### macOS — 进程轮询 + SIGKILL

**原理**：后台线程每 500ms 枚举一次系统进程列表（`sysctl KERN_PROC_ALL`），发现屏蔽 App 时立即发送 `SIGKILL`，并弹出桌面通知（`osascript`）。

- 有 0~500ms 窗口期，被屏蔽 App 会短暂启动后被杀死
- macOS 缺少等效于 Linux `fanotify FAN_OPEN_EXEC_PERM` 的内核拦截 API（Endpoint Security 框架需要 Apple entitlement 和公证）

**匹配方式**：
- 精确路径匹配：`/Applications/WeChat.app/Contents/MacOS/WeChat`
- 进程名匹配（basename 和 comm）：`WeChat`、`Bilibili`
- 前缀通配符匹配：`bilibili*`

### iOS — FamilyControls ApplicationToken

**原理**：通过 `ManagedSettings` 的 `application.blockedApplications` 设置 `ApplicationToken` 集合，由系统在 App 启动时强制拦截。

- `ApplicationToken` 是不透明值，**必须通过 `FamilyActivityPicker` UI 让用户选择**，无法从 bundle ID 直接构造
- 选择后 token 缓存在 `AppTokenCache`，后续可通过 HTTP API 的 `bundle_ids` 字段触发
- 支持按 App Store 分类屏蔽（`categoryIDs`，同样需通过 picker 选择）
- `app_pattern` 通配符在 iOS 上**不支持**（API 限制）

### Android — UsageStats + 覆盖层

**原理**：后台线程每 500ms 查询 `UsageStatsManager` 获取当前前台 App，发现屏蔽 App 时启动全屏 `ShieldActivity` 覆盖。

- 需要 `PACKAGE_USAGE_STATS` 权限（需引导用户在设置中手动开启）
- 约 500ms 内用户可短暂看到被屏蔽 App 的内容
- 通过广播（`ACTION_BLOCKLIST_UPDATED`）实时接收屏蔽列表更新

**匹配方式**：
- 精确包名匹配：`tv.danmaku.bili`
- 前缀通配符匹配：`tv.danmaku.*`（匹配所有以 `tv.danmaku.` 开头的包名）

---

## 4. 通配符匹配

### 域名通配符（`domain_pattern`）

格式：`*.bilibili.com`（仅支持最左侧单层 `*`）

语义：匹配 `bilibili.com` 本身及所有子域名（`api.bilibili.com`、`www.bilibili.com`、`live.bilibili.com` 等）。

| 平台 | 实现机制 | 传入格式 |
|------|---------|---------|
| Linux | eBPF 后缀遍历：提取 SNI 后逐 label 边界查 BLOCKLIST，后缀键以 `.` 开头 | 同时存 `.bilibili.com`（后缀键）和 `bilibili.com`（根域名） |
| macOS | /etc/hosts 精确匹配，后缀键（`.` 开头）被静默忽略 | 仅存 `bilibili.com`（根域名） |
| iOS | `WebDomain("bilibili.com")` 自动覆盖所有子域名 | 仅传 `bilibili.com`（根域名） |
| Android | `DnsVpnService.isBlocked` 做 `endsWith(".$blocked")` 后缀匹配 | 仅传 `bilibili.com`（根域名） |

**acticat 展开逻辑**（`passive-block-engine.ts` for Electron，`capacitor.ts` for 移动端）：

```
domain_pattern "*.bilibili.com"
  → Electron (Linux/macOS): 发送 [".bilibili.com", "bilibili.com"]
  → Mobile (iOS/Android):   发送 ["bilibili.com"]
```

### 应用通配符（`app_pattern`）

格式：`bilibili*` 或 `tv.danmaku.*`（仅支持 `*` 结尾的前缀匹配）

| 平台 | 支持 | 匹配对象 | 示例 |
|------|:----:|---------|------|
| Linux | ✅ | 进程名（basename） | `bilibili*` 匹配 `bilibili`、`bilibili-helper` |
| macOS | ✅ | 进程名（basename 和 comm） | `bilibili*` 匹配 `bilibili`、`bilibili-helper` |
| iOS | ❌ | — | FamilyControls API 限制，无法从通配符构造 ApplicationToken |
| Android | ✅ | 包名（packageName） | `tv.danmaku.*` 匹配 `tv.danmaku.bili`、`tv.danmaku.bilibilihd` |

**存储约定**：通配符模式（`*` 结尾）存入 `patterns` 集合，精确名称存入 `names` 集合，由各平台的 `isBlocked` 函数分别处理。

---

## 5. 进程冻结

仅 Linux 和 macOS 支持。

**原理**：向目标进程发送 `SIGSTOP` 信号使其挂起，发送 `SIGCONT` 恢复。与应用屏蔽（SIGKILL / fanotify）不同，冻结是可逆的，进程状态完整保留。

**使用场景**：临时暂停某个进程（如 IDE、游戏），而不是彻底阻止其运行。

**控制命令**（Linux/macOS Unix socket）：
```json
{"cmd": "freeze_app", "names": ["code", "steam"]}
{"cmd": "thaw_app",   "names": ["code"]}
```

---

## 6. 强制锁屏

仅 Linux 和 macOS 支持，默认时间段 01:00–07:00。

### Linux

两层机制：

1. **PAM 拦截**：在 `/etc/pam.d/gdm-password` 和 `/etc/pam.d/gdm-fingerprint` 中插入 `pam_exec.so` 规则，调用 `/usr/local/bin/enforce-lock.sh`。锁定时间段内的解锁尝试直接被 PAM 拒绝，用户无法输入密码解锁。

2. **锁屏守护进程**（`enforce-lock-daemon.sh` / `enforce-lock.service`）：每 60 秒检查一次，若在锁定时间段内屏幕被解锁，立即重新锁定。

### macOS

**锁屏守护进程**（`--screen-lock-daemon` 模式）：
- 01:00 时执行 `pmset displaysleepnow` + 启动 `ScreenSaverEngine` 强制锁屏
- 每 60 秒检查，若在 01:00–07:00 内屏幕被解锁，立即重新锁定

---

## 7. 控制接口

### Linux / macOS — Unix Domain Socket

**Socket 路径**：`/var/run/antidistractor.sock`（权限 `0600 root:root`）

**协议**：每个连接发送一行 JSON，读取一行 JSON 响应后关闭连接。

**控制脚本**：`/usr/local/bin/antidistractor-ctl`（需 sudoers NOPASSWD 配置）

```bash
antidistractor-ctl '{"cmd":"status"}'
antidistractor-ctl '{"cmd":"block","domains":["tiktok.com"]}'
```

#### 命令列表

| 命令 | 字段 | 说明 |
|------|------|------|
| `block` | `domains: string[]` | 添加域名到动态屏蔽列表 |
| `unblock` | `domains: string[]` | 从动态屏蔽列表移除域名 |
| `sync` | `blocked_domains: string[]`<br>`blocked_apps: string[]` | **原子替换**：清空当前动态屏蔽，批量写入新集合（acticat passive-block-engine 专用） |
| `focus_mode` | `enabled: bool`<br>`domains?: string[]` | 开启/关闭专注模式（批量屏蔽/解除） |
| `block_app` | `paths?: string[]`<br>`names?: string[]` | 屏蔽应用（支持路径或进程名，`*` 结尾为前缀通配符） |
| `unblock_app` | `paths?: string[]`<br>`names?: string[]` | 解除应用屏蔽 |
| `block_apps` | `apps: string[]` | `block_app` 的别名（acticat 接口） |
| `unblock_apps` | `apps: string[]` | `unblock_app` 的别名（acticat 接口） |
| `freeze_app` | `names: string[]` | 冻结进程（SIGSTOP） |
| `thaw_app` | `names: string[]` | 解冻进程（SIGCONT） |
| `status` | — | 查询当前状态 |

#### 响应格式

```jsonc
// 成功
{"ok": true}

// 失败
{"ok": false, "error": "..."}

// status 响应
{
  "ok": true,
  "status": {
    "focus_mode": false,
    "blocked_domains": ["bilibili.com", ".bilibili.com"],
    "dynamic_blocked": ["bilibili.com", ".bilibili.com"],  // 同上，向后兼容字段
    "blocked_apps": {
      "paths": [],
      "names": ["WeChat", "bilibili*"]  // names + patterns 合并返回
    },
    "frozen_apps": [],
    "uptime_seconds": 3600,
    "platform": "linux/ebpf"  // 或 "macos/pf"
  }
}
```

#### 域名通配符在 sync 命令中的用法

```bash
# 屏蔽 bilibili.com 及所有子域名（Linux eBPF 后缀匹配）
antidistractor-ctl '{"cmd":"sync","blocked_domains":[".bilibili.com","bilibili.com"],"blocked_apps":[]}'

# 屏蔽所有以 "bilibili" 开头的进程
antidistractor-ctl '{"cmd":"sync","blocked_domains":[],"blocked_apps":["bilibili*"]}'
```

#### sudoers 配置

```
# /etc/sudoers.d/antidistractor-ctl
<username> ALL=(root) NOPASSWD: /usr/local/bin/antidistractor-ctl
```

---

### iOS / Android — 本地 HTTP API

**地址**：`http://127.0.0.1:18964`（仅监听 localhost）

**认证**：请求头 `X-Antidistractor-Secret: <secret>`（启动时配置，为空则跳过认证）

#### 端点列表

| 方法 | 路径 | 请求体 | 说明 |
|------|------|--------|------|
| `POST` | `/block` | `{"domains":[...], "bundle_ids":[...], "category_ids":[...]}` | 追加屏蔽（iOS）|
| `POST` | `/block` | `{"domains":[...], "package_names":[...], "categories":[...]}` | 追加屏蔽（Android）|
| `POST` | `/unblock` | `{"domains":[...], "bundle_ids":[...]}` / `{"domains":[...], "package_names":[...]}` | 移除屏蔽 |
| `POST` | `/sync` | 同 `/block` 格式 | **原子替换**：清空后批量写入（acticat 专用） |
| `POST` | `/clear` | `{}` | 清除所有屏蔽 |
| `POST` | `/authorize` | `{}` | 触发 FamilyControls 授权弹窗（iOS 专用） |
| `GET` | `/status` | — | 查询当前状态 |

#### iOS 请求体字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `domains` | `string[]` | 域名列表（传根域名即可，自动覆盖子域名） |
| `bundle_ids` | `string[]` | App bundle ID（需已通过 picker 选择并缓存 token） |
| `category_ids` | `int[]` | App Store 分类 ID（需已通过 picker 选择） |

#### Android 请求体字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `domains` | `string[]` | 域名列表（传根域名即可，DNS VPN 自动覆盖子域名） |
| `package_names` | `string[]` | 包名列表，支持 `*` 结尾的前缀通配符（如 `tv.danmaku.*`） |
| `categories` | `string[]` | 分类标签（`gaming`、`social` 等，预留字段） |

#### /status 响应

```jsonc
// iOS
{
  "ok": true,
  "authorized": true,
  "blocking": true,
  "blocklist": {
    "domains": ["bilibili.com"],
    "bundle_ids": ["com.bilibili.app.iphone"],
    "category_ids": []
  }
}

// Android
{
  "ok": true,
  "vpn_enabled": true,
  "app_block_enabled": true,
  "blocklist": {
    "domains": ["bilibili.com"],
    "package_names": ["tv.danmaku.*"],
    "categories": []
  }
}
```

---

## 8. 默认屏蔽列表

Linux 和 macOS daemon 启动时自动加载以下域名（硬编码在 `main.rs`）：

```
bilibili.com        www.bilibili.com    m.bilibili.com
api.bilibili.com    api.vc.bilibili.com app.bilibili.com
live.bilibili.com   t.bilibili.com      space.bilibili.com
search.bilibili.com member.bilibili.com passport.bilibili.com
account.bilibili.com manga.bilibili.com
hdslb.com           www.hdslb.com
i0.hdslb.com        i1.hdslb.com        i2.hdslb.com
s1.hdslb.com
bilivideo.com       bilivideo.cn
biliapi.net         biliapi.com
```

默认列表不受 `sync` / `unblock` 命令影响（这些命令只操作动态屏蔽集合）。

---

## 9. 限制与注意事项

### 全平台

- **代理绕过**：流量经过本地代理（SOCKS5/HTTP）时，eBPF 和 DNS VPN 均无法检查真实目标域名，需在代理配置中额外添加屏蔽规则。
- **QUIC/HTTP3**：eBPF 仅拦截 TCP 443，基于 UDP 的 QUIC 不受影响（浏览器通常会回退到 TCP）。
- **DoH（DNS over HTTPS）**：Android DNS VPN 无法拦截应用内置的 DoH 客户端。

### Linux

- 需要 Linux 5.15+ 内核（BPF TC classifier 支持）
- 需要 root 权限（eBPF 加载 + fanotify）
- eBPF 程序需要 nightly Rust 工具链编译（`bpfel-unknown-none` target）

### macOS

- 应用屏蔽有 0~500ms 窗口期（进程轮询间隔）
- 缺少等效于 Linux fanotify 的内核拦截 API（Endpoint Security 需要 Apple 审批）
- 域名通配符（`*.x.com`）在 macOS 上只能屏蔽根域名，子域名不受 /etc/hosts 影响

### iOS

- 需要 `com.apple.developer.family-controls` entitlement（向 Apple 申请）
- App 屏蔽必须通过 `FamilyActivityPicker` UI 选择，无法从 bundle ID 或通配符直接构造
- 仅在真实设备上有效（模拟器不支持 FamilyControls / ManagedSettings）
- HTTP 服务器仅监听 localhost（127.0.0.1），不对外暴露

### Android

- 应用屏蔽需要 `PACKAGE_USAGE_STATS` 权限（需用户在设置中手动开启）
- 与其他 VPN/代理冲突（Android 同时只能运行一个 VPN）
- 应用屏蔽有约 500ms 窗口期（UsageStats 轮询间隔）
