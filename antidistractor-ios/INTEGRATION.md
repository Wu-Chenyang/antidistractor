# Antidistractor iOS — 集成指南

## 架构概览

```
Host App (多端应用)
    │
    │  HTTP POST localhost:18964/block
    │  { "domains": ["bilibili.com"], "bundle_ids": [...] }
    ▼
AntidistractorServer (本地 HTTP 服务)
    │
    ▼
AntidistractorCore (FamilyControls + ManagedSettings)
    ├── BlockingManager   → ManagedSettingsStore (实际屏蔽)
    ├── AppPickerManager  → FamilyActivityPicker (选择 App)
    └── ScheduleManager   → DeviceActivityCenter (定时屏蔽)
    
DeviceActivityMonitor Extension (独立进程，后台运行)
    └── 定时触发 → 读取 App Group 数据 → 应用屏蔽

ShieldConfiguration Extension
    └── 自定义屏蔽页面样式
```

## Xcode 项目配置

### 1. 添加 Swift Package

在 Xcode 中 File → Add Package Dependencies，添加本地路径：
```
/path/to/antidistractor/antidistractor-ios
```

或在 Package.swift 中添加：
```swift
.package(path: "../antidistractor/antidistractor-ios")
```

### 2. 添加 Targets

在 Xcode 项目中需要添加两个 Extension Target：

**DeviceActivityMonitor Extension:**
- File → New Target → Device Activity Monitor Extension
- 将 `DeviceActivityMonitorExtension.swift` 的内容替换到生成的文件中

**Shield Configuration Extension:**
- File → New Target → Shield Configuration Extension  
- 将 `ShieldConfigurationExtension.swift` 的内容替换到生成的文件中

### 3. App Group 配置

三个 Target（主 App + 两个 Extension）都需要：
- Signing & Capabilities → + Capability → App Groups
- 添加同一个 Group ID：`group.com.antidistractor.shared`
- 修改 `BlocklistStore.swift` 中的 `appGroupID` 为你的实际 Group ID

### 4. FamilyControls Entitlement

主 App target 的 `.entitlements` 文件中添加：
```xml
<key>com.apple.developer.family-controls</key>
<true/>
```

⚠️ 此 entitlement 需要向 Apple 申请：
https://developer.apple.com/contact/request/family-controls-distribution

### 5. Info.plist

主 App 的 Info.plist 添加：
```xml
<key>NSFamilyControlsUsageDescription</key>
<string>Antidistractor 需要屏幕使用时间权限来屏蔽干扰性应用和网站。</string>
```

## 在 Host App 中使用

### 初始化（AppDelegate 或 @main App）

```swift
import AntidistractorCore
import AntidistractorServer

@main
struct MyApp: App {
    @StateObject private var blockingManager = BlockingManager.shared
    private let server = ControlServer()
    
    init() {
        // 生成或从 Keychain 读取共享密钥
        let secret = loadOrGenerateSecret()
        
        // 初始化 antidistractor
        AntidistractorIOS.setup(sharedSecret: secret)
        
        // 启动 HTTP 控制服务器
        try? server.start()
        server.sharedSecret = secret
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(blockingManager)
        }
    }
}
```

### 请求授权（必须由用户手势触发）

```swift
Button("开启屏幕时间权限") {
    Task {
        await BlockingManager.shared.requestAuthorization()
    }
}
```

### App 选择器（FamilyActivityPicker）

```swift
import FamilyControls
import AntidistractorCore

struct AppPickerView: View {
    @StateObject private var picker = AppPickerManager.shared
    
    var body: some View {
        Button("选择要屏蔽的 App") {
            picker.isPickerPresented = true
        }
        .familyActivityPicker(
            isPresented: $picker.isPickerPresented,
            selection: $picker.selection
        )
        .onChange(of: picker.selection) { newSelection in
            picker.applySelection(newSelection)
        }
    }
}
```

### 通过 HTTP API 控制（从 Mac 端调用）

Mac 端 antidistractor daemon 或多端 app 通过 HTTP 调用：

```bash
# 屏蔽域名
curl -X POST http://[iPhone-IP]:18964/block \
  -H "Content-Type: application/json" \
  -H "X-Antidistractor-Secret: YOUR_SECRET" \
  -d '{"domains": ["bilibili.com", "tiktok.com"]}'

# 屏蔽 App（需要先通过 FamilyActivityPicker 选择）
curl -X POST http://[iPhone-IP]:18964/block \
  -H "X-Antidistractor-Secret: YOUR_SECRET" \
  -d '{"bundle_ids": ["com.bilibili.app.iphone"]}'

# 查询状态
curl http://[iPhone-IP]:18964/status \
  -H "X-Antidistractor-Secret: YOUR_SECRET"

# 清除所有屏蔽
curl -X POST http://[iPhone-IP]:18964/clear \
  -H "X-Antidistractor-Secret: YOUR_SECRET"
```

### 定时屏蔽（对应 Mac 端的 enforce-lock）

```swift
// 启动夜间强制锁定 01:00-07:00
try ScheduleManager.shared.startNightlyLock(startHour: 1, endHour: 7)

// 启动专注会话（60分钟）
try ScheduleManager.shared.startFocusSession(minutes: 60)
```

## HTTP API 参考

| 方法 | 路径 | 请求体 | 说明 |
|------|------|--------|------|
| POST | /block | `{"domains":[...], "bundle_ids":[...], "category_ids":[...]}` | 添加屏蔽 |
| POST | /unblock | `{"domains":[...], "bundle_ids":[...]}` | 移除屏蔽 |
| POST | /clear | `{}` | 清除所有屏蔽 |
| POST | /authorize | `{}` | 触发授权弹窗（需用户在设备上操作）|
| GET | /status | — | 查询当前状态 |

所有请求需要 Header：`X-Antidistractor-Secret: <secret>`（若配置了密钥）

## 重要限制

1. **App 屏蔽需要 FamilyActivityPicker**：ApplicationToken 是不透明值，无法从 bundle ID 直接构造。用户必须通过系统提供的 picker UI 选择 App，选择后 token 被缓存，后续可通过 HTTP API 的 `bundle_ids` 字段触发（实际使用缓存的 token）。

2. **HTTP 服务器仅监听 localhost**：出于安全考虑，服务器绑定在 `127.0.0.1`。如果需要从 Mac 端远程调用，需要在同一局域网内通过 SSH 隧道或修改绑定地址（注意安全风险）。

3. **模拟器不支持**：FamilyControls 和 ManagedSettings 只在真实设备上工作。

4. **需要 Apple 审批的 entitlement**：`com.apple.developer.family-controls` 需要向 Apple 申请，不是普通开发者账号默认拥有的。

## 文件结构

```
antidistractor-ios/
├── Package.swift
├── INTEGRATION.md
├── Sources/
│   ├── AntidistractorCore/
│   │   ├── AntidistractorIOS.swift      # 入口，setup()
│   │   ├── BlockingManager.swift        # FamilyControls + ManagedSettings
│   │   ├── BlocklistStore.swift         # App Group 持久化
│   │   ├── AppPickerManager.swift       # FamilyActivityPicker 管理
│   │   └── ScheduleManager.swift        # 定时屏蔽
│   └── AntidistractorServer/
│       └── ControlServer.swift          # 本地 HTTP 控制服务器
├── DeviceActivityMonitorExtension/
│   └── DeviceActivityMonitorExtension.swift  # 后台定时触发
├── ShieldConfigurationExtension/
│   └── ShieldConfigurationExtension.swift    # 屏蔽页面样式
└── Tests/
    └── AntidistractorCoreTests/
        └── BlocklistStoreTests.swift
```
