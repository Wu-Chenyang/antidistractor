# Antidistractor

A cross-platform distraction blocker that prevents access to time-wasting websites and apps.

| Platform | Network Blocking | App Blocking | Wildcard | Process Freezing | Screen Lock |
|----------|-----------------|--------------|----------|-----------------|-------------|
| **Linux** | eBPF TC Classifier (kernel-level) | fanotify FAN_OPEN_EXEC_PERM | ✅ domain suffix + app prefix | SIGSTOP via /proc | PAM + D-Bus |
| **macOS** | /etc/hosts | Process polling + SIGKILL | ⚠️ app prefix only | SIGSTOP via sysctl | pmset + ScreenSaverEngine |
| **iOS** | ManagedSettings WebDomain | FamilyControls ApplicationToken | ✅ domain (auto) | — | — |
| **Android** | DNS VPN (local TUN) | UsageStats overlay | ✅ domain suffix + app prefix | — | — |

→ **[完整功能文档 docs/features.md](docs/features.md)**

## Features

- **Network blocking**: Blocks outbound connections to configured domains at the kernel/firewall level
- **App blocking**: Prevents blocked applications from running
- **Wildcard matching**: `*.bilibili.com` blocks all subdomains; `bilibili*` blocks all processes with that prefix
- **Process freezing**: Suspends running processes with SIGSTOP (reversible)
- **Forced screen lock**: Enforces screen lock during configurable hours (default 01:00-07:00)
- **TUI interface**: Interactive terminal UI for real-time blocklist management
- **Daemon mode**: Headless background operation
- **Runtime control**: Unix socket API (Linux/macOS) and HTTP API (iOS/Android) for programmatic control

## Architecture

```
antidistractor/           # Cross-platform userspace binary (TUI + daemon)
  src/
    main.rs               # Platform-aware entry point
    ui.rs                 # Cross-platform TUI (ratatui)
    control_server.rs     # Unix socket control server
    process_freezer.rs    # SIGSTOP/SIGCONT (cross-platform)
    ebpf.rs               # Linux eBPF manager
    app_blocker.rs        # Linux fanotify app blocker
    macos/                # macOS-specific implementations
      pf_blocker.rs       # PF firewall + /etc/hosts
      app_watcher.rs      # Process polling + SIGKILL
      process_utils.rs    # sysctl process enumeration
      screen_lock.rs      # pmset/screensaver lock
      notifications.rs    # osascript notifications

antidistractor-ebpf/      # Linux eBPF TC classifier (kernel program)
antidistractor-common/    # Shared types
```

---

## Linux

### Prerequisites

- Linux kernel 5.15+ with BPF support
- Rust nightly toolchain
- `bpf-linker` (`cargo install bpf-linker`)

### Build

```bash
# Install prerequisites and build everything
make all

# Or build separately:
make build-ebpf    # Build eBPF kernel program
make build-user    # Build userspace binary
```

### How it works (Linux)

The eBPF program attaches to the TC egress qdisc and inspects every outgoing packet:

1. Filter for TCP port 443
2. Parse the TLS record layer for ClientHello handshake
3. Walk TLS extensions to find SNI (type 0x0000)
4. Look up the hostname in a BPF HashMap (`BLOCKLIST`)
5. Return `TC_ACT_SHOT` (drop) if matched, `TC_ACT_OK` otherwise

### Usage (Linux)

```bash
# Interactive TUI (requires root for eBPF)
sudo ./target/release/antidistractor

# Daemon mode
sudo ./target/release/antidistractor --daemon
```

### Systemd Service (Linux)

```bash
sudo cp target/release/antidistractor /usr/local/bin/
sudo tee /etc/systemd/system/antidistractor.service << 'EOF'
[Unit]
Description=Antidistractor - eBPF based website blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/antidistractor --daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now antidistractor.service
```

### Forced Screen Lock (Linux, 01:00-07:00)

```bash
# 1. Install PAM time-check script
sudo install -m 755 scripts/enforce-lock.sh /usr/local/bin/

# 2. Add PAM rule to GDM (insert after pam_nologin.so line):
#    auth requisite pam_exec.so quiet /usr/local/bin/enforce-lock.sh
# In both: /etc/pam.d/gdm-password and /etc/pam.d/gdm-fingerprint

# 3. Install and enable the lock daemon
sudo install -m 755 scripts/enforce-lock-daemon.sh /usr/local/bin/
sudo cp scripts/enforce-lock.service /etc/systemd/system/
sudo systemctl enable --now enforce-lock.service
```

### Proxy Integration (mihomo/Clash Meta)

For traffic routed through a local proxy (e.g., mihomo-party at 127.0.0.1:7890), the eBPF blocker cannot inspect the encapsulated traffic. Add REJECT rules in your mihomo override script:

```javascript
const blockedDomains = ['bilibili.com', 'bilivideo.com', 'biliapi.net', 'biliapi.com']
if (config.rules && Array.isArray(config.rules)) {
  const rejectRules = blockedDomains.map(d => `DOMAIN-SUFFIX,${d},REJECT`)
  config.rules = [...rejectRules, ...config.rules]
}
```

---

## macOS

### Prerequisites

- macOS 10.15+ (Catalina or later)
- Rust stable toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Root access (for pfctl and /etc/hosts)

### Build

```bash
# Build for current architecture (Apple Silicon or Intel)
make build-macos

# Or directly:
cargo build --package antidistractor --release
```

### How it works (macOS)

**Network blocking** (two-layer approach):
1. `/etc/hosts`: Maps blocked domains to `127.0.0.1` — prevents DNS-based access
2. **PF firewall anchor**: Blocks outbound TCP/UDP to resolved IPs at the kernel level

DNS is periodically refreshed (every 5 minutes) to handle CDN IP rotation.

**App blocking**: A background thread polls the process list every 500ms. When a blocked app is found, it receives `SIGKILL` immediately and a desktop notification is shown.

**Process freezing**: Uses `SIGSTOP`/`SIGCONT` with macOS `sysctl(KERN_PROC_ALL)` for process enumeration.

### Usage (macOS)

```bash
# Interactive TUI (requires root for PF + hosts)
sudo ./target/release/antidistractor

# Daemon mode
sudo ./target/release/antidistractor --daemon

# Screen lock daemon only
sudo ./target/release/antidistractor --screen-lock-daemon
```

Keys in TUI:
- `a` - Add domain to blocklist
- `d` - Remove last domain
- `p` - Toggle protection on/off
- `q` - Quit

### Install as System Daemon (macOS)

```bash
# Install binary + launchd daemon (starts at boot)
sudo make install-macos-daemon

# Or step by step:
sudo make install-macos                    # Install binary only
sudo cp scripts/com.antidistractor.daemon.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.antidistractor.daemon.plist
```

### Forced Screen Lock (macOS, 01:00-07:00)

The screen lock daemon enforces screen lock during 01:00-07:00, similar to the Linux PAM mechanism.

```bash
# Install screen lock daemon
sudo cp scripts/com.antidistractor.screenlock.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.antidistractor.screenlock.plist

# Check status
sudo launchctl list | grep antidistractor
```

The daemon:
- Locks the screen at 01:00 using `pmset displaysleepnow` + ScreenSaverEngine
- Checks every 60 seconds if the screen was unlocked during the lock window
- Re-locks immediately if the screen is unlocked during 01:00-07:00

### Runtime Control (macOS)

Send commands to the running daemon via Unix socket:

```bash
# Install control script
sudo cp scripts/antidistractor-ctl-macos /usr/local/bin/antidistractor-ctl

# Usage:
antidistractor-ctl '{"cmd":"status"}'
antidistractor-ctl '{"cmd":"block","domains":["tiktok.com","youtube.com"]}'
antidistractor-ctl '{"cmd":"unblock","domains":["youtube.com"]}'
antidistractor-ctl '{"cmd":"focus_mode","enabled":true,"domains":["twitter.com"]}'
antidistractor-ctl '{"cmd":"block_app","names":["WeChat","Bilibili"]}'
antidistractor-ctl '{"cmd":"freeze_app","names":["Finder"]}'
antidistractor-ctl '{"cmd":"thaw_app","names":["Finder"]}'
```

### Uninstall (macOS)

```bash
sudo make uninstall-macos-daemon
```

---

## Technical Notes

### Linux: GSO on TC Egress

On the TC egress path, TCP segmentation hasn't happened yet. The linear portion of the skb (`ctx.data()` to `ctx.data_end()`) typically contains only the 54-byte headers (ETH+IP+TCP). The actual TCP payload (including TLS ClientHello) resides in skb fragments. This is why `bpf_skb_load_bytes()` is essential — it can read from both linear and non-linear skb data.

### Linux: BPF Verifier Tricks

- **`name_len | 1`**: Guarantees the read length is always >= 1, preventing "invalid zero-sized read" verifier errors
- **`PerCpuArray` map buffer**: Used instead of stack arrays to avoid the 512-byte BPF stack limit
- **Bounded loops**: All loops have explicit iteration limits (e.g., `for _ in 0..64u32`) to satisfy the verifier's termination check

### macOS: PF Anchor

The PF anchor `antidistractor` is added to `/etc/pf.conf` and loaded via:
```
pfctl -a antidistractor -f /etc/pf.anchors/antidistractor
```

Rules use a PF table `<antidistractor_blocked>` for efficient IP-set membership:
```
table <antidistractor_blocked> { 1.2.3.4, 5.6.7.8 }
block out quick proto {tcp, udp} from any to <antidistractor_blocked>
```

### macOS: App Blocking Limitations

macOS lacks a kernel-level exec interception API equivalent to Linux's `fanotify FAN_OPEN_EXEC_PERM` without the Endpoint Security framework (which requires Apple entitlements and notarization). The polling approach has a ~0-500ms window where a blocked app can briefly run before being killed.

## License

MIT
