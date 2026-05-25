# Antidistractor

An eBPF-based website blocker for Linux that intercepts TLS ClientHello packets on the TC egress path and drops connections to blocked domains by inspecting the SNI (Server Name Indication) field.

## Features

- **Kernel-level blocking**: Uses eBPF TC classifier to drop packets before they leave the machine - cannot be bypassed by browser extensions or DNS tricks
- **SNI inspection**: Parses TLS ClientHello to extract the target hostname from the SNI extension
- **GSO-aware**: Uses `bpf_skb_load_bytes()` to read packet data from skb fragments (handles Generic Segmentation Offload on egress)
- **Proxy-aware blocking**: Injects REJECT rules into mihomo/Clash Meta proxy config to block proxied traffic
- **Forced screen lock**: Enforces screen lock during configurable hours (default 01:00-07:00) with PAM-level authentication denial
- **TUI interface**: Interactive terminal UI for managing the blocklist in real-time
- **Daemon mode**: Headless operation as a systemd service

## Architecture

```
antidistractor/           # Userspace binary (TUI + daemon)
antidistractor-ebpf/      # eBPF TC classifier (runs in kernel)
antidistractor-common/    # Shared types between kernel and userspace
```

The eBPF program attaches to the TC egress qdisc and inspects every outgoing packet:

1. Filter for TCP port 443
2. Parse the TLS record layer for ClientHello handshake
3. Walk TLS extensions to find SNI (type 0x0000)
4. Look up the hostname in a BPF HashMap (`BLOCKLIST`)
5. Return `TC_ACT_SHOT` (drop) if matched, `TC_ACT_OK` otherwise

## Prerequisites

- Linux kernel 5.15+ with BPF support
- Rust nightly toolchain
- `bpf-linker` (`cargo install bpf-linker`)

## Build

```bash
# Install prerequisites and build everything
make all

# Or build separately:
make build-ebpf    # Build eBPF program
make build-user    # Build userspace binary
```

## Usage

### Interactive TUI

```bash
sudo ./target/release/antidistractor
```

Keys:
- `a` - Add domain to blocklist
- `d` - Remove last domain
- `p` - Toggle protection on/off
- `q` - Quit

### Daemon Mode

```bash
sudo ./target/release/antidistractor --daemon
```

### Systemd Service

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

## Forced Screen Lock (01:00 - 07:00)

The project includes a forced screen lock mechanism that:
- Locks the screen at 01:00 every night
- Prevents unlocking (PAM denies all authentication) until 07:00
- Monitors D-Bus for any bypass attempts and re-locks immediately

### Setup

```bash
# 1. Install the PAM time-check script
sudo install -m 755 scripts/enforce-lock.sh /usr/local/bin/

# 2. Add PAM rule to GDM (insert after pam_nologin.so line):
#    auth requisite pam_exec.so quiet /usr/local/bin/enforce-lock.sh
# In both: /etc/pam.d/gdm-password and /etc/pam.d/gdm-fingerprint

# 3. Install and enable the lock daemon
sudo install -m 755 scripts/enforce-lock-daemon.sh /usr/local/bin/
sudo cp scripts/enforce-lock.service /etc/systemd/system/
sudo systemctl enable --now enforce-lock.service
```

## Proxy Integration (mihomo/Clash Meta)

For traffic routed through a local proxy (e.g., mihomo-party at 127.0.0.1:7890), the eBPF blocker cannot inspect the encapsulated traffic. Add REJECT rules in your mihomo override script:

```javascript
const blockedDomains = ['bilibili.com', 'bilivideo.com', 'biliapi.net', 'biliapi.com']
if (config.rules && Array.isArray(config.rules)) {
  const rejectRules = blockedDomains.map(d => `DOMAIN-SUFFIX,${d},REJECT`)
  config.rules = [...rejectRules, ...config.rules]
}
```

## Technical Notes

### GSO on TC Egress

On the TC egress path, TCP segmentation hasn't happened yet. The linear portion of the skb (`ctx.data()` to `ctx.data_end()`) typically contains only the 54-byte headers (ETH+IP+TCP). The actual TCP payload (including TLS ClientHello) resides in skb fragments. This is why `bpf_skb_load_bytes()` is essential - it can read from both linear and non-linear skb data.

### BPF Verifier Tricks

- **`name_len | 1`**: Guarantees the read length is always >= 1, preventing "invalid zero-sized read" verifier errors
- **`PerCpuArray` map buffer**: Used instead of stack arrays to avoid the 512-byte BPF stack limit
- **Bounded loops**: All loops have explicit iteration limits (e.g., `for _ in 0..64u32`) to satisfy the verifier's termination check

## License

MIT
