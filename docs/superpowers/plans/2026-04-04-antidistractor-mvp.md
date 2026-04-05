# Antidistractor Implementation Plan (MVP)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust-based website blocker using eBPF for SNI-based filtering and Ratatui for the TUI dashboard.

**Architecture:** A Rust workspace consisting of an eBPF program (kernel-side) for packet filtering and a userspace program (TUI) for management and monitoring. They communicate via eBPF Maps.

**Tech Stack:** Rust, Aya (eBPF), Ratatui (TUI), Tokio (Async).

---

### Task 1: Project Initialization

**Files:**
- Create: `Cargo.toml` (Workspace)
- Create: `antidistractor-common/Cargo.toml`
- Create: `antidistractor-common/src/lib.rs`
- Create: `antidistractor-ebpf/Cargo.toml`
- Create: `antidistractor-ebpf/src/main.rs`
- Create: `antidistractor/Cargo.toml`
- Create: `antidistractor/src/main.rs`

- [ ] **Step 1: Create workspace `Cargo.toml`**

```toml
[workspace]
members = [
    "antidistractor",
    "antidistractor-ebpf",
    "antidistractor-common",
]
resolver = "2"
```

- [ ] **Step 2: Initialize `antidistractor-common`**

```rust
// antidistractor-common/src/lib.rs
#![no_std]

pub const MAX_DNS_NAME_LEN: usize = 256;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BlockEntry {
    pub name: [u8; MAX_DNS_NAME_LEN],
    pub len: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEntry {}
```

- [ ] **Step 3: Initialize `antidistractor-ebpf` (Skeleton)**

```rust
// antidistractor-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use antidistractor_common::BlockEntry;

#[map]
static mut BLOCKLIST: HashMap<[u8; 256], u8> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn antidistractor(ctx: TcContext) -> i32 {
    match try_antidistractor(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_antidistractor(_ctx: TcContext) -> Result<i32, u32> {
    Ok(0) // TC_ACT_OK
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

- [ ] **Step 4: Initialize `antidistractor` userspace (Skeleton)**

```rust
// antidistractor/src/main.rs
fn main() {
    println!("Antidistractor starting...");
}
```

- [ ] **Step 5: Verify build**

Run: `cargo build`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "chore: initialize rust workspace and project skeleton"
```

---

### Task 2: eBPF SNI Parsing Logic

**Files:**
- Modify: `antidistractor-ebpf/src/main.rs`

- [ ] **Step 1: Implement SNI extraction in eBPF**

```rust
// Update antidistractor-ebpf/src/main.rs with SNI parsing logic
// (Detailed implementation of parsing Ethernet -> IP -> TCP -> TLS Client Hello -> SNI)
```

- [ ] **Step 2: Implement blocklist lookup**

```rust
// Check extracted SNI against BLOCKLIST map
```

- [ ] **Step 3: Compile eBPF program**

Run: `cargo xtask build-ebpf` (Assuming aya-template structure or similar)
Expected: `target/bpfel-unknown-none/debug/antidistractor` generated.

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: implement SNI parsing and filtering in eBPF"
```

---

### Task 3: Userspace eBPF Loader & Map Interaction

**Files:**
- Modify: `antidistractor/src/main.rs`
- Modify: `antidistractor/Cargo.toml`

- [ ] **Step 1: Add `aya` and `tokio` dependencies**

- [ ] **Step 2: Implement eBPF loader**

```rust
// antidistractor/src/main.rs
// Load eBPF program, attach to TC egress hook, and get handle to BLOCKLIST map.
```

- [ ] **Step 3: Implement test function to add a domain to blocklist**

```rust
// Function to push "bilibili.com" to the eBPF map for testing.
```

- [ ] **Step 4: Run as root and verify blocking**

Run: `sudo cargo run`
Expected: `curl https://www.bilibili.com` should time out/fail.

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: implement userspace eBPF loader and map sync"
```

---

### Task 4: TUI Dashboard Implementation

**Files:**
- Create: `antidistractor/src/ui/mod.rs`
- Create: `antidistractor/src/ui/dashboard.rs`
- Modify: `antidistractor/src/main.rs`

- [ ] **Step 1: Implement Ratatui layout (Dashboard style)**

```rust
// Create the sidebar, status cards, and log area.
```

- [ ] **Step 2: Implement event loop (Input handling)**

```rust
// Handle [q] for quit, [s] for start/stop, [+] for adding domain.
```

- [ ] **Step 3: Integrate TUI with eBPF state**

```rust
// Display real-time stats from the map/logs.
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: implement TUI dashboard and user interaction"
```

---

### Task 5: Persistent Configuration & Logging

**Files:**
- Create: `antidistractor/src/config.rs`
- Modify: `antidistractor/src/main.rs`

- [ ] **Step 1: Implement TOML config loading/saving**

```rust
// Save/Load blocklist to ~/.config/antidistractor/config.toml
```

- [ ] **Step 2: Implement RingBuffer for real-time logs**

```rust
// Use BPF_MAP_TYPE_RINGBUF to send block events to userspace TUI.
```

- [ ] **Step 3: Final verification**

Run: `sudo cargo run`
Expected: Full TUI working, persistent settings, real-time logging.

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: add persistent config and real-time blocking logs"
```
