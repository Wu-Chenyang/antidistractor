# Antidistractor Makefile
# Supports both Linux (eBPF) and macOS (PF firewall) builds.

.PHONY: all build-ebpf build-user build-macos run run-macos clean setup setup-macos \
        install-macos install-macos-daemon uninstall-macos-daemon

# ─── Linux build ──────────────────────────────────────────────────────────────

# Auto-detect default network interface (Linux)
IFACE := $(shell ip route show default 2>/dev/null | awk '{print $$5}' | head -n1)
# Check if bpf-linker is installed
BPF_LINKER := $(shell command -v bpf-linker 2>/dev/null)

# Default target: build for current platform
ifeq ($(shell uname),Darwin)
all: build-macos
else
all: setup build-ebpf build-user
endif

setup:
	@echo "Checking prerequisites (Linux)..."
	@rustup toolchain install nightly
	@rustup component add rust-src --toolchain nightly
ifeq ($(BPF_LINKER),)
	@echo "Installing bpf-linker..."
	@cargo install bpf-linker
endif

build-ebpf:
	@echo "Building eBPF program (Target interface: $(IFACE))..."
	cd antidistractor-ebpf && RUSTFLAGS="-g -C link-arg=--btf" cargo +nightly build \
		--target bpfel-unknown-none \
		-Z build-std=core \
		--release

build-user:
	@echo "Building userspace application (Linux)..."
	cargo build --package antidistractor --release

run: build-ebpf build-user
	@echo "Starting Antidistractor on interface: $(IFACE)"
	@echo "Requesting sudo for eBPF loading..."
	sudo ./target/release/antidistractor

# ─── macOS build ──────────────────────────────────────────────────────────────

MACOS_BINARY := ./target/release/antidistractor

setup-macos:
	@echo "Checking prerequisites (macOS)..."
	@command -v rustup >/dev/null 2>&1 || (echo "Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" && exit 1)
	@rustup target add aarch64-apple-darwin x86_64-apple-darwin 2>/dev/null || true
	@echo "Prerequisites OK."

build-macos: setup-macos
	@echo "Building Antidistractor for macOS..."
	cargo build --package antidistractor --release
	@echo "Binary: $(MACOS_BINARY)"

run-macos: build-macos
	@echo "Starting Antidistractor (macOS, PF + hosts mode)..."
	@echo "Requires root for pfctl and /etc/hosts modification."
	sudo $(MACOS_BINARY)

# Install binary and launchd daemon
install-macos: build-macos
	@echo "Installing Antidistractor on macOS..."
	sudo cp $(MACOS_BINARY) /usr/local/bin/antidistractor
	sudo chmod 755 /usr/local/bin/antidistractor
	@echo "Binary installed to /usr/local/bin/antidistractor"
	@echo ""
	@echo "To install as a system daemon (runs at boot):"
	@echo "  make install-macos-daemon"

install-macos-daemon: install-macos
	@echo "Installing launchd daemon..."
	sudo cp scripts/com.antidistractor.daemon.plist /Library/LaunchDaemons/
	sudo launchctl load /Library/LaunchDaemons/com.antidistractor.daemon.plist
	@echo "Daemon installed and started."
	@echo ""
	@echo "To install screen lock enforcement:"
	sudo cp scripts/com.antidistractor.screenlock.plist /Library/LaunchDaemons/
	sudo launchctl load /Library/LaunchDaemons/com.antidistractor.screenlock.plist
	@echo "Screen lock daemon installed."
	@echo ""
	@echo "Install control script:"
	sudo cp scripts/antidistractor-ctl-macos /usr/local/bin/antidistractor-ctl
	sudo chmod 755 /usr/local/bin/antidistractor-ctl

uninstall-macos-daemon:
	@echo "Uninstalling launchd daemons..."
	-sudo launchctl unload /Library/LaunchDaemons/com.antidistractor.daemon.plist 2>/dev/null
	-sudo launchctl unload /Library/LaunchDaemons/com.antidistractor.screenlock.plist 2>/dev/null
	-sudo rm -f /Library/LaunchDaemons/com.antidistractor.daemon.plist
	-sudo rm -f /Library/LaunchDaemons/com.antidistractor.screenlock.plist
	-sudo rm -f /usr/local/bin/antidistractor
	-sudo rm -f /usr/local/bin/antidistractor-ctl
	@echo "Uninstalled."

# ─── Common ───────────────────────────────────────────────────────────────────

clean:
	cargo clean
