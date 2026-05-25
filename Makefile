.PHONY: all build-ebpf build-user run clean setup

# 自动检测默认网卡
IFACE := $(shell ip route show default | awk '{print $$5}' | head -n1)
# 检查是否安装了 bpf-linker
BPF_LINKER := $(shell command -v bpf-linker 2> /dev/null)

all: setup build-ebpf build-user

setup:
	@echo "Checking prerequisites..."
	@rustup toolchain install nightly
	@rustup component add rust-src --toolchain nightly
ifeq ($(BPF_LINKER),)
	@echo "Installing bpf-linker..."
	@cargo install bpf-linker
endif

build-ebpf:
	@echo "Building eBPF program (Target: $(IFACE))..."
	# 显式传递 -g 和 --btf 链接参数
	RUSTFLAGS="-g -C link-arg=--btf" cargo +nightly build --package antidistractor-ebpf --target bpfel-unknown-none -Z build-std=core --release

build-user:
	@echo "Building userspace application..."
	cargo build --package antidistractor --release

run: build-ebpf build-user
	@echo "Starting Antidistractor on interface: $(IFACE)"
	@echo "Requesting sudo for eBPF loading..."
	sudo ./target/release/antidistractor

clean:
	cargo clean
