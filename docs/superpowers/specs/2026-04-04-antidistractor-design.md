# Antidistractor 设计文档

**日期：** 2026-04-04
**状态：** 提案中
**目标：** 实现一个在 Linux 系统上运行、带有 TUI 界面、基于 eBPF 的高效网页屏蔽工具。

## 1. 项目背景与目标

Antidistractor 旨在帮助 Linux 用户保持专注，类似于 Windows/macOS 上的 Cold Turkey Blocker。其核心目标是提供一个难以绕过、低开销且与现代代理软件（如 Clash）兼容的网站屏蔽方案。

### 核心特性：
- **强力屏蔽**：利用 eBPF 在内核态拦截 TLS SNI 请求，无视代理软件的 TUN/Fake-IP 模式。
- **低资源占用**：eBPF 保证了即使在大规模屏蔽列表下也几乎不产生性能损耗。
- **现代化 TUI**：基于 Ratatui 构建仪表盘风格的终端界面。
- **Rust 实现**：保证内存安全与高效的分发。

## 2. 系统架构

系统分为两个主要部分：用户态（User Space）和内核态（Kernel Space）。

### 2.1 内核态 (eBPF)
- **挂钩点 (Hook Point)**：TC (Traffic Control) 出口过滤。
- **功能**：
    - 解析出口数据包，识别 TCP 端口 443 流量。
    - 提取 TLS Client Hello 中的 SNI 字段。
    - 在 `BPF_MAP_TYPE_HASH` 中查找该域名。
    - 如果匹配，则直接丢弃包或返回 RST。

### 2.2 用户态 (Rust)
- **框架**：Aya-rs。
- **职责**：
    - 加载和挂载 eBPF 程序。
    - 与内核态通过 eBPF Maps 通信（同步屏蔽名单、读取拦截日志）。
    - 提供 TUI 交互界面。
    - 持久化配置管理（域名列表、计划任务等）。

## 3. 技术栈

- **开发语言**：Rust
- **eBPF 库**：Aya (aya-rs.dev)
- **TUI 框架**：Ratatui
- **配置格式**：TOML 或 YAML
- **核心依赖**：
    - `tokio`：异步运行时
    - `ratatui`：UI 渲染
    - `aya`：eBPF 加载与交互

## 4. 界面设计 (TUI)

采用**仪表盘风格**，包含以下模块：
- **Sidebar (侧边栏)**：导航（概览、名单、日志、设置）。
- **Status View (状态视图)**：显示运行状态、倒计时、统计数据。
- **List Manager (名单管理)**：增删改查屏蔽域名。
- **Real-time Logs (实时日志)**：展示 eBPF 拦截详情。

## 5. 安全与权限

- **Root 权限**：加载 eBPF 程序必须以 root 权限运行。
- **自保护**：后期考虑防止非预期的进程结束。

## 6. 实现路线图

### 第一阶段：MVP (最小可行性产品)
1. 环境搭建：Rust + Aya 项目脚手架。
2. eBPF 核心：实现简单的 SNI 提取与丢包逻辑。
3. TUI 基础：实现基本的 Dashboard 布局。
4. 联动测试：在 Clash 开启状态下验证屏蔽效果。

### 第二阶段：功能完善
1. 完整的名单管理。
2. 倒计时锁定功能。
3. 统计报表。

## 7. 风险评估

- **ECH (Encrypted Client Hello)**：当 ECH 普及时，SNI 屏蔽将失效。届时需引入 IP 级别屏蔽作为补充。
- **内核碎片化**：需依赖 CO-RE 技术确保兼容性。
