# Prism 网络协议栈开发路线图 (Roadmap)

本文档详细记录了 `prism` 核心库的开发进度、架构设计及后续演进计划。

## 📍 1. 项目概述 (Overview)

**Prism** 是 Mirage VPN 项目的核心网络引擎，基于 Rust 和 `smoltcp` 构建的高性能用户态网络协议栈。
它的核心目标是：
1.  **TCP Meltdown 终结者**: 通过在用户态终结 TCP 连接，将 VPN 流量转化为纯净的数据流，彻底解决 TCP-in-TCP 性能崩溃问题。
2.  **通用 L3/L2 支持**: 同时支持 IP层 (TUN) 和 以太网层 (TAP) 接入，适配各种复杂网络环境。
3.  **零拷贝 (Zero-Copy)**: 利用 Rust 的所有权机制和 `bytes` crate，实现内存安全的高效数据转发。

---

## ✅ 2. 已完成 (Completed Phases)

### Phase 1: 核心剥离与重构 (Extraction)
- [x] **独立 Crate**: 创建 `prism` 为独立 workspace member，解耦 `mirage` 业务逻辑。
- [x] **PrismDevice**: 实现了通用的 PHY 适配层，支持 `tokio` 异步通道 (`mpsc`) 与 `smoltcp` 同步接口的桥接。
- [x] **PrismStack**: 移植并重构了原 `VirtualStack`，作为协议栈的主控中心。
- [x] **PrismTrap**: 实现了高性能的 TCP SYN 拦截器 (AnyIP)，用于按需创建虚拟连接。

### Phase 2: 握手与连接管理 (Handshake Strategy)
- [x] **Fast Mode (抢答模式)**: 收到 SYN 立即回复 SYN-ACK (0-RTT)，适合 Web 浏览。
- [x] **Consistent Mode (同步模式)**: 收到 SYN 后挂起，等待远程隧道建立成功后再回复 SYN-ACK，保留真实 RTT，适合游戏/VoIP。
- [x] **Tunnel Request API**: 定义了清晰的 `TunnelRequest` 接口，允许上层 (Relayer) 动态处理连接请求。

### Phase 3: 内存优化 (Memory Optimization)
- [x] **Phase 6.1 (Clone Safety)**: 初步实现，确保多线程数据传递的安全性。
- [x] **Phase 6.2 (Bytes Refactor)**: 全面引入 `bytes::Bytes` crate。
    - [x] 将所有 `Vec<u8>` 通道替换为 `Bytes`，支持 O(1) 克隆和切片。
    - [x] 优化 `PrismDevice` 的 RX/TX 队列处理。
    - [x] 优化 `mirage-client` 的转发层 (`ClientRelayer`)。
    - [x] **成果**: 实现了 "Safe Zero-Copy"，在 Prism 内部管道中消除了不必要的内存分配。

---

## 🚧 3. 进行中 / 待办 (In Progress & Todo)

### Phase 4: L2 以太网支持 (Ethernet / TAP) 🔴
**目标**: 支持 TAP 模式，允许 Mirage 处理 ARP 请求和非 IP 流量，实现真正的二层虚拟网络。

- [ ] **TAP 设备适配**:
    - [x] `PrismDevice` 已支持 `Medium::Ethernet` 枚举。
    - [x] **平台验证**: macOS 原生 `utun` 仅支持 L3 (TUN)。L2 (TAP) 需要第三方 kext (已废弃)。**结论: macOS 仅支持 L3，L2 功能主要针对 Linux/Windows。**
    - [ ] Linux/Windows TAP 创建测试 (需对应环境)。
- [ ] **ARP 响应 (ARP Responder)**:
    - [ ] 在 `PrismStack` 中启用 `smoltcp` 的 ARP 功能 (`NeighborCache`)。
    - [ ] 实现虚拟网关 ARP 响应 (如 10.0.0.1 对应的虚拟 MAC)。
- [ ] **L2 转发逻辑**:
    - [ ] 识别以太网帧头 (Ethernet II)。
    - [ ] 提取 IP 包进行 TCP/UDP 处理 (同 L3 逻辑)。
    - [ ] 对非 IP 流量 (如 ARP) 进行本地响应或广播处理。

### Phase 5: 深度性能调优 (Advanced Performance) 🟡
**目标**: 将吞吐量推向物理极限 (1Gbps+)。

- [x] **Event-Driven Polling**:
    - [x] 重构 `PrismStack::run`，移除 `sleep(10ms)`。
    - [x] 引入 `tokio::select!` 监听 TUN/Channel 事件。
    - [x] 实现 `SelectAll` 用于动态隧道数据聚合 (Fan-in)。
- [x] **Batch Processing (批量处理)**:
    - [x] 在 `PrismStack` 中实现 Receive Loop 批量读取 (Max 64 pkts)。
- [x] **GSO/GRO (分段卸载)**:
    - [x] 研究结论: macOS `utun` 不支持用户态 GSO/GRO (需 Linux `virtio-net-hdr`)。暂跳过。
- [x] **Smoltcp 缓冲区调优**:
    - [x] `TCP_RX_BUFFER_SIZE` / `TCP_TX_BUFFER_SIZE` 调整为 2MB。

### Phase 6: 协议扩展 (Universal Protocol Support) 🟢
**核心策略**: **TCP 必须拦截** (为了性能和抗 Meltdown)，**其他协议统一切换为纯盲转发 (Blind Relay)**。

- [x] **Blind Relay 机制 (UDP/ICMP/GRE/ESP)**:
    - [x] **实现原理**: 对于非 TCP 流量，直接封装 IP 包转发，不在用户态维护连接状态。
    - [x] **TCP**: 继续保持通过 PrismStack 拦截与终结，确保极致性能。
    - [x] **其他协议**: 通过 Blind Relay 通道 (UDP Tunnel) 直接透传，支持 Ping, DNS (UDP), QUIC 等。

---

## 4. 架构图 (Architecture)

```mermaid
graph TD
    UserApp[用户应用 (Browser/Game)] -->|Syscall| OS_Network[操作系统网络栈]
    OS_Network -->|IP Packet| TUN_Interface[TUN/TAP 网卡]
    
    subgraph "Mirage/Prism User Space"
        TUN_Interface <-->|Read/Write| PrismDevice
        
        subgraph "Prism Core"
            PrismDevice <-->|Bytes| PrismStack[Prism 虚拟协议栈 (smoltcp)]
            PrismStack -- "Intercept SYN" --> PrismTrap[AnyIP 拦截器]
            PrismStack -- "TCP Stream" --> VirtualSocket[Virtual TCP Socket]
        end
        
        VirtualSocket <-->|Bytes| ClientRelayer[Client Relayer]
        ClientRelayer <-->|TLS/Stream| RemoteServer[远端服务器]
    end
```

## 5. 常见问题 (FAQ)

**Q: 为什么需要 Consistent Handshake (同步握手)?**
A: 为了欺骗 TCPing 和游戏客户端。如果使用 Fast Mode (0-RTT)，所有连接看起来都是 <1ms 延迟，这会导致客户端误判网络质量，且无法通过 TCPing 探测真实服务器存活。同步握手确保了"只有这一头通了，我才告诉你通了"。

**Q: Zero-Copy 是真的零拷贝吗?**
A: 在 Rust 生态中，真正的“零拷贝”通常指从内核直接 DMA 到用户态 (io_uring/AF_XDP)。Prism 目前实现的是 **Safe Zero-Copy**：
1. 内核 -> 用户态 (1次拷贝，不可避免，除非用 AF_XDP)。
2. 用户态内部传递 (PrismDevice -> Stack -> Relayer -> TLS) -> **0 拷贝** (全链路引用计数 `Bytes`)。
这是目前标准 socket API 下的最优解。
