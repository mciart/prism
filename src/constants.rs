/// Maximum number of packets to process per event-loop wakeup.
/// Higher values reduce context switching overhead but increase latency jitter.
pub const BATCH_SIZE: usize = 64;

/// Internal mpsc channel queue depth for TUN <-> Stack communication.
pub const CHANNEL_SIZE: usize = 8192;

/// Single TCP connection receive buffer size.
/// Large buffers (2MB) are needed to saturate high Bandwidth-Delay Product (BDP) links (10Gbps).
pub const TCP_RX_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Single TCP connection send buffer size.
pub const TCP_TX_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// TX buffer pool pre-allocation count.
pub const TX_POOL_CAPACITY: usize = 64;

/// TX buffer pool maximum size. Prevents unbounded growth under extreme load.
pub const TX_POOL_MAX_SIZE: usize = 128;

/// Minimum remaining capacity in a TX buffer to be recycled back to the pool.
pub const TX_POOL_RECYCLE_THRESHOLD: usize = 2048;

/// Arena allocation chunk size for TX buffers (64KB = one Jumbo Frame).
pub const TX_ARENA_SIZE: usize = 65535;

/// Default MSS clamp value for egress path compatibility.
pub const DEFAULT_MSS_CLAMP: u16 = 1280;

/// Size of the virtio_net_hdr structure (Linux GSO/GRO).
/// When IFF_VNET_HDR is enabled, the TUN device prepends this header to each packet.
pub const VIRTIO_NET_HDR_SIZE: usize = 10;
