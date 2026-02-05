/// Buffer size for operations on the TUN interface.
pub const PACKET_BUFFER_SIZE: usize = 4;

/// Packet channel size used for communication between the TUN interface and TCP/TLS tunnels.
pub const PACKET_CHANNEL_SIZE: usize = 1024 * 1024;
