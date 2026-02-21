//! Linux Native GSO/GRO support via virtio_net_hdr.
//!
//! This module is only compiled on Linux (`#[cfg(target_os = "linux")]`).
//! It provides helpers to strip and prepend the 10-byte `virtio_net_hdr`
//! that the TUN device prepends/expects when `IFF_VNET_HDR` is enabled.

use bytes::{BytesMut, BufMut};
use crate::constants::VIRTIO_NET_HDR_SIZE;

// virtio_net_hdr flags
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

// virtio_net_hdr gso_type
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Parsed virtio_net_hdr (10 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// Parse a virtio_net_hdr from the start of a buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < VIRTIO_NET_HDR_SIZE {
            return None;
        }
        Some(Self {
            flags: buf[0],
            gso_type: buf[1],
            hdr_len: u16::from_le_bytes([buf[2], buf[3]]),
            gso_size: u16::from_le_bytes([buf[4], buf[5]]),
            csum_start: u16::from_le_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_le_bytes([buf[8], buf[9]]),
        })
    }

    /// Serialize this header to bytes and write to the front of a buffer.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= VIRTIO_NET_HDR_SIZE);
        buf[0] = self.flags;
        buf[1] = self.gso_type;
        buf[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        buf[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        buf[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        buf[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
    }

    /// Create an empty header (GSO_NONE, no checksum offload).
    pub fn none() -> Self {
        Self::default()
    }
}

/// Strip the virtio_net_hdr from the front of a buffer.
/// Returns the IP packet data after the header.
/// 
/// # Panics
/// Panics if buffer is smaller than VIRTIO_NET_HDR_SIZE.
pub fn strip_virtio_hdr(buf: &[u8]) -> &[u8] {
    &buf[VIRTIO_NET_HDR_SIZE..]
}

/// Prepend an empty virtio_net_hdr (GSO_NONE) to a packet for TX.
/// This is the simplest form — no offload, just tells the kernel
/// "this is a normal packet, handle it as-is."
pub fn prepend_virtio_hdr_none(packet: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(VIRTIO_NET_HDR_SIZE + packet.len());
    buf.put_bytes(0, VIRTIO_NET_HDR_SIZE); // 10 zero bytes = GSO_NONE
    buf.put_slice(packet);
    buf
}

/// Prepend a virtio_net_hdr with checksum offload hints.
///
/// For TCP: `csum_start` = IP header length, `csum_offset` = 16 (TCP checksum field offset).
/// For UDP: `csum_start` = IP header length, `csum_offset` = 6 (UDP checksum field offset).
///
/// This tells the kernel to compute the checksum, saving CPU cycles.
pub fn prepend_virtio_hdr_csum(packet: &[u8]) -> BytesMut {
    if packet.is_empty() {
        return prepend_virtio_hdr_none(packet);
    }

    let version = packet[0] >> 4;
    let (ip_hdr_len, protocol) = match version {
        4 => {
            let ihl = (packet[0] & 0x0F) as usize * 4;
            let proto = packet[9];
            (ihl, proto)
        }
        6 => {
            // IPv6: fixed 40-byte header, next_header at offset 6
            let proto = packet[6];
            (40usize, proto)
        }
        _ => return prepend_virtio_hdr_none(packet),
    };

    // Protocol numbers: TCP=6, UDP=17
    let csum_offset: u16 = match protocol {
        6 => 16,  // TCP checksum field offset within TCP header
        17 => 6,  // UDP checksum field offset within UDP header
        _ => return prepend_virtio_hdr_none(packet),
    };

    let hdr = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_NONE, // We're just offloading checksum, not segmentation
        hdr_len: 0,
        gso_size: 0,
        csum_start: ip_hdr_len as u16,
        csum_offset,
    };

    let mut buf = BytesMut::with_capacity(VIRTIO_NET_HDR_SIZE + packet.len());
    buf.resize(VIRTIO_NET_HDR_SIZE + packet.len(), 0);
    hdr.write_to(&mut buf[..VIRTIO_NET_HDR_SIZE]);
    buf[VIRTIO_NET_HDR_SIZE..].copy_from_slice(packet);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_hdr_none_is_all_zeros() {
        let hdr = VirtioNetHdr::none();
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
        assert_eq!(hdr.gso_size, 0);
    }

    #[test]
    fn test_parse_roundtrip() {
        let original = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 54,
            gso_size: 1460,
            csum_start: 34,
            csum_offset: 16,
        };
        let mut buf = [0u8; 10];
        original.write_to(&mut buf);
        let parsed = VirtioNetHdr::parse(&buf).unwrap();
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.gso_type, original.gso_type);
        assert_eq!(parsed.hdr_len, original.hdr_len);
        assert_eq!(parsed.gso_size, original.gso_size);
        assert_eq!(parsed.csum_start, original.csum_start);
        assert_eq!(parsed.csum_offset, original.csum_offset);
    }

    #[test]
    fn test_strip_virtio_hdr() {
        let mut data = vec![0u8; 10]; // 10 bytes header
        data.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]); // IP data
        let stripped = strip_virtio_hdr(&data);
        assert_eq!(stripped.len(), 4);
        assert_eq!(stripped[0], 0x45); // IPv4 version+IHL
    }

    #[test]
    fn test_prepend_virtio_hdr_none() {
        let packet = vec![0x45u8; 20]; // Fake IPv4 packet
        let result = prepend_virtio_hdr_none(&packet);
        assert_eq!(result.len(), VIRTIO_NET_HDR_SIZE + 20);
        // First 10 bytes should be zeros
        assert!(result[..VIRTIO_NET_HDR_SIZE].iter().all(|&b| b == 0));
        assert_eq!(&result[VIRTIO_NET_HDR_SIZE..], &packet[..]);
    }

    #[test]
    fn test_prepend_virtio_hdr_csum_tcp_v4() {
        // Minimal IPv4 TCP packet (IHL=5, proto=6)
        let mut packet = vec![0u8; 40]; // 20 IP + 20 TCP
        packet[0] = 0x45; // Version=4, IHL=5
        packet[9] = 6;    // Protocol = TCP
        let result = prepend_virtio_hdr_csum(&packet);
        
        let hdr = VirtioNetHdr::parse(&result).unwrap();
        assert_eq!(hdr.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr.csum_start, 20); // IP header = 20 bytes
        assert_eq!(hdr.csum_offset, 16); // TCP checksum offset
    }

    #[test]
    fn test_prepend_virtio_hdr_csum_udp_v6() {
        // Minimal IPv6 UDP packet
        let mut packet = vec![0u8; 48]; // 40 IPv6 + 8 UDP
        packet[0] = 0x60; // Version=6
        packet[6] = 17;   // Next Header = UDP
        let result = prepend_virtio_hdr_csum(&packet);
        
        let hdr = VirtioNetHdr::parse(&result).unwrap();
        assert_eq!(hdr.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr.csum_start, 40); // IPv6 fixed header
        assert_eq!(hdr.csum_offset, 6);  // UDP checksum offset
    }

    #[test]
    fn test_prepend_virtio_hdr_csum_unknown_proto() {
        // ICMP (protocol 1) — should fall back to none
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1; // ICMP
        let result = prepend_virtio_hdr_csum(&packet);
        
        let hdr = VirtioNetHdr::parse(&result).unwrap();
        assert_eq!(hdr.flags, 0); // No offload
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
    }
}
