use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, Ipv6Packet};
use std::net::{IpAddr, SocketAddr};
use bytes::Bytes;
use crate::constants::DEFAULT_MSS_CLAMP;

#[derive(Debug, Clone)]
pub struct PrismTrap {
    pub dst: SocketAddr,
    pub packet: Bytes,
}

pub type TrapEvent = PrismTrap;

pub enum PacketType {
    Tcp,
    Other, // UDP, ICMP, etc.
    Unknown, // Not IP
}

/// Inspects the packet to determine if it is TCP or something else.
pub fn get_packet_type(buffer: &[u8]) -> PacketType {
    if buffer.len() < 1 { return PacketType::Unknown; }
    
    let version = buffer[0] >> 4;
    match version {
        4 => {
            if let Ok(ip) = Ipv4Packet::new_checked(buffer) {
                if ip.next_header() == IpProtocol::Tcp {
                    return PacketType::Tcp;
                }
                return PacketType::Other;
            }
            PacketType::Unknown
        }
        6 => {
            if let Ok(_) = Ipv6Packet::new_checked(buffer) {
                // Elegant IPv6 Extension Header Skipping
                if let Ok((next_proto, _offset)) = skip_ipv6_headers(buffer) {
                     if next_proto == IpProtocol::Tcp {
                         return PacketType::Tcp;
                     }
                }
                
                return PacketType::Other;
            }
            PacketType::Unknown
        }
        _ => PacketType::Unknown,
    }
}

fn skip_ipv6_headers(buffer: &[u8]) -> Result<(IpProtocol, usize), ()> {
    if buffer.len() < 40 { return Err(()); }
    let mut next_header = IpProtocol::from(buffer[6]); // Next Header field in IPv6 fixed header
    let mut offset = 40;
    
    for _ in 0..10 {
        if next_header == IpProtocol::Tcp {
            return Ok((next_header, offset));
        }
        
        match next_header {
            IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Frag | IpProtocol::Ipv6Opts => {
                if offset + 2 > buffer.len() { return Err(()); }
                let next_proto = IpProtocol::from(buffer[offset]);
                
                let hdr_len = if next_header == IpProtocol::Ipv6Frag {
                    8
                } else {
                    (buffer[offset + 1] as usize + 1) * 8
                };
                
                next_header = next_proto;
                offset += hdr_len;
            },
            _ => return Ok((next_header, offset)), // Found L4 or Unknown
        }
    }
    // Too many headers or loop
    Err(())
}

/// Inspects a raw packet buffer to detect TCP SYN segments.
pub fn inspect_packet(buffer: &[u8]) -> Option<PrismTrap> {
    // Basic length check
    if buffer.len() < 20 {
        return None;
    }

    let version = buffer[0] >> 4;
    match version {
        4 => inspect_ipv4(buffer),
        6 => inspect_ipv6(buffer),
        _ => None,
    }
}

fn inspect_ipv4(buffer: &[u8]) -> Option<PrismTrap> {
    let ipv4_packet = Ipv4Packet::new_checked(buffer).ok()?;
    if ipv4_packet.next_header() != IpProtocol::Tcp {
        return None;
    }

    let _src_addr = IpAddr::V4(ipv4_packet.src_addr().into());
    let dst_addr = IpAddr::V4(ipv4_packet.dst_addr().into());
    let payload = ipv4_packet.payload();

    inspect_tcp(payload, dst_addr, buffer)
}

fn inspect_ipv6(buffer: &[u8]) -> Option<PrismTrap> {
    let ipv6_packet = Ipv6Packet::new_checked(buffer).ok()?;
    
    // Header Skipping Logic
    if let Ok((proto, offset)) = skip_ipv6_headers(buffer) {
        if proto == IpProtocol::Tcp {
             if offset > buffer.len() { return None; }
             let payload = &buffer[offset..];
             let _src_addr = IpAddr::V6(ipv6_packet.src_addr().into());
             let dst_addr = IpAddr::V6(ipv6_packet.dst_addr().into());
             return inspect_tcp(payload, dst_addr, buffer);
        }
    }

    None
}

fn inspect_tcp(_buffer: &[u8], dst_ip: IpAddr, original_packet: &[u8]) -> Option<PrismTrap> {
    // We need to modify the MSS option if present (MSS Clamping)
    // But original_packet is &[u8] which is immutable.
    // However, PrismTrap stores a Bytes, which owns the data.
    // To implement MSS clamping, we should probably do it *before* wrapping in PrismTrap,
    // or modify the Bytes in PrismTrap.
    // Wait, PrismTrap stores `packet: Bytes`.
    // The `inspect_packet` function returns `Option<PrismTrap>`.
    // If we want to clamp MSS, we must modify the packet data HERE.
    
    // To modify, we need to clone to a mutable buffer first.
    // This is the "Trap" path (SYN only), so copying is acceptable (low frequency).
    
    let mut modified_packet = original_packet.to_vec();
    
    // Reparse from mutable buffer
    // Note: We already know it's valid IP/TCP from previous checks
    let version = modified_packet[0] >> 4;
    
    match version {
        4 => {
            if let Ok(mut ip) = Ipv4Packet::new_checked(&mut modified_packet) {
                let src_addr = ip.src_addr();
                let dst_addr = ip.dst_addr();
                
                // Re-borrow payload after inner scope
                let payload = ip.payload_mut();
                
                // 1. Check flags & get port
                let mut should_clamp = false;
                let mut dst_port = 0;
                if let Ok(tcp) = TcpPacket::new_checked(&payload) {
                     if tcp.syn() && !tcp.ack() {
                         should_clamp = true;
                         dst_port = tcp.dst_port();
                     }
                }
                
                if should_clamp {
                    // 2. Clamp MSS on raw payload
                    clamp_mss_raw(payload);
                    
                    // 3. Re-calculate checksums
                    if let Ok(mut tcp) = TcpPacket::new_checked(payload) {
                        tcp.fill_checksum(&src_addr.into(), &dst_addr.into());
                    }
                    ip.fill_checksum();
                    
                    let event = PrismTrap {
                        dst: SocketAddr::new(dst_ip, dst_port),
                        packet: Bytes::from(modified_packet),
                    };
                    return Some(event);
                }
            }
        },
        6 => {
             if let Ok(_) = Ipv6Packet::new_checked(&mut modified_packet) {
                 // IPv6 Extension Header Skipping to find TCP payload
                 if let Ok((proto, offset)) = skip_ipv6_headers(&modified_packet) {
                     if proto == IpProtocol::Tcp && offset < modified_packet.len() {
                         let tcp_payload = &modified_packet[offset..];
                         
                         // 1. Check SYN flag & get port
                         let mut should_clamp = false;
                         let mut dst_port = 0;
                         if let Ok(tcp) = TcpPacket::new_checked(tcp_payload) {
                             if tcp.syn() && !tcp.ack() {
                                 should_clamp = true;
                                 dst_port = tcp.dst_port();
                             }
                         }
                         
                         if should_clamp {
                             // 2. Clamp MSS on TCP payload (mutable slice)
                             let tcp_payload_mut = &mut modified_packet[offset..];
                             clamp_mss_raw(tcp_payload_mut);
                             
                             // 3. Re-calculate TCP checksum (IPv6 has no IP checksum)
                             let src_addr = Ipv6Packet::new_checked(&modified_packet).unwrap().src_addr();
                             let dst_addr_smol = Ipv6Packet::new_checked(&modified_packet).unwrap().dst_addr();
                             let tcp_payload_mut = &mut modified_packet[offset..];
                             if let Ok(mut tcp) = TcpPacket::new_checked(tcp_payload_mut) {
                                 tcp.fill_checksum(&src_addr.into(), &dst_addr_smol.into());
                             }
                             
                             let event = PrismTrap {
                                 dst: SocketAddr::new(dst_ip, dst_port),
                                 packet: Bytes::from(modified_packet),
                             };
                             return Some(event);
                         }
                     }
                 }
             }
        },
        _ => {}
    }

    None
}

/// Clamps the MSS option in a TCP packet to a safe value (e.g. 1280)
// Removed old clamp_mss function to avoid confusion and unused code warnings
// Fixed signature to take raw buffer
fn clamp_mss_raw(buffer: &mut [u8]) {
    if buffer.len() < 20 { return; }
    let data_offset = ((buffer[12] >> 4) * 4) as usize;
    if data_offset < 20 || data_offset > buffer.len() { return; }
    
    let options = &mut buffer[20..data_offset];
    
    let mut i = 0;
    while i < options.len() {
        let kind = options[i];
        if kind == 0 || kind == 1 { // EOL or NOP
            i += 1;
            continue;
        }
        if i + 1 >= options.len() { break; }
        let len = options[i+1] as usize;
        if i + len > options.len() { break; }
        
        if kind == 2 { // MSS
            if len == 4 {
                // Found MSS option!
                let old_mss = ((options[i+2] as u16) << 8) | (options[i+3] as u16);
                if old_mss > DEFAULT_MSS_CLAMP {
                    options[i+2] = (DEFAULT_MSS_CLAMP >> 8) as u8;
                    options[i+3] = (DEFAULT_MSS_CLAMP & 0xFF) as u8;
                }
            }
            break; // MSS only appears once
        }
        i += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal IPv4 TCP SYN packet with an MSS option.
    fn build_ipv4_tcp_syn(mss: u16) -> Vec<u8> {
        // IPv4 Header (20 bytes) + TCP Header (24 bytes, with MSS option)
        let mut pkt = vec![0u8; 44];
        // IPv4: version=4, IHL=5
        pkt[0] = 0x45;
        // Total length = 44
        pkt[2] = 0;
        pkt[3] = 44;
        // TTL
        pkt[8] = 64;
        // Protocol = TCP (6)
        pkt[9] = 6;
        // Src IP: 192.168.1.1
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        // Dst IP: 10.0.0.1
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);

        // TCP Header starts at offset 20
        let tcp = &mut pkt[20..];
        // Src port: 12345
        tcp[0] = (12345 >> 8) as u8;
        tcp[1] = (12345 & 0xFF) as u8;
        // Dst port: 80
        tcp[2] = 0;
        tcp[3] = 80;
        // Data offset: 6 (24 bytes = 20 header + 4 option)
        tcp[12] = 6 << 4;
        // Flags: SYN only
        tcp[13] = 0x02;
        // Window: 65535
        tcp[14] = 0xFF;
        tcp[15] = 0xFF;
        // TCP Options: MSS (Kind=2, Len=4, Value=mss)
        tcp[20] = 2; // Kind: MSS
        tcp[21] = 4; // Length
        tcp[22] = (mss >> 8) as u8;
        tcp[23] = (mss & 0xFF) as u8;

        // Compute IP checksum
        compute_ipv4_checksum(&mut pkt);
        // Compute TCP checksum
        compute_tcp_checksum_v4(&mut pkt, 20);

        pkt
    }

    /// Builds a minimal IPv4 UDP packet.
    fn build_ipv4_udp() -> Vec<u8> {
        let mut pkt = vec![0u8; 28]; // 20 IP + 8 UDP
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 28;
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        compute_ipv4_checksum(&mut pkt);
        pkt
    }

    /// Builds a minimal IPv6 TCP SYN packet.
    fn build_ipv6_tcp_syn(mss: u16) -> Vec<u8> {
        // IPv6 Header (40 bytes) + TCP Header (24 bytes with MSS option)
        let mut pkt = vec![0u8; 64];
        // Version = 6
        pkt[0] = 0x60;
        // Payload length = 24 (TCP header with options)
        pkt[4] = 0;
        pkt[5] = 24;
        // Next Header = TCP (6)
        pkt[6] = 6;
        // Hop Limit
        pkt[7] = 64;
        // Src: fd00::2
        pkt[8..24].copy_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Dst: fd00::1
        pkt[24..40].copy_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        // TCP Header at offset 40
        let tcp = &mut pkt[40..];
        tcp[0] = (12345 >> 8) as u8;
        tcp[1] = (12345 & 0xFF) as u8;
        tcp[2] = (443 >> 8) as u8;
        tcp[3] = (443 & 0xFF) as u8;
        tcp[12] = 6 << 4; // Data offset = 6
        tcp[13] = 0x02;   // SYN
        tcp[14] = 0xFF;
        tcp[15] = 0xFF;
        // MSS option
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22] = (mss >> 8) as u8;
        tcp[23] = (mss & 0xFF) as u8;

        pkt
    }

    fn compute_ipv4_checksum(pkt: &mut [u8]) {
        pkt[10] = 0;
        pkt[11] = 0;
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += ((pkt[i] as u32) << 8) | (pkt[i + 1] as u32);
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !sum as u16;
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;
    }

    fn compute_tcp_checksum_v4(pkt: &mut [u8], ip_hdr_len: usize) {
        let tcp_len = pkt.len() - ip_hdr_len;
        let tcp = &mut pkt[ip_hdr_len..];
        tcp[16] = 0;
        tcp[17] = 0;
        let mut sum: u32 = 0;
        // Pseudo-header: src, dst, reserved, proto, tcp_len
        for i in (12..20).step_by(2) {
            sum += ((pkt[i] as u32) << 8) | (pkt[i + 1] as u32);
        }
        sum += 6; // TCP protocol
        sum += tcp_len as u32;
        let tcp = &pkt[ip_hdr_len..];
        for i in (0..tcp_len).step_by(2) {
            let hi = tcp[i] as u32;
            let lo = if i + 1 < tcp_len { tcp[i + 1] as u32 } else { 0 };
            sum += (hi << 8) | lo;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !sum as u16;
        let tcp = &mut pkt[ip_hdr_len..];
        tcp[16] = (cksum >> 8) as u8;
        tcp[17] = (cksum & 0xFF) as u8;
    }

    #[test]
    fn test_get_packet_type_tcp_v4() {
        let pkt = build_ipv4_tcp_syn(1460);
        assert!(matches!(get_packet_type(&pkt), PacketType::Tcp));
    }

    #[test]
    fn test_get_packet_type_udp_v4() {
        let pkt = build_ipv4_udp();
        assert!(matches!(get_packet_type(&pkt), PacketType::Other));
    }

    #[test]
    fn test_get_packet_type_tcp_v6() {
        let pkt = build_ipv6_tcp_syn(1460);
        assert!(matches!(get_packet_type(&pkt), PacketType::Tcp));
    }

    #[test]
    fn test_get_packet_type_empty() {
        assert!(matches!(get_packet_type(&[]), PacketType::Unknown));
    }

    #[test]
    fn test_get_packet_type_garbage() {
        assert!(matches!(get_packet_type(&[0xFF, 0x00]), PacketType::Unknown));
    }

    #[test]
    fn test_inspect_ipv4_syn_detected() {
        let pkt = build_ipv4_tcp_syn(1460);
        let trap = inspect_packet(&pkt);
        assert!(trap.is_some());
        let trap = trap.unwrap();
        assert_eq!(trap.dst.port(), 80);
    }

    #[test]
    fn test_inspect_ipv4_non_syn_ignored() {
        let mut pkt = build_ipv4_tcp_syn(1460);
        // Change flags from SYN (0x02) to ACK (0x10)
        pkt[20 + 13] = 0x10;
        compute_ipv4_checksum(&mut pkt);
        compute_tcp_checksum_v4(&mut pkt, 20);
        assert!(inspect_packet(&pkt).is_none());
    }

    #[test]
    fn test_mss_clamping_ipv4() {
        let pkt = build_ipv4_tcp_syn(1460);
        let trap = inspect_packet(&pkt).expect("Should detect SYN");
        // MSS should be clamped to DEFAULT_MSS_CLAMP (1280)
        // Check the MSS option in the stored packet
        let stored = trap.packet;
        let tcp_options = &stored[20 + 20..20 + 24]; // IP(20) + TCP(20) is where options start
        assert_eq!(tcp_options[0], 2); // Kind = MSS
        assert_eq!(tcp_options[1], 4); // Len = 4
        let clamped_mss = ((tcp_options[2] as u16) << 8) | (tcp_options[3] as u16);
        assert_eq!(clamped_mss, DEFAULT_MSS_CLAMP);
    }

    #[test]
    fn test_mss_not_clamped_if_small() {
        let pkt = build_ipv4_tcp_syn(536); // Already smaller than DEFAULT_MSS_CLAMP
        let trap = inspect_packet(&pkt).expect("Should detect SYN");
        let stored = trap.packet;
        let tcp_options = &stored[20 + 20..20 + 24];
        let mss = ((tcp_options[2] as u16) << 8) | (tcp_options[3] as u16);
        assert_eq!(mss, 536); // Should not be changed
    }

    #[test]
    fn test_inspect_ipv6_syn_detected() {
        let pkt = build_ipv6_tcp_syn(1460);
        let trap = inspect_packet(&pkt);
        assert!(trap.is_some());
        let trap = trap.unwrap();
        assert_eq!(trap.dst.port(), 443);
    }

    #[test]
    fn test_mss_clamping_ipv6() {
        let pkt = build_ipv6_tcp_syn(1460);
        let trap = inspect_packet(&pkt).expect("Should detect IPv6 SYN");
        let stored = trap.packet;
        // IPv6(40) + TCP header(20) = offset 60 for options
        let tcp_options = &stored[60..64];
        assert_eq!(tcp_options[0], 2); // Kind = MSS
        let clamped_mss = ((tcp_options[2] as u16) << 8) | (tcp_options[3] as u16);
        assert_eq!(clamped_mss, DEFAULT_MSS_CLAMP);
    }

    #[test]
    fn test_clamp_mss_raw_directly() {
        // Build a raw TCP header with MSS = 8960
        let mut tcp = vec![0u8; 24];
        tcp[12] = 6 << 4; // Data offset = 6
        tcp[13] = 0x02;   // SYN
        tcp[20] = 2;      // MSS Kind
        tcp[21] = 4;      // MSS Len
        tcp[22] = (8960 >> 8) as u8;
        tcp[23] = (8960 & 0xFF) as u8;

        clamp_mss_raw(&mut tcp);

        let new_mss = ((tcp[22] as u16) << 8) | (tcp[23] as u16);
        assert_eq!(new_mss, DEFAULT_MSS_CLAMP);
    }

    #[test]
    fn test_skip_ipv6_headers_simple() {
        let pkt = build_ipv6_tcp_syn(1460);
        let result = skip_ipv6_headers(&pkt);
        assert!(result.is_ok());
        let (proto, offset) = result.unwrap();
        assert_eq!(proto, IpProtocol::Tcp);
        assert_eq!(offset, 40); // No extension headers
    }
}
