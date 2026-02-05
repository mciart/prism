use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, Ipv6Packet};
use std::net::{IpAddr, SocketAddr};
use bytes::Bytes;

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

fn inspect_tcp(buffer: &[u8], dst_ip: IpAddr, original_packet: &[u8]) -> Option<PrismTrap> {
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
                 // Removed unused variables and simplified logic for now
                 
                 // Fallback to read-only check if we can't easily mutate safely yet
                 let tcp_packet = TcpPacket::new_checked(buffer).ok()?;
                 if tcp_packet.syn() && !tcp_packet.ack() {
                      let event = PrismTrap {
                         dst: SocketAddr::new(dst_ip, tcp_packet.dst_port()),
                         packet: Bytes::copy_from_slice(original_packet), 
                     };
                     return Some(event);
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
                if old_mss > 1280 {
                    options[i+2] = (1280 >> 8) as u8;
                    options[i+3] = (1280 & 0xFF) as u8;
                }
            }
            break; // MSS only appears once
        }
        i += len;
    }
}
