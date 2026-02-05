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
pub fn get_packet_type(buffer: &Bytes) -> PacketType {
    if buffer.len() < 1 { return PacketType::Unknown; }
    
    let version = buffer[0] >> 4;
    match version {
        4 => {
            if let Ok(ip) = Ipv4Packet::new_checked(buffer.as_ref()) {
                if ip.next_header() == IpProtocol::Tcp {
                    return PacketType::Tcp;
                }
                return PacketType::Other;
            }
            PacketType::Unknown
        }
        6 => {
             if let Ok(_) = Ipv6Packet::new_checked(buffer.as_ref()) {
                // Elegant IPv6 Extension Header Skipping
                if let Ok((next_proto, _offset)) = skip_ipv6_headers(buffer.as_ref()) {
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
pub fn inspect_packet(buffer: &Bytes) -> Option<PrismTrap> {
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

fn inspect_ipv4(buffer: &Bytes) -> Option<PrismTrap> {
    let ipv4_packet = Ipv4Packet::new_checked(buffer.as_ref()).ok()?;
    if ipv4_packet.next_header() != IpProtocol::Tcp {
        return None;
    }

    let _src_addr = IpAddr::V4(ipv4_packet.src_addr().into());
    let dst_addr = IpAddr::V4(ipv4_packet.dst_addr().into());
    let payload = ipv4_packet.payload();

    inspect_tcp(payload, dst_addr, buffer)
}

fn inspect_ipv6(buffer: &Bytes) -> Option<PrismTrap> {
    let ipv6_packet = Ipv6Packet::new_checked(buffer.as_ref()).ok()?;
    
    // Header Skipping Logic
    if let Ok((proto, offset)) = skip_ipv6_headers(buffer.as_ref()) {
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

fn inspect_tcp(buffer: &[u8], dst_ip: IpAddr, original_packet: &Bytes) -> Option<PrismTrap> {
    let tcp_packet = TcpPacket::new_checked(buffer).ok()?;
    
    // Check for SYN flag (and NOT ACK/RST)
    if tcp_packet.syn() && !tcp_packet.ack() && !tcp_packet.rst() {
        let event = PrismTrap {
            dst: SocketAddr::new(dst_ip, tcp_packet.dst_port()),
            packet: original_packet.clone(),
        };
        return Some(event);
    }
    None
}
