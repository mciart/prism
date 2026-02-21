use tun_rs::DeviceBuilder;
use std::io;
use smoltcp::phy::Medium;
use tokio::sync::mpsc;
use bytes::{Bytes, BytesMut};
use prism::stack::{PrismStack, PrismConfig, HandshakeMode};
use prism::device::PrismDevice;
use std::sync::Arc;
use clap::Parser;

/// Prism Echo Server Benchmark Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// MTU (Maximum Transmission Unit) for the TUN device.
    /// Use 65535 for GSO/GRO support.
    #[arg(long, default_value_t = 1280)]
    mtu: usize,

    /// Egress MTU (Physical Network Limit).
    /// Used for TCP MSS clamping and UDP packet size limits.
    #[arg(long, default_value_t = 1280)]
    egress_mtu: usize,

    /// Handshake Mode: fast (0-RTT) or consistent (Real RTT)
    #[arg(long, default_value = "fast")]
    mode: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Enable logging
    tracing_subscriber::fmt::init();
    
    // Parse CLI args
    let args = Args::parse();
    let handshake_mode = match args.mode.to_lowercase().as_str() {
        "consistent" => HandshakeMode::Consistent,
        _ => HandshakeMode::Fast,
    };

    println!("🚀 Prism Echo Server Benchmark");
    println!("Operating System: {}", std::env::consts::OS);
    println!("Configuration: TUN MTU={}, Egress MTU={}, Mode={:?}", args.mtu, args.egress_mtu, handshake_mode);
    
    // 1. Create TUN Device
    // User requested 10.11.12.1 to avoid 10.0.0.1 conflict
    let builder = DeviceBuilder::new()
        .ipv4(
            std::net::Ipv4Addr::new(10, 11, 12, 1),
            std::net::Ipv4Addr::new(255, 255, 255, 0),
            None 
        )
        .ipv6(
            std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            64
        )
        .mtu(args.mtu as u16) // Conservative MTU for mobile networks
        .packet_information(false); // Critical for macOS to avoid 4-byte header

    let dev = builder.build_async().expect("Failed to create TUN");
    println!("✅ TUN Device Created: {} (IP: 10.11.12.1, IPv6: fd00::1)", dev.name().unwrap_or("unknown".to_string()));
    let dev = Arc::new(dev); // Wrap in Arc for shared access
    
    // 2. Setup Prism Channels (TUN <-> Stack)
    let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(8192); // Stack -> OS
    let (os_tx, os_rx) = mpsc::channel::<BytesMut>(8192); // OS -> Stack (BytesMut for Zero-Copy)

    // Spawn Bridge Tasks
    // Reader Task
    let reader_dev = dev.clone();
    tokio::spawn(async move {
        // Optimization A: Buffer Reuse (Smart Batching)
        // Allocate a large buffer (1MB) once to reduce malloc overhead
        let mut buf = BytesMut::with_capacity(1024 * 1024);
        
        loop {
            // Ensure capacity for next Jumbo Frame
            if buf.capacity() < 65535 {
                buf.reserve(65535);
            }
            
            // Unsafe Optimization: Avoid memset(0)
            // We set length to 65535 so we have a mutable slice to write into.
            // Safety: We must ensure we don't read uninitialized bytes before writing.
            // tun_rs.recv() will overwrite the buffer content.
            unsafe { buf.set_len(65535) };
            
            // tun-rs AsyncDevice implements AsyncRead
            match reader_dev.recv(&mut buf).await {
                Ok(n) => {
                    if n > 0 {
                         // Truncate to actual read size
                         unsafe { buf.set_len(n) };
                         
                         // Zero-Copy: split_to moves the data ownership to os_tx
                         // The remaining capacity in `buf` is retained for next loop!
                         let packet = buf.split_to(n);
                         
                         if os_tx.send(packet).await.is_err() { break; }
                    }
                }
                Err(e) => {
                    eprintln!("TUN Read Error: {}", e);
                    break;
                }
            }
        }
    });

    // Writer Task
    let writer_dev = dev.clone();
    tokio::spawn(async move {
        while let Some(pkt) = tun_rx.recv().await {
            // tun-rs AsyncDevice implements AsyncWrite or send
            if let Err(e) = writer_dev.send(&pkt).await {
                eprintln!("TUN Write Error: {}", e);
            }
        }
    });

    // 3. Create Prism Stack
    let config = PrismConfig {
        handshake_mode,
        egress_mtu: args.egress_mtu, // Use the dedicated egress MTU parameter
    };
    
    let device = PrismDevice::new(os_rx, tun_tx.clone(), args.mtu, Medium::Ip);
    let mut stack = PrismStack::new(device, config);
    
    // 4. Setup Tunnel Request Handling AND Blind Relay
    let (req_tx, mut req_rx) = mpsc::channel(128);
    stack.set_tunnel_request_sender(req_tx);
    
    let (blind_tx, mut blind_rx) = mpsc::channel(8192);
    stack.set_blind_relay_sender(blind_tx);
    
    // Stack Runner
    tokio::spawn(async move {
        println!("🔥 Stack Running... Waiting for TCP connections & UDP Blind Relay.");
        if let Err(e) = stack.run().await {
            eprintln!("Stack Error: {}", e);
        }
    });

    // 5. TCP Echo Loop (Concurrent with Blind Relay)
    tokio::spawn(async move {
        let mut tunnel_count = 0;
        while let Some(req) = req_rx.recv().await {
            tunnel_count += 1;
            println!("[TCP #{}] New Connection: {}", tunnel_count, req.target);
            
            if let Some(resp) = req.response_tx {
                let _ = resp.send(true);
            }
            let mut rx = req.rx;
            let tx = req.tx;
            tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    if tx.send(data).await.is_err() { break; }
                }
            });
        }
    });

    // 6. Blind Relay Echo Loop (UDP/ICMP Mock)
    // In reality, this would forward to a remote server.
    // For benchmark, we just PRINT and DROP (or Echo if we could parse IP headers easily).
    // Let's just print stats to prove it works.
    println!("🔥 Stack Running... Press Ctrl+C to stop.");
    
    loop {
        tokio::select! {
            res = blind_rx.recv() => {
                match res {
                    Some(pkt) => {
                        // Create a visual log for EVERY packet so user sees activity
                        println!("🔍 Blind Relay: Forwarded packet size={} bytes", pkt.len());
                        
                        // ECHO LOGIC (Mock)
                        // Parse and swap Src/Dst to simulate echo
                        use smoltcp::wire::{Ipv4Packet, Ipv6Packet, UdpPacket, Icmpv4Packet, IpProtocol};
                        
                        // We need a mutable buffer to modify the packet in-place
                        // Bytes is immutable, so we must clone to Vec or BytesMut if we want to edit.
                        // Or create new packet.
                        let len = pkt.len();
                        if len < 20 { continue; }
                        
                        let mut response = vec![0u8; len];
                        response.copy_from_slice(&pkt);
                        
                        let version = response[0] >> 4;
                        
                        match version {
                            4 => {
                                if let Ok(mut ip) = Ipv4Packet::new_checked(&mut response) {
                                    let src = ip.src_addr();
                                    let dst = ip.dst_addr();
                                    ip.set_src_addr(dst);
                                    ip.set_dst_addr(src);
                                    
                                    let proto = ip.next_header();
                                    let payload = ip.payload_mut();
                                    
                                    if proto == IpProtocol::Udp {
                                        if let Ok(mut udp) = UdpPacket::new_checked(payload) {
                                            let src_port = udp.src_port();
                                            let dst_port = udp.dst_port();
                                            udp.set_src_port(dst_port);
                                            udp.set_dst_port(src_port);
                                            // Critical: Recalculate UDP checksum with pseudo-header
                                            udp.fill_checksum(
                                                &src.into(),
                                                &dst.into()
                                            );
                                            println!("   -> UDP Echo: Swapped ports {} <-> {}, New Cksum Generated.", src_port, dst_port);
                                        }
                                    } else if proto == IpProtocol::Icmp {
                                         if let Ok(mut icmp) = Icmpv4Packet::new_checked(payload) {
                                             // Echo Request (8) -> Echo Reply (0)
                                             if icmp.msg_type() == smoltcp::wire::Icmpv4Message::EchoRequest {
                                                 icmp.set_msg_type(smoltcp::wire::Icmpv4Message::EchoReply);
                                                 // ICMPv4 Checksum calculation
                                                 icmp.fill_checksum();
                                             }
                                         }
                                    }
                                    
                                    // Recompute IP Checksum
                                    ip.fill_checksum();
                                }
                            },
                            6 => {
                                if let Ok(mut ip) = Ipv6Packet::new_checked(&mut response) {
                                    let src = ip.src_addr();
                                    let dst = ip.dst_addr();
                                    ip.set_src_addr(dst);
                                    ip.set_dst_addr(src);
                                    
                                    let proto = ip.next_header();
                                    let payload = ip.payload_mut();
                                    
                                    if proto == IpProtocol::Udp {
                                        if let Ok(mut udp) = UdpPacket::new_checked(payload) {
                                            let src_port = udp.src_port();
                                            let dst_port = udp.dst_port();
                                            udp.set_src_port(dst_port);
                                            udp.set_dst_port(src_port);
                                             udp.fill_checksum(
                                                &src.into(),
                                                &dst.into()
                                            );
                                        }
                                    } else if proto == IpProtocol::Icmpv6 {
                                         // Note: imports need Icmpv6Packet
                                         if let Ok(mut icmp) = smoltcp::wire::Icmpv6Packet::new_checked(payload) {
                                             if icmp.msg_type() == smoltcp::wire::Icmpv6Message::EchoRequest {
                                                 icmp.set_msg_type(smoltcp::wire::Icmpv6Message::EchoReply);
                                                 icmp.fill_checksum(
                                                    &src.into(),
                                                    &dst.into()
                                                 );
                                             }
                                         }
                                    }
                                }
                            }
                            _ => {}
                        }
                        
                        // Send back to TUN (Echo)
                        let _ = tun_tx.send(Bytes::from(response)).await;
                    }
                    None => break,
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n🛑 Shutting down...");
                break;
            }
        }
    }

    Ok(())
}
