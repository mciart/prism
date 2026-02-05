use smoltcp::iface::{Config, Interface, SocketSet, SocketHandle};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv6Address, HardwareAddress, EthernetAddress};
use tokio::time::{self, Duration};
use tokio::sync::{mpsc, oneshot};
use rand::Rng;
use crate::device::PrismDevice;
use crate::trap::PrismTrap;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, warn, error};
use smoltcp::phy::Device;
use bytes::Bytes;
use futures::stream::{StreamExt, SelectAll, BoxStream};
use tokio_stream::wrappers::ReceiverStream;

/// Configuration for the Prism Stack.
#[derive(Debug, Clone)]
pub struct PrismConfig {
    pub handshake_mode: HandshakeMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMode {
    Fast,
    Consistent,
}

/// Request to create a tunnel to a remote target.
pub struct TunnelRequest {
    pub target: SocketAddr,
    /// Channel to write data TO the remote tunnel (PrismStack -> TLS)
    pub tx: mpsc::Sender<Bytes>,
    /// Channel to read data FROM the remote tunnel (TLS -> PrismStack)
    pub rx: mpsc::Receiver<Bytes>,
    /// Optional feedback channel for Consistent Handshake.
    pub response_tx: Option<oneshot::Sender<bool>>,
}

/// The virtual network stack structure.
pub struct PrismStack {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    // Removed trap_rx channel, we handle it directly in loop
    
    /// Control channel to request new tunnels from the Relayer
    pub tunnel_req_tx: Option<mpsc::Sender<TunnelRequest>>,
    
    /// Blind Relay channel for non-TCP packets (UDP, ICMP, etc.)
    pub blind_relay_tx: Option<mpsc::Sender<Bytes>>,
    
    /// Map of active sockets to their EGRESS data channels
    /// Key: SocketHandle, Value: tx_to_remote
    /// RX is handled via ingress_streams
    pub active_tunnels: HashMap<SocketHandle, mpsc::Sender<Bytes>>,
    
    /// Aggregated stream of incoming data from all active tunnels
    /// Yields: (SocketHandle, Data)
    pub ingress_streams: SelectAll<BoxStream<'static, (SocketHandle, Bytes)>>,

    /// The PHY device
    pub device: PrismDevice,
    /// Stack configuration
    pub config: PrismConfig,
    /// Pending SYNs waiting for tunnel confirmation (Consistent Mode)
    pub pending_syns: HashMap<SocketAddr, (PrismTrap, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)>,
    /// Internal feedback channel to receive signals from the async bridge tasks
    pub feedback_tx: mpsc::Sender<(SocketAddr, bool)>,
    pub feedback_rx: mpsc::Receiver<(SocketAddr, bool)>,
}

impl PrismStack {
    /// Creates a new PrismStack instance with the given Device.
    pub fn new(mut device: PrismDevice, config: PrismConfig) -> Self {
        let medium = device.capabilities().medium;
        let hardware_addr = match medium {
            smoltcp::phy::Medium::Ethernet => {
                let mut bytes = [0u8; 6];
                rand::thread_rng().fill(&mut bytes);
                bytes[0] &= 0xfe; // Unicast
                bytes[0] |= 0x02; // Local
                HardwareAddress::Ethernet(EthernetAddress(bytes))
            }
            smoltcp::phy::Medium::Ip => HardwareAddress::Ip,
            _ => panic!("Unsupported medium"),
        };

        let mut iface_config = Config::new(hardware_addr);
        iface_config.random_seed = rand::random::<u64>();

        // Removed trap channel creation - no longer needed in Device

        let mut iface = Interface::new(iface_config, &mut device, Instant::now());

        // Configure IP addresses (virtual gateway IP)
        // We generally pick a link-local or private IP that won't conflict
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(IpAddress::v4(10, 11, 12, 1), 24)).unwrap();
            // Add IPv6 ULA (Unique Local Address) for virtual gateway
            ip_addrs.push(IpCidr::new(IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64)).unwrap();
        });

        // Configure default route to sink all traffic
        // NOTE: add_default_ipv4_route requires Ipv4Address, not IpAddress enum
        iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 11, 12, 1)).unwrap();
        iface.routes_mut().add_default_ipv6_route(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)).unwrap();

        let sockets = SocketSet::new(vec![]);
        let (feedback_tx, feedback_rx) = mpsc::channel(128);

        Self {
            iface,
            sockets,
            tunnel_req_tx: None,
            blind_relay_tx: None,
            active_tunnels: HashMap::new(),
            ingress_streams: SelectAll::new(),
            device,
            config,
            pending_syns: HashMap::new(),
            feedback_tx,
            feedback_rx,
        }
    }

    pub fn set_tunnel_request_sender(&mut self, tx: mpsc::Sender<TunnelRequest>) {
        self.tunnel_req_tx = Some(tx);
    }
    
    pub fn set_blind_relay_sender(&mut self, tx: mpsc::Sender<Bytes>) {
        self.blind_relay_tx = Some(tx);
    }

    /// Runs the virtual stack poll loop (Event-Driven).
    pub async fn run(mut self) -> anyhow::Result<()> {
        debug!("Prism Stack started (Event-Driven Mode).");

        // Buffer size tuning for 1Gbps+ throughput (2MB+)
        const TCP_RX_BUFFER_SIZE: usize = 2 * 1024 * 1024;
        const TCP_TX_BUFFER_SIZE: usize = 2 * 1024 * 1024;

        loop {
            let now = Instant::now();
            
            // 1. Calculate Poll Delay
            // smoltcp tells us when it needs to be called next (e.g. retransmit timer)
            let poll_delay = self.iface.poll_delay(now, &self.sockets).map(|d| Duration::from(d));
            
            // 2. Select on Events
            tokio::select! {
                // Event A: Network Packet from TUN
                // We pull directly from device.rx_queue because device.receive() is now passive/dumb
                // BATCHING: Try to consume up to 64 packets per wake-up to reduce context switching
                res = self.device.rx_queue.recv() => {
                    if let Some(pkt) = res {
                        let mut count = 0;
                        let mut current_pkt = Some(pkt);
                        
                        while let Some(pkt) = current_pkt {
                            // PROTOCOL CLASSIFICATION
                            // We only intercept TCP. Everything else goes to Blind Relay.
                            let pkt_type = if matches!(self.device.medium, smoltcp::phy::Medium::Ip) {
                                crate::trap::get_packet_type(&pkt)
                            } else {
                                // L2 Frames: For now treat as "Unknown/Other" -> Blind Relay if we wanted L2 bridge
                                // But smoltcp stack expects IP.
                                // Let's just pass to stack if we are unsure, or drop?
                                // For now, pass to stack so it might answer ARP?
                                // Actually, ARP is L2, so get_packet_type might return Unknown.
                                crate::trap::PacketType::Unknown
                            };

                            match pkt_type {
                                crate::trap::PacketType::Tcp => {
                                    // TCP: Check for SYN Trap
                                    if let Some(event) = crate::trap::inspect_packet(&pkt) {
                                        self.handle_trap(event, pkt, TCP_RX_BUFFER_SIZE, TCP_TX_BUFFER_SIZE);
                                    } else {
                                        // TCP Data/ACK -> Stack
                                        self.device.pending_packets.push_back(pkt);
                                    }
                                }
                                crate::trap::PacketType::Other => {
                                    // UDP/ICMP/Gre etc. -> Blind Relay
                                    if let Some(ref relay) = self.blind_relay_tx {
                                        // Fire and forget, don't block main loop
                                        let _ = relay.try_send(pkt);
                                    } else {
                                        // If no relay configured, drop or let stack reject it (ICMP Unreachable)
                                        // Letting stack see it might generate "Port Unreachable", which is good.
                                        self.device.pending_packets.push_back(pkt);
                                    }
                                }
                                crate::trap::PacketType::Unknown => {
                                     // Debug log to catch IPv6 parsing failures
                                     if pkt.len() > 0 {
                                         let ver = pkt[0] >> 4;
                                         if ver == 6 {
                                             tracing::warn!("IPv6 Packet failed classification! Len: {}", pkt.len());
                                         }
                                     }
                                     self.device.pending_packets.push_back(pkt);
                                }
                            }
                            
                            count += 1;
                            if count >= 64 { break; }
                            
                            // Try get next without waiting
                            match self.device.rx_queue.try_recv() {
                                Ok(p) => current_pkt = Some(p),
                                Err(_) => current_pkt = None,
                            }
                        }
                    } else {
                        debug!("Network Interface Closed.");
                        break;
                    }
                },

                // Event B: Data from Active Tunnels (Fan-in)
                Some((handle, data)) = self.ingress_streams.next() => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    if true { // Simplified scope block for consistency
                        if socket.can_send() {
                            // Write to socket TX buffer (Simulated RX from network perspective)
                            // Wait, socket.send_slice() writes to the socket's TX buffer?
                            // No! socket.send_slice() writes data that the socket will SEND to the network (to Client).
                            // Here 'data' comes FROM network (Tunnel/Remote) intended FOR Client.
                            // So we should write to socket's "send buffer".
                            // smoltcp `socket.send_slice` queues data to be sent over TCP.
                            // Yes.
                            let sent = socket.send_slice(&data).unwrap_or(0);
                            if sent < data.len() {
                                warn!("Socket buffer full (Handle {:?}), dropped {} bytes", handle, data.len() - sent);
                            }
                        }
                    } // End if true block
                },

                // Event C: Feedback from Consistent Handshake
                Some((target, success)) = self.feedback_rx.recv() => {
                     self.handle_handshake_feedback(target, success, TCP_RX_BUFFER_SIZE, TCP_TX_BUFFER_SIZE);
                },

                // Event D: Timer Expiry
                // If poll_delay is None, we wait forever (for IO)
                // If poll_delay is Some, we sleep until then
                _ = async {
                    if let Some(d) = poll_delay {
                        time::sleep(d).await;
                    } else {
                        // If no delay, wait forever (future never completes, but select! waits for others)
                        std::future::pending::<()>().await;
                    }
                } => {}
            }

            // 3. Poll smoltcp (Process packets, timers, state updates)
            // This consumes packets from pending_packets
            let poll_now = Instant::now();
            self.iface.poll(poll_now, &mut self.device, &mut self.sockets);

            // 4. Data Pumping (Egress: Socket -> Tunnel)
            // Iterate sockets to see if they have data for us
            let mut sockets_to_remove = Vec::new();
            
            for (handle, tx_to_remote) in self.active_tunnels.iter_mut() {
                let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

                // Check for closure
                if socket.state() == tcp::State::Closed || socket.state() == tcp::State::TimeWait {
                    // We can remove it
                    // But wait, if TimeWait, maybe we still need to send ACKs?
                    // socket.recv() reads payload data (from Client).
                    // If Closed, no more data from Client.
                    sockets_to_remove.push(*handle);
                    continue;
                }

                if !socket.can_recv() {
                     continue;
                }

                // Ingress (Socket -> Tunnel) (Data FROM Client TO Remote)
                while let Ok(data) = socket.recv(|buf| (buf.len(), Bytes::copy_from_slice(buf))) {
                    if data.is_empty() { break; }
                     // Optimization: Use try_send to avoid blocking loop
                    if let Err(_) = tx_to_remote.try_send(data) {
                         // Backpressure: drop or break? 
                         // If we break, we leave data in socket buffer (Good).
                        break; 
                    }
                }
            }
            
            for handle in sockets_to_remove {
                self.active_tunnels.remove(&handle);
                self.sockets.remove(handle);
                // Note: The corresponding ingress_stream will naturally end if we drop the socket?
                // No, the stream is driven by the channel from Relayer.
                // If we remove the socket, the stream might still produce data.
                // Our `ingress_streams.next()` check `self.sockets.get_mut` handles this gracefully (if None, ignore).
            }
        }
        
        Ok(())
    }

    // Helper to handle Trap Logic
    fn handle_trap(&mut self, event: crate::trap::TrapEvent, pkt: Bytes, rx_buf_size: usize, tx_buf_size: usize) {
        debug!("Trapped SYN for target: {}", event.dst);
        
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; rx_buf_size]),
            tcp::SocketBuffer::new(vec![0; tx_buf_size])
        );
        socket.set_keep_alive(Some(Duration::from_secs(60).into()));

         // Register IP to Interface
        match event.dst {
            std::net::SocketAddr::V4(addr) => {
                let endpoint_ip = Ipv4Address::from_bytes(&addr.ip().octets());
                self.iface.update_ip_addrs(|ip_addrs| {
                    let cidr = IpCidr::new(IpAddress::Ipv4(endpoint_ip), 32);
                    if !ip_addrs.contains(&cidr) {
                         let _ = ip_addrs.push(cidr);
                    }
                });
                
                if self.config.handshake_mode == HandshakeMode::Consistent {
                    self.initiate_consistent_handshake(event, pkt);
                } else {
                    self.initiate_fast_handshake(event, pkt, socket);
                }
            },
            std::net::SocketAddr::V6(addr) => {
                 debug!("handle_trap: Handling IPv6 target: {}", addr);
                 let endpoint_ip = Ipv6Address::from_bytes(&addr.ip().octets());
                 self.iface.update_ip_addrs(|ip_addrs| {
                    let cidr = IpCidr::new(IpAddress::Ipv6(endpoint_ip), 128);
                    if !ip_addrs.contains(&cidr) {
                         debug!("handle_trap: Registering new IPv6 addr: {}", cidr);
                         let _ = ip_addrs.push(cidr);
                    }
                });
                
                if self.config.handshake_mode == HandshakeMode::Consistent {
                    self.initiate_consistent_handshake(event, pkt);
                } else {
                    debug!("handle_trap: Intiating Fast Handshake for IPv6");
                    self.initiate_fast_handshake(event, pkt, socket);
                }
            }
        }
    }

    fn initiate_consistent_handshake(&mut self, event: crate::trap::TrapEvent, pkt: Bytes) {
        debug!("Consistent Handshake: Buffering SYN for {}", event.dst);
        
        if let Some(ref req_tx) = self.tunnel_req_tx {
            let (tx_to_remote, rx_from_internal) = mpsc::channel::<Bytes>(1024);
            let (tx_to_internal, rx_from_remote) = mpsc::channel::<Bytes>(1024);
            let (resp_tx, resp_rx) = oneshot::channel();

            let request = TunnelRequest {
                target: event.dst,
                tx: tx_to_internal,
                rx: rx_from_internal,
                response_tx: Some(resp_tx),
            };

            if let Err(e) = req_tx.try_send(request) {
                error!("Failed to request tunnel (Consistent): {}", e);
            } else {
                 let trap = PrismTrap { dst: event.dst, packet: pkt };
                 // Store pending
                 self.pending_syns.insert(event.dst, (trap, tx_to_remote, rx_from_remote));
                 
                 // Spawn wait task
                 let feedback_tx = self.feedback_tx.clone();
                 let target = event.dst;
                 tokio::spawn(async move {
                      let success = resp_rx.await.unwrap_or(false);
                      let _ = feedback_tx.send((target, success)).await;
                 });
            }
        }
    }

    fn initiate_fast_handshake(&mut self, event: crate::trap::TrapEvent, pkt: Bytes, mut socket: tcp::Socket<'static>) {
    // Unconditional handling - smoltcp IpEndpoint handles both V4/V6 via IpAddress enum
    // But we need to convert std::net::SocketAddr to smoltcp::wire::IpEndpoint
    let endpoint = match event.dst {
        std::net::SocketAddr::V4(addr) => smoltcp::wire::IpEndpoint::new(
             smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&addr.ip().octets())),
             addr.port(),
        ),
        std::net::SocketAddr::V6(addr) => smoltcp::wire::IpEndpoint::new(
             smoltcp::wire::IpAddress::Ipv6(Ipv6Address::from_bytes(&addr.ip().octets())),
             addr.port(),
        ),
    };

    if let Err(e) = socket.listen(endpoint) {
        warn!("Failed to listen: {}", e);
        return;
    }
    
    let handle = self.sockets.add(socket);
    self.device.pending_packets.push_back(pkt); // Re-inject SYN

    if let Some(ref req_tx) = self.tunnel_req_tx {
        let (tx_to_remote, rx_from_internal) = mpsc::channel::<Bytes>(1024);
        let (tx_to_internal, rx_from_remote) = mpsc::channel::<Bytes>(1024);
        
        let request = TunnelRequest {
            target: event.dst,
            tx: tx_to_internal,
            rx: rx_from_internal,
            response_tx: None,
        };

        if let Err(_) = req_tx.try_send(request) {
            self.sockets.remove(handle);
        } else {
            // Add to active tunnels
            self.active_tunnels.insert(handle, tx_to_remote);
            // Add RX stream to SelectAll (Fan-in)
            self.ingress_streams.push(
                ReceiverStream::new(rx_from_remote).map(move |b| (handle, b)).boxed()
            );
        }
    }
}

    fn handle_handshake_feedback(&mut self, target: SocketAddr, success: bool, rx_buf: usize, tx_buf: usize) {
        if let Some((trap, tx_to_remote, rx_from_remote)) = self.pending_syns.remove(&target) {
            if success {
                debug!("Tunnel ready for {}. Releasing SYN.", target);
                // Re-create socket logic similar to Fast Mode
                 let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; rx_buf]),
                    tcp::SocketBuffer::new(vec![0; tx_buf])
                );
                socket.set_keep_alive(Some(Duration::from_secs(60).into()));
                
                let endpoint = match target {
                    std::net::SocketAddr::V4(addr) => smoltcp::wire::IpEndpoint::new(
                         smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&addr.ip().octets())),
                         addr.port(),
                    ),
                    std::net::SocketAddr::V6(addr) => smoltcp::wire::IpEndpoint::new(
                         smoltcp::wire::IpAddress::Ipv6(Ipv6Address::from_bytes(&addr.ip().octets())),
                         addr.port(),
                    ),
                };

                if let Ok(_) = socket.listen(endpoint) {
                    let handle = self.sockets.add(socket);
                    self.active_tunnels.insert(handle, tx_to_remote);
                    self.ingress_streams.push(
                        ReceiverStream::new(rx_from_remote).map(move |b| (handle, b)).boxed()
                    );
                    self.device.pending_packets.push_back(trap.packet);
                }
            } else {
                warn!("Tunnel failed for {}. Dropping SYN.", target);
            }
        }
    }
}
