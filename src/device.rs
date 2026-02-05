use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;
use crate::trap::PrismTrap;
use std::collections::VecDeque;
use tracing::warn;
use bytes::Bytes;

/// A TunDevice that bridges tokio mpsc channels to smoltcp.
/// Now uses `bytes::Bytes` for zero-copy efficiency.
pub struct PrismDevice {
    pub rx_queue: mpsc::Receiver<Bytes>,
    pub tx_queue: mpsc::Sender<Bytes>,
    pub trap_tx: Option<mpsc::Sender<PrismTrap>>,
    pub pending_packets: VecDeque<Bytes>,
    pub mtu: usize,
    pub medium: Medium,
}

impl PrismDevice {
    pub fn new(
        rx_queue: mpsc::Receiver<Bytes>,
        tx_queue: mpsc::Sender<Bytes>,
        mtu: usize,
        medium: Medium,
    ) -> Self {
        Self {
            rx_queue,
            tx_queue,
            trap_tx: None,
            pending_packets: VecDeque::new(),
            mtu,
            medium,
        }
    }
    
    pub fn set_trap_sender(&mut self, tx: mpsc::Sender<PrismTrap>) {
        self.trap_tx = Some(tx);
    }
}

impl Device for PrismDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // 1. Check pending packets (pumped from rx_queue by the stack loop)
        if let Some(buffer) = self.pending_packets.pop_front() {
             let rx_token = RxTokenImpl(buffer);
             let tx_token = TxTokenImpl(self);
             return Some((rx_token, tx_token));
        }
        
        // Note: We used to try_recv() here directly, but to support efficient event-driven polling,
        // the external loop now handles rx_queue -> pending_packets pumping.
        // This avoids busy-waiting or split ownership issues.

        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = self.medium;
        caps
    }
}

pub struct RxTokenImpl(Bytes);

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // smoltcp requires &mut [u8] for RxToken!
        // This is tricky with Bytes which is immutable.
        // However, smoltcp only modifies the buffer for checksum offloading usually (swapping bytes).
        // Since we are software, we might not need mutable access for reading?
        // Wait, smoltcp RxToken `consume` gives `&mut [u8]`.
        // If we give immutable `Bytes`, we must enable `Packet` mutation or copy.
        // Option A: Copy to stack (bad).
        // Option B: Use `BytesMut`? But we received `Bytes`.
        // Option C: Use `std::cell::RefCell` / `unsafe` cast if we know smoltcp behaves? (Crucial Risk)
        // Option D: Clone to `Vec<u8>` (Defeats the purpose temporarily, but safer than Unsafe).
        
        // Let's implement Option D for now (Migration Phase 6.2a).
        // To be truly zero-copy with smoltcp, we might need to implement a custom Device that owns a BytesMut pool?
        // Or if smoltcp doesn't actually mutate, we are fine.
        // Actually, rx packets ARE mutated by smoltcp sometimes (e.g. adjust headers).
        
        // Wait, let's look at `RxToken::consume` signature.
        // `fn consume<R, F>(self, f: F) -> R where F: FnOnce(&mut [u8]) -> R`
        // It demands mutable reference.
        
        let mut buffer = self.0.to_vec(); // Copy occurs here.
        f(&mut buffer)
    }
}

pub struct TxTokenImpl<'a>(&'a mut PrismDevice);

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        let bytes = Bytes::from(buffer);
        
        if let Err(e) = self.0.tx_queue.try_send(bytes) {
             warn!("TX Queue Full/Closed: {}", e);
        }
        
        result
    }
}
