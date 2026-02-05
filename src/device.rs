use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;
use crate::trap::PrismTrap;
use std::collections::VecDeque;
use tracing::warn;
use bytes::{Bytes, BytesMut};

/// A TunDevice that bridges tokio mpsc channels to smoltcp.
/// Now uses `bytes::BytesMut` for zero-copy efficiency.
pub struct PrismDevice {
    pub rx_queue: mpsc::Receiver<BytesMut>,
    pub tx_queue: mpsc::Sender<Bytes>,
    pub trap_tx: Option<mpsc::Sender<PrismTrap>>,
    pub pending_packets: VecDeque<BytesMut>,
    pub mtu: usize,
    pub medium: Medium,
}

impl PrismDevice {
    pub fn new(
        rx_queue: mpsc::Receiver<BytesMut>,
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

pub struct RxTokenImpl(BytesMut);

impl RxToken for RxTokenImpl {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // smoltcp requires &mut [u8] for RxToken!
        // With BytesMut, we can provide mutable access directly without copying.
        f(&mut self.0)
    }
}

pub struct TxTokenImpl<'a>(&'a mut PrismDevice);

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Optimization: Use BytesMut to avoid Vec allocation (malloc)
        // We use zeroed() to ensure safety (initialized memory), although it has slight overhead.
        // This allows us to freeze() into Bytes without copying.
        let mut buffer = BytesMut::zeroed(len);
        let result = f(&mut buffer);
        let bytes = buffer.freeze();
        
        if let Err(e) = self.0.tx_queue.try_send(bytes) {
             warn!("TX Queue Full/Closed: {}", e);
        }
        
        result
    }
}
