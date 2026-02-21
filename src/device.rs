use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;
use crate::trap::PrismTrap;
use crate::constants::{TX_POOL_CAPACITY, TX_POOL_MAX_SIZE, TX_POOL_RECYCLE_THRESHOLD, TX_ARENA_SIZE};
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
    // Simple Object Pool for TX buffers
    // We use Vec<BytesMut> as a stack.
    // Ideally we would use crossbeam::SegQueue or deadpool for lock-free, but Mutex is fine for now as it's single-threaded context mostly.
    // Actually, PrismDevice is accessed via &mut, so we don't even need Arc<Mutex> if we own it?
    // But TxToken needs to access it. TxToken holds &'a mut PrismDevice.
    pub tx_pool: Vec<BytesMut>, 
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
            tx_pool: Vec::with_capacity(TX_POOL_CAPACITY),
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
        // Optimization: Arena Allocation (Slab-like)
        // 1. Try get from pool
        let mut buffer = self.0.tx_pool.pop().unwrap_or_else(|| {
             BytesMut::with_capacity(TX_ARENA_SIZE)
        });

        // 2. Ensure capacity
        // If the popped buffer is too small (shouldn't happen with our logic, but safe guard)
        if buffer.capacity() < len {
             buffer = BytesMut::with_capacity(TX_ARENA_SIZE);
        }
        
        // 3. Set length safely (avoid memset)
        // We set length to `len` so `f` can write into it.
        // Safety: `f` (smoltcp) will initialize it.
        unsafe { buffer.set_len(len) };
        
        // 4. Write data
        let result = f(&mut buffer);
        
        // 5. Zero-Copy Send via Splitting
        // `split_to(len)` returns a new BytesMut containing [0, len)
        // `buffer` retains [len, capacity) - effectively the "rest" of the allocation
        let packet = buffer.split_to(len).freeze();
        
        // 6. Recycle remaining capacity
        // Recycle if has enough space AND pool isn't full (prevent OOM)
        if buffer.capacity() > TX_POOL_RECYCLE_THRESHOLD && self.0.tx_pool.len() < TX_POOL_MAX_SIZE {
             self.0.tx_pool.push(buffer);
        }
        
        if let Err(e) = self.0.tx_queue.try_send(packet) {
             warn!("TX Queue Full/Closed: {}", e);
        }
        
        result
    }
}
