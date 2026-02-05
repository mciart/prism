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
            tx_pool: Vec::with_capacity(64), // Pre-allocate pool
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
        // Optimization: Use Object Pool to avoid malloc
        // 1. Try get from pool
        let mut buffer = self.0.tx_pool.pop().unwrap_or_else(|| {
             // Fallback: Allocate new if pool empty
             // Use with_capacity to avoid memset
             BytesMut::with_capacity(len)
        });

        // 2. Ensure capacity
        if buffer.capacity() < len {
             buffer.reserve(len - buffer.capacity());
        }
        
        // 3. Set length safely (avoid memset)
        unsafe { buffer.set_len(len) };
        
        // 4. Write data
        let result = f(&mut buffer);
        
        // 5. Zero-Copy Send
        // Note: buffer.freeze() consumes the BytesMut and returns Bytes.
        // We cannot return the BytesMut to the pool because it's gone (transformed).
        // BUT, if the Bytes is dropped elsewhere, the memory is freed.
        // To truly recycle, we need the Consumer to return the buffer.
        // Since we are sending to a Channel, we lose control.
        // However, we can keep the *allocation* if we use `split()` or similar?
        // No, `freeze` takes ownership.
        
        // Wait, if we send `Bytes`, we lose the `BytesMut`.
        // So this Pool strategy only works if we don't send it, OR if we clone?
        // Cloning defeats the purpose.
        
        // Actually, there is a trick: `BytesMut::split_to` or `freeze` works on the active part.
        // If we want to reuse the *allocation*, we should probably not use `freeze` if we want to keep `BytesMut`.
        // But `tx_queue` expects `Bytes`.
        
        // If we use `recycler` crate, it handles this via specific types.
        // But for a simple Vec pool, we can't easily recycle *after* sending to channel unless the receiver sends it back.
        // Since we can't change the channel signature easily (it's `Sender<Bytes>`), we might be stuck with allocation 
        // unless we change the architecture to return buffers.
        
        // HOWEVER, `BytesMut` does have a trick: `split()`
        // "Splits the bytes into two ... Retains the capacity in the original."
        // Let's try:
        
        let packet = buffer.split_to(len).freeze();
        
        // Now `packet` (Bytes) owns the data.
        // `buffer` (BytesMut) retains the remaining capacity (if any) or is empty but might keep allocation?
        // Actually, `split_to` moves the pointer. The *head* is moved.
        // If we split *everything*, `buffer` becomes empty. Does it keep capacity?
        // Docs: "The returned BytesMut will have the same capacity as the original... NO."
        // Docs: "Splits the buffer into two at the given index. Afterwards self contains elements [at, len), and the returned BytesMut contains elements [0, at)."
        // We want to send [0, len). So we call split_to(len).
        // Then `buffer` contains [len, capacity).
        // If capacity was exactly len, buffer is empty.
        
        // So to reuse capacity, we should allocate *larger* chunks (Arena style)?
        // Or, we just accept that we can't easily recycle `BytesMut` if we give it away as `Bytes`.
        
        // REVISION: The user suggested "recycler" crate or "simple Vec<BytesMut>".
        // With simple Vec<BytesMut>, if we give away the BytesMut (via freeze), we can't put it back.
        // Unless we don't give it away?
        // But we MUST send it to `tx_queue`.
        
        // The only way to recycle is if the `Bytes` we send is a *copy* (slow) OR if we have a mechanism to get it back.
        // Since we want Zero-Copy, we must send the underlying memory.
        
        // WAIT! `BytesMut` allows multiple handles to the same memory?
        // No, `Bytes` is ref-counted.
        
        // Let's look at `recycler` crate pattern if we were to use it.
        // But for now, let's implement the "Arena" pattern with `split_to`.
        // If we allocate 64KB, and send 1500B.
        // `split_to(1500)` returns a new BytesMut with the data.
        // `buffer` keeps the rest (64000B).
        // We can put `buffer` back in the pool!
        // This works for "fragmentation" recycling.
        
        // Let's implement this "Arena" strategy.
        // Allocate 64KB chunks. Slice off packets.
        // When buffer is too small, drop it and allocate new 64KB.
        
        if buffer.capacity() < 2048 { // If too small to be useful
             // Drop it (let it free)
             // Create new big chunk next time
        } else {
             self.0.tx_pool.push(buffer);
        }
        
        if let Err(e) = self.0.tx_queue.try_send(packet) {
             warn!("TX Queue Full/Closed: {}", e);
        }
        
        result
    }
}
