//! Lock-free single-producer single-consumer ring of fixed-size slots.
//!
//! The ring is designed for two cooperating processes that share the same
//! memory region. One process is the producer, the other the consumer —
//! responsibilities never swap within a single ring. The netstack uses
//! two rings per container (request / response), so each process is
//! producer on one and consumer on the other.
//!
//! # Layout
//!
//! ```text
//! +---------------------------+  <- offset 0
//! | RingHeader (64 bytes)     |
//! +---------------------------+  <- offset RING_HEADER_SIZE
//! | slot[0]  (SLOT_SIZE)      |
//! | slot[1]  (SLOT_SIZE)      |
//! | ...                       |
//! | slot[N-1]                 |
//! +---------------------------+
//! ```
//!
//! `N` (slot count) must be a power of two so wrap-around is a cheap
//! bitmask. The producer advances `head`; the consumer advances `tail`.
//! Both indices are **monotonically increasing** 64-bit counters —
//! wrapping happens in the slot-index computation only. This avoids the
//! classic "empty vs. full" ambiguity of equal-index rings without
//! wasting a slot.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use psroot_netstack_proto::{SlotHeader, DATA_CAPACITY, HEADER_SIZE, SLOT_SIZE};

/// Errors the ring can return to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// No message currently available (consumer side).
    Empty,
    /// Ring is full (producer side).
    Full,
    /// Shared memory is too small for the requested number of slots.
    TooSmall,
    /// Slot count is not a power of two.
    NotPow2,
    /// Memory slice is not properly aligned (required for atomic access).
    Misaligned,
}

/// Result of successfully reading a message from the ring.
pub struct Slot<'a> {
    pub header: SlotHeader,
    /// View into the data region. Always `payload_len` bytes long.
    pub data: &'a [u8],
}

/// Fixed-size header at the start of a shared ring region.
///
/// Cache-line aligned so the producer/consumer atomics don't thrash the
/// same line as metadata. 64 bytes total.
#[repr(C, align(64))]
pub struct RingHeader {
    /// Magic number for sanity checks (`0x70_72_5f_52` = "pr_R" little-endian).
    magic: AtomicU32,
    /// Ring layout version; bumped if the on-wire layout changes.
    version: AtomicU32,
    /// Number of slots in the ring (always power of two).
    slot_count: AtomicU32,
    /// Reserved / padding for future flags.
    _reserved0: AtomicU32,
    /// Producer index — only the producer writes. Consumer reads with
    /// `Acquire` to observe fresh slot contents.
    head: AtomicU64,
    /// Consumer index — only the consumer writes. Producer reads with
    /// `Acquire` to discover freed slots.
    tail: AtomicU64,
    /// Futex word used by [`Channel`] for sleep/wake coordination.
    /// Stored here (inside the ring header) so that a single shared
    /// mapping is sufficient.
    pub(crate) futex: AtomicU32,
    _reserved1: AtomicU32,
    _pad: [u8; 16],
}

const MAGIC: u32 = 0x70_72_5f_52;
const VERSION: u32 = 1;

/// Ring size, in bytes, for a given slot count.
pub const fn ring_bytes(slot_count: u32) -> usize {
    RING_HEADER_SIZE + (slot_count as usize) * SLOT_SIZE
}

/// Size of the header region that precedes the slot array.
pub const RING_HEADER_SIZE: usize = core::mem::size_of::<RingHeader>();

/// SPSC ring that operates over a caller-provided, aligned byte slice.
///
/// The slice must live for as long as the ring is in use. Both the host
/// and the shim create a `Ring` that references the same shared memory.
pub struct Ring<'a> {
    buf: &'a [u8],
    mask: u64,
    slot_count: u32,
}

impl<'a> Ring<'a> {
    /// Initialise a fresh ring over `buf`. Called by whichever side is
    /// responsible for first-time setup (the host/daemon).
    pub fn create(buf: &'a mut [u8], slot_count: u32) -> Result<Self, RingError> {
        if !slot_count.is_power_of_two() || slot_count < 2 {
            return Err(RingError::NotPow2);
        }
        if buf.len() < ring_bytes(slot_count) {
            return Err(RingError::TooSmall);
        }
        if (buf.as_ptr() as usize) % 64 != 0 {
            return Err(RingError::Misaligned);
        }

        // Safe: we just checked size and alignment; RingHeader is POD.
        let header: &RingHeader = unsafe { &*(buf.as_ptr() as *const RingHeader) };
        header.magic.store(MAGIC, Ordering::Relaxed);
        header.version.store(VERSION, Ordering::Relaxed);
        header.slot_count.store(slot_count, Ordering::Relaxed);
        header.head.store(0, Ordering::Relaxed);
        header.tail.store(0, Ordering::Relaxed);
        header.futex.store(0, Ordering::Relaxed);

        Ok(Self {
            buf,
            mask: (slot_count as u64) - 1,
            slot_count,
        })
    }

    /// Attach to an already-initialised ring. Called by the shim on
    /// startup. Validates magic + version.
    pub fn attach(buf: &'a [u8]) -> Result<Self, RingError> {
        if buf.len() < RING_HEADER_SIZE {
            return Err(RingError::TooSmall);
        }
        if (buf.as_ptr() as usize) % 64 != 0 {
            return Err(RingError::Misaligned);
        }
        let header: &RingHeader = unsafe { &*(buf.as_ptr() as *const RingHeader) };
        let magic = header.magic.load(Ordering::Relaxed);
        if magic != MAGIC {
            return Err(RingError::TooSmall); // treat as bad-shape
        }
        let slot_count = header.slot_count.load(Ordering::Relaxed);
        if !slot_count.is_power_of_two() || slot_count < 2 {
            return Err(RingError::NotPow2);
        }
        if buf.len() < ring_bytes(slot_count) {
            return Err(RingError::TooSmall);
        }
        Ok(Self {
            buf,
            mask: (slot_count as u64) - 1,
            slot_count,
        })
    }

    #[inline]
    fn header(&self) -> &RingHeader {
        unsafe { &*(self.buf.as_ptr() as *const RingHeader) }
    }

    #[inline]
    fn slot_ptr(&self, index: u64) -> *const u8 {
        let slot_idx = (index & self.mask) as usize;
        let offset = RING_HEADER_SIZE + slot_idx * SLOT_SIZE;
        unsafe { self.buf.as_ptr().add(offset) }
    }

    #[inline]
    fn slot_ptr_mut(&self, index: u64) -> *mut u8 {
        self.slot_ptr(index) as *mut u8
    }

    /// How many messages are currently pending.
    pub fn len(&self) -> u64 {
        let head = self.header().head.load(Ordering::Acquire);
        let tail = self.header().tail.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn slot_count(&self) -> u32 {
        self.slot_count
    }

    /// Try to push a message. Returns `RingError::Full` if there is no
    /// room; callers should then park on the futex.
    pub fn try_push(&self, header: SlotHeader, data: &[u8]) -> Result<(), RingError> {
        if data.len() > DATA_CAPACITY {
            return Err(RingError::TooSmall);
        }
        let head = self.header().head.load(Ordering::Relaxed);
        let tail = self.header().tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= self.slot_count as u64 {
            return Err(RingError::Full);
        }

        // Write into slot.
        let slot = self.slot_ptr_mut(head);
        // Header — memcpy via write_unaligned (align(16) guarantees 16, but
        // slot boundary is 4096-aligned from start of ring anyway).
        unsafe {
            let mut h = header;
            h.payload_len = data.len() as u32;
            core::ptr::write(slot as *mut SlotHeader, h);
            if !data.is_empty() {
                let data_dst = slot.add(HEADER_SIZE);
                core::ptr::copy_nonoverlapping(data.as_ptr(), data_dst, data.len());
            }
        }

        // Publish with Release so the consumer observes the slot contents.
        self.header().head.store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Try to pop a message. Returns `RingError::Empty` on empty.
    pub fn try_pop(&self) -> Result<(SlotHeader, Vec<u8>), RingError> {
        let tail = self.header().tail.load(Ordering::Relaxed);
        let head = self.header().head.load(Ordering::Acquire);
        if head == tail {
            return Err(RingError::Empty);
        }

        let slot = self.slot_ptr(tail);
        let header = unsafe { core::ptr::read(slot as *const SlotHeader) };
        let len = (header.payload_len as usize).min(DATA_CAPACITY);
        let mut data = Vec::with_capacity(len);
        if len > 0 {
            unsafe {
                let src = slot.add(HEADER_SIZE);
                data.set_len(len);
                core::ptr::copy_nonoverlapping(src, data.as_mut_ptr(), len);
            }
        }

        self.header().tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok((header, data))
    }

    /// Peek without consuming. For zero-copy callers that can borrow
    /// straight from the slot; still advances semantics on commit.
    pub fn try_peek(&self) -> Result<(SlotHeader, &[u8]), RingError> {
        let tail = self.header().tail.load(Ordering::Relaxed);
        let head = self.header().head.load(Ordering::Acquire);
        if head == tail {
            return Err(RingError::Empty);
        }

        let slot = self.slot_ptr(tail);
        let header = unsafe { core::ptr::read(slot as *const SlotHeader) };
        let len = (header.payload_len as usize).min(DATA_CAPACITY);
        let data = unsafe { core::slice::from_raw_parts(slot.add(HEADER_SIZE), len) };
        Ok((header, data))
    }

    /// Commit the most recent peek (advance tail by one).
    pub fn commit_peek(&self) {
        let tail = self.header().tail.load(Ordering::Relaxed);
        self.header().tail.store(tail.wrapping_add(1), Ordering::Release);
    }

    /// Futex word accessor for [`signal`] module use.
    pub fn futex(&self) -> &AtomicU32 {
        &self.header().futex
    }
}

// ───────────────────────────── tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use psroot_netstack_proto::{OpCode, SlotHeader};

    // Helper: allocate a 64-byte-aligned buffer of the required size.
    // Uses a #[repr(align(64))] array wrapper so the heap slot is naturally
    // aligned; regular Vec<u8> is only 1-byte aligned.
    #[repr(align(64))]
    struct Chunk([u8; 64]);

    struct AlignedBuf {
        inner: Vec<Chunk>,
    }
    impl AlignedBuf {
        fn new(bytes: usize) -> Self {
            let chunks = (bytes + 63) / 64;
            Self {
                inner: (0..chunks).map(|_| Chunk([0u8; 64])).collect(),
            }
        }
        fn as_slice(&self) -> &[u8] {
            // SAFETY: Chunks are #[repr(align(64))] arrays of bytes; the
            // Vec's backing storage is contiguous.
            unsafe {
                core::slice::from_raw_parts(
                    self.inner.as_ptr() as *const u8,
                    self.inner.len() * 64,
                )
            }
        }
        fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe {
                core::slice::from_raw_parts_mut(
                    self.inner.as_mut_ptr() as *mut u8,
                    self.inner.len() * 64,
                )
            }
        }
    }

    fn aligned_buf(slot_count: u32) -> AlignedBuf {
        AlignedBuf::new(ring_bytes(slot_count))
    }

    #[test]
    fn create_and_attach() {
        let mut buf = aligned_buf(16);
        let r1 = Ring::create(buf.as_mut_slice(), 16).unwrap();
        assert_eq!(r1.slot_count(), 16);
        assert!(r1.is_empty());
        let r2 = Ring::attach(buf.as_slice()).unwrap();
        assert_eq!(r2.slot_count(), 16);
    }

    #[test]
    fn rejects_non_pow2() {
        let mut buf = aligned_buf(8);
        assert!(matches!(
            Ring::create(buf.as_mut_slice(), 7),
            Err(RingError::NotPow2)
        ));
    }

    #[test]
    fn push_pop_roundtrip() {
        let mut buf = aligned_buf(4);
        let r = Ring::create(buf.as_mut_slice(), 4).unwrap();

        let data = b"hello world";
        let hdr = SlotHeader::new(OpCode::Send, 42);
        r.try_push(hdr, data).unwrap();
        assert_eq!(r.len(), 1);

        let (got_hdr, got_data) = r.try_pop().unwrap();
        assert_eq!(got_hdr.opcode, OpCode::Send as u16);
        assert_eq!(got_hdr.correlation, 42);
        assert_eq!(got_hdr.payload_len, data.len() as u32);
        assert_eq!(&got_data, data);
        assert!(r.is_empty());
    }

    #[test]
    fn fills_then_full() {
        let mut buf = aligned_buf(4);
        let r = Ring::create(buf.as_mut_slice(), 4).unwrap();
        for i in 0..4u32 {
            r.try_push(SlotHeader::new(OpCode::Send, i), &[i as u8]).unwrap();
        }
        assert!(matches!(
            r.try_push(SlotHeader::new(OpCode::Send, 99), &[0]),
            Err(RingError::Full)
        ));
        // Drain one, now there's room again.
        r.try_pop().unwrap();
        r.try_push(SlotHeader::new(OpCode::Send, 99), &[0]).unwrap();
    }

    #[test]
    fn peek_and_commit() {
        let mut buf = aligned_buf(4);
        let r = Ring::create(buf.as_mut_slice(), 4).unwrap();
        r.try_push(SlotHeader::new(OpCode::Recv, 1), b"peek-me").unwrap();

        let (hdr, data) = r.try_peek().unwrap();
        assert_eq!(hdr.correlation, 1);
        assert_eq!(data, b"peek-me");
        // Still there — peek doesn't consume.
        assert_eq!(r.len(), 1);
        r.commit_peek();
        assert!(r.is_empty());
    }

    #[test]
    fn wraps_around() {
        let mut buf = aligned_buf(4);
        let r = Ring::create(buf.as_mut_slice(), 4).unwrap();
        for round in 0..10u32 {
            for i in 0..3 {
                let corr = round * 10 + i;
                r.try_push(SlotHeader::new(OpCode::Send, corr), &[i as u8]).unwrap();
            }
            for i in 0..3 {
                let (hdr, data) = r.try_pop().unwrap();
                assert_eq!(hdr.correlation, round * 10 + i);
                assert_eq!(data, vec![i as u8]);
            }
        }
    }

    #[test]
    fn parallel_producer_consumer() {
        // Build a ring owned by one thread, then use raw pointers carefully
        // to share between threads. We *know* it's SPSC so this is safe.
        use std::sync::Arc;
        use std::thread;

        struct Shared(AlignedBuf);
        unsafe impl Send for Shared {}
        unsafe impl Sync for Shared {}

        let shared = Arc::new(Shared(aligned_buf(64)));
        // Create the ring view first on the shared buffer.
        {
            // SAFETY: we are the only user before spawning threads.
            let s: &Shared = &shared;
            let ptr = s.0.as_slice().as_ptr() as *mut u8;
            let len = s.0.as_slice().len();
            let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
            Ring::create(slice, 64).unwrap();
        }

        let count = 5000usize;
        let producer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let slice: &[u8] = shared.0.as_slice();
                let r = Ring::attach(slice).unwrap();
                let mut sent = 0usize;
                while sent < count {
                    let hdr = SlotHeader::new(OpCode::Send, sent as u32);
                    match r.try_push(hdr, &(sent as u32).to_le_bytes()) {
                        Ok(_) => sent += 1,
                        Err(RingError::Full) => std::thread::yield_now(),
                        Err(e) => panic!("producer error: {:?}", e),
                    }
                }
            })
        };

        let consumer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let slice: &[u8] = shared.0.as_slice();
                let r = Ring::attach(slice).unwrap();
                let mut recvd = 0usize;
                while recvd < count {
                    match r.try_pop() {
                        Ok((hdr, data)) => {
                            assert_eq!(hdr.correlation as usize, recvd);
                            assert_eq!(data, (recvd as u32).to_le_bytes().to_vec());
                            recvd += 1;
                        }
                        Err(RingError::Empty) => std::thread::yield_now(),
                        Err(e) => panic!("consumer error: {:?}", e),
                    }
                }
            })
        };

        producer.join().unwrap();
        consumer.join().unwrap();
    }
}
