//! End-user IPC abstraction: a bidirectional [`Channel`] composed of
//! two SPSC rings inside a single shared memory mapping.
//!
//! The host (parent) side uses [`ChannelSide::Host`]; the shim (child)
//! side uses [`ChannelSide::Shim`]. The rings are wired so that each side
//! is the *sole* producer on one and the *sole* consumer on the other.

use crate::ring::{ring_bytes, Ring, RING_HEADER_SIZE};
#[cfg(windows)]
use crate::shm::SharedMemory;
#[cfg(windows)]
use crate::signal;
use psroot_netstack_proto::{SlotHeader, DEFAULT_RING_SLOTS};

/// Describes the byte layout of a shared mapping hosting one channel.
///
/// Two rings + a tiny control header are packed into one mapping so that
/// we only have to inherit a single handle to the child.
#[derive(Debug, Clone, Copy)]
pub struct ChannelLayout {
    pub slot_count: u32,
    pub host_to_shim_offset: usize,
    pub shim_to_host_offset: usize,
    pub total_size: usize,
}

impl ChannelLayout {
    pub const fn new(slot_count: u32) -> Self {
        // Ring buffer bytes, 64-byte aligned.
        let ring = ring_bytes(slot_count);
        let aligned = (ring + 63) & !63;
        // Place `host_to_shim` first, `shim_to_host` second.
        Self {
            slot_count,
            host_to_shim_offset: 0,
            shim_to_host_offset: aligned,
            total_size: aligned * 2,
        }
    }

    pub const fn default_layout() -> Self {
        Self::new(DEFAULT_RING_SLOTS)
    }
}

#[allow(dead_code)]
const _: () = {
    // RING_HEADER_SIZE must be at most 64 or layout assumptions break.
    assert!(RING_HEADER_SIZE <= 64);
};

/// Which side of the channel owns this handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSide {
    /// Parent / runtime / daemon.
    Host,
    /// Injected shim inside the AppContainer child.
    Shim,
}

/// A duplex IPC channel.
#[cfg(windows)]
pub struct Channel {
    shm: SharedMemory,
    layout: ChannelLayout,
    side: ChannelSide,
}

#[cfg(windows)]
impl Channel {
    /// Create a brand-new channel backed by `shm`. Initialises both rings.
    /// Used by the host before spawning the child.
    pub fn create(mut shm: SharedMemory, layout: ChannelLayout, side: ChannelSide) -> Self {
        {
            let buf = shm.as_mut_slice();
            let (a, b) = buf.split_at_mut(layout.shim_to_host_offset);
            let h2s = &mut a[layout.host_to_shim_offset..layout.host_to_shim_offset + ring_bytes(layout.slot_count)];
            let s2h = &mut b[..ring_bytes(layout.slot_count)];
            let _ = Ring::create(h2s, layout.slot_count).expect("h2s init");
            let _ = Ring::create(s2h, layout.slot_count).expect("s2h init");
        }
        Self { shm, layout, side }
    }

    /// Attach to an already-initialised channel (shim side).
    pub fn attach(shm: SharedMemory, layout: ChannelLayout, side: ChannelSide) -> Self {
        Self { shm, layout, side }
    }

    /// Byte offset of the TX ring this side writes into.
    fn tx_offset(&self) -> usize {
        match self.side {
            ChannelSide::Host => self.layout.host_to_shim_offset,
            ChannelSide::Shim => self.layout.shim_to_host_offset,
        }
    }

    /// Byte offset of the RX ring this side reads from.
    fn rx_offset(&self) -> usize {
        match self.side {
            ChannelSide::Host => self.layout.shim_to_host_offset,
            ChannelSide::Shim => self.layout.host_to_shim_offset,
        }
    }

    fn tx_ring(&self) -> Ring<'_> {
        let buf = &self.shm.as_slice()[self.tx_offset()..self.tx_offset() + ring_bytes(self.layout.slot_count)];
        Ring::attach(buf).expect("tx ring valid")
    }

    fn rx_ring(&self) -> Ring<'_> {
        let buf = &self.shm.as_slice()[self.rx_offset()..self.rx_offset() + ring_bytes(self.layout.slot_count)];
        Ring::attach(buf).expect("rx ring valid")
    }

    /// Post a message to the other side.
    pub fn send(&self, header: SlotHeader, data: &[u8]) -> Result<(), crate::ring::RingError> {
        let ring = self.tx_ring();
        ring.try_push(header, data)?;
        signal::post(ring.futex());
        Ok(())
    }

    /// Try to pop the next message without blocking.
    pub fn try_recv(&self) -> Result<(SlotHeader, Vec<u8>), crate::ring::RingError> {
        self.rx_ring().try_pop()
    }

    /// Park up to `timeout` for a message, then try once more.
    pub fn recv_blocking(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> std::io::Result<Option<(SlotHeader, Vec<u8>)>> {
        match self.try_recv() {
            Ok(v) => return Ok(Some(v)),
            Err(crate::ring::RingError::Empty) => {}
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))),
        }
        let _ = signal::park(self.rx_ring().futex(), timeout)?;
        match self.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(crate::ring::RingError::Empty) => Ok(None),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))),
        }
    }

    pub fn side(&self) -> ChannelSide {
        self.side
    }

    pub fn shared_memory(&self) -> &SharedMemory {
        &self.shm
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use psroot_netstack_proto::{OpCode, SlotHeader};

    #[test]
    fn roundtrip_over_named_shm() {
        let layout = ChannelLayout::new(16);
        let name = format!("Local\\psroot-ns-chan-{}", std::process::id());

        let shm_host = SharedMemory::create(&name, layout.total_size).unwrap();
        let host = Channel::create(shm_host, layout, ChannelSide::Host);

        let shm_shim = SharedMemory::open(&name, layout.total_size).unwrap();
        let shim = Channel::attach(shm_shim, layout, ChannelSide::Shim);

        // Host -> shim
        host.send(SlotHeader::new(OpCode::Hello, 1), b"from-host").unwrap();
        let (h, data) = shim.try_recv().unwrap();
        assert_eq!(h.correlation, 1);
        assert_eq!(&data, b"from-host");

        // Shim -> host
        shim.send(SlotHeader::reply_ok(1, 42), b"from-shim").unwrap();
        let (h, data) = host.try_recv().unwrap();
        assert!(h.is_ok());
        assert_eq!(h.correlation, 1);
        assert_eq!(h.socket_id, 42);
        assert_eq!(&data, b"from-shim");
    }
}
