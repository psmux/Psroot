//! Backend trait: the abstraction that lets us swap the NAT
//! implementation out for smoltcp (or a router) in Phase 2.

use psroot_netstack_proto::{SlotHeader, SockAddrBytes, StatusCode};

/// Events produced asynchronously by a backend — e.g. data arrived on a
/// socket, or a listener accepted a connection. Pushed back to the shim
/// over the same channel.
#[derive(Debug, Clone)]
pub enum Event {
    /// New bytes available for `recv` on a socket.
    Readable { socket_id: u32 },
    /// Socket became writable again after hitting backpressure.
    Writable { socket_id: u32 },
    /// Connection on a listener is ready to be accepted.
    Accepted {
        listener_id: u32,
        new_socket_id: u32,
        peer: SockAddrBytes,
    },
    /// Connection closed by peer.
    Closed { socket_id: u32 },
}

/// The only interface the [`Daemon`] needs to dispatch shim requests.
///
/// Each method returns either a successful reply header + payload, or an
/// error status that the daemon turns into a [`SlotHeader::reply_err`].
pub trait Backend: Send {
    /// Socket id 0 is reserved.
    fn socket(&mut self, af: u16, typ: u16, proto: u32) -> BResult<u32>;
    fn bind(&mut self, socket_id: u32, addr: SockAddrBytes) -> BResult<()>;
    fn connect(&mut self, socket_id: u32, addr: SockAddrBytes) -> BResult<()>;
    fn listen(&mut self, socket_id: u32, backlog: u32) -> BResult<()>;
    fn accept(&mut self, socket_id: u32) -> BResult<(u32, SockAddrBytes)>;
    fn send(&mut self, socket_id: u32, data: &[u8]) -> BResult<u32>;
    fn recv(&mut self, socket_id: u32, max: u32) -> BResult<Vec<u8>>;
    fn close(&mut self, socket_id: u32) -> BResult<()>;
    fn shutdown(&mut self, socket_id: u32, how: u32) -> BResult<()>;
    fn get_sock_name(&mut self, socket_id: u32) -> BResult<SockAddrBytes>;
    fn get_peer_name(&mut self, socket_id: u32) -> BResult<SockAddrBytes>;

    /// UDP `sendto` — send a datagram to `addr`. Returns bytes sent.
    fn sendto(
        &mut self,
        _socket_id: u32,
        _addr: SockAddrBytes,
        _data: &[u8],
    ) -> BResult<u32> {
        Err(StatusCode::NotSupported)
    }
    /// UDP `recvfrom` — receive one datagram. Returns `(data, peer)`.
    /// Must respect non-blocking semantics and return `WouldBlock` if
    /// no datagram is ready.
    fn recvfrom(&mut self, _socket_id: u32, _max: u32) -> BResult<(Vec<u8>, SockAddrBytes)> {
        Err(StatusCode::NotSupported)
    }

    /// Drain any async events the backend produced since the last call.
    ///
    /// The daemon calls this after each request and also periodically
    /// while idle. Zero events is the common case.
    fn poll_events(&mut self) -> Vec<Event> {
        Vec::new()
    }

    /// Human-readable name for logging.
    fn name(&self) -> &'static str;
}

pub type BResult<T> = Result<T, StatusCode>;

/// Turn a `BResult` into a reply header ready to post back to the shim.
pub fn reply_from<T>(
    correlation: u32,
    socket_id: u32,
    result: BResult<T>,
) -> (SlotHeader, Option<T>) {
    match result {
        Ok(v) => (SlotHeader::reply_ok(correlation, socket_id), Some(v)),
        Err(status) => (SlotHeader::reply_err(correlation, status), None),
    }
}
