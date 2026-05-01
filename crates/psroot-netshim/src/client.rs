//! Shim-side IPC client. Wraps a [`Channel`] and exposes synchronous,
//! Winsock-shaped methods.
//!
//! # Correlation / framing
//!
//! Every request carries a monotonically increasing `correlation` id.
//! The daemon echoes it in the reply so we could (in Phase 2) pipeline
//! multiple in-flight calls per thread. For Phase 1 we keep it simple:
//! one request, then one reply. A mismatched correlation is a protocol
//! error and returns [`ClientError::Protocol`].

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use psroot_netstack_ipc::Channel;
use psroot_netstack_proto::{
    pack_socket_args, pack_u32, OpCode, SlotHeader, SockAddrBytes, StatusCode, FLAG_MORE,
};

/// Errors surfaced to callers of [`Client`].
#[derive(Debug)]
pub enum ClientError {
    /// Channel transport failure (shared memory / futex).
    Io(std::io::Error),
    /// Daemon replied with an explicit status code.
    Status(StatusCode),
    /// Something about the reply was malformed.
    Protocol(&'static str),
    /// Timed out waiting for a reply.
    Timeout,
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

pub type Result<T> = core::result::Result<T, ClientError>;

/// Synchronous client bound to one [`Channel`] (shim side).
pub struct Client {
    channel: Channel,
    next_correlation: AtomicU32,
    /// Maximum time a single request/reply round-trip may take.
    pub request_timeout: Duration,
}

impl Client {
    pub fn new(channel: Channel) -> Self {
        Self {
            channel,
            next_correlation: AtomicU32::new(1),
            request_timeout: Duration::from_secs(5),
        }
    }

    fn next_id(&self) -> u32 {
        // `fetch_add` with Relaxed is fine — correlation ids don't
        // synchronise anything, they just have to be unique per client.
        self.next_correlation.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a request header + payload, receive the matching reply.
    /// Drains `FLAG_MORE` fragments into one `Vec<u8>`.
    fn exchange(&self, mut hdr: SlotHeader, data: &[u8]) -> Result<(SlotHeader, Vec<u8>)> {
        let cid = self.next_id();
        hdr.correlation = cid;
        self.channel
            .send(hdr, data)
            .map_err(|e| ClientError::Protocol(ring_err_str(e)))?;

        let deadline = std::time::Instant::now() + self.request_timeout;
        let mut combined: Vec<u8> = Vec::new();
        let done_hdr: SlotHeader;

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::Timeout);
            }
            match self.channel.recv_blocking(Some(remaining))? {
                Some((rh, rd)) => {
                    if rh.correlation != cid {
                        return Err(ClientError::Protocol("correlation mismatch"));
                    }
                    if !rh.is_ok() {
                        let status = decode_status(rh.opcode)
                            .ok_or(ClientError::Protocol("bad status"))?;
                        return Err(ClientError::Status(status));
                    }
                    combined.extend_from_slice(&rd);
                    if rh.flags & FLAG_MORE == 0 {
                        done_hdr = rh;
                        break;
                    }
                }
                None => continue,
            }
        }
        Ok((done_hdr, combined))
    }

    // ── Winsock-shaped API ──────────────────────────────────────────

    pub fn hello(&self) -> Result<u32> {
        let (rh, _) = self.exchange(SlotHeader::new(OpCode::Hello, 0), &[])?;
        // Version echoed in args[0..4].
        Ok(u32::from_le_bytes([rh.args[0], rh.args[1], rh.args[2], rh.args[3]]))
    }

    pub fn socket(&self, af: u16, typ: u16, proto: u32) -> Result<u32> {
        let mut hdr = SlotHeader::new(OpCode::Socket, 0);
        hdr.args = pack_socket_args(af, typ, proto, 0);
        let (rh, _) = self.exchange(hdr, &[])?;
        Ok(rh.socket_id)
    }

    pub fn bind(&self, socket_id: u32, addr: SockAddrBytes) -> Result<()> {
        let mut hdr = SlotHeader::new(OpCode::Bind, 0);
        hdr.socket_id = socket_id;
        let buf = sockaddr_bytes(&addr);
        self.exchange(hdr, &buf)?;
        Ok(())
    }

    pub fn connect(&self, socket_id: u32, addr: SockAddrBytes) -> Result<()> {
        let mut hdr = SlotHeader::new(OpCode::Connect, 0);
        hdr.socket_id = socket_id;
        let buf = sockaddr_bytes(&addr);
        self.exchange(hdr, &buf)?;
        Ok(())
    }

    pub fn listen(&self, socket_id: u32, backlog: u32) -> Result<()> {
        let mut hdr = SlotHeader::new(OpCode::Listen, 0);
        hdr.socket_id = socket_id;
        hdr.args = pack_u32(backlog);
        self.exchange(hdr, &[])?;
        Ok(())
    }

    pub fn accept(&self, socket_id: u32) -> Result<(u32, SockAddrBytes)> {
        let mut hdr = SlotHeader::new(OpCode::Accept, 0);
        hdr.socket_id = socket_id;
        let (rh, data) = self.exchange(hdr, &[])?;
        let addr = parse_sockaddr(&data).ok_or(ClientError::Protocol("bad peer"))?;
        Ok((rh.socket_id, addr))
    }

    pub fn send(&self, socket_id: u32, data: &[u8]) -> Result<u32> {
        let mut hdr = SlotHeader::new(OpCode::Send, 0);
        hdr.socket_id = socket_id;
        let (rh, _) = self.exchange(hdr, data)?;
        Ok(u32::from_le_bytes([rh.args[0], rh.args[1], rh.args[2], rh.args[3]]))
    }

    pub fn recv(&self, socket_id: u32, max: u32) -> Result<Vec<u8>> {
        let mut hdr = SlotHeader::new(OpCode::Recv, 0);
        hdr.socket_id = socket_id;
        hdr.args = pack_u32(max);
        let (_rh, data) = self.exchange(hdr, &[])?;
        Ok(data)
    }

    pub fn close(&self, socket_id: u32) -> Result<()> {
        let mut hdr = SlotHeader::new(OpCode::Close, 0);
        hdr.socket_id = socket_id;
        self.exchange(hdr, &[])?;
        Ok(())
    }

    pub fn shutdown(&self, socket_id: u32, how: u32) -> Result<()> {
        let mut hdr = SlotHeader::new(OpCode::Shutdown, 0);
        hdr.socket_id = socket_id;
        hdr.args = pack_u32(how);
        self.exchange(hdr, &[])?;
        Ok(())
    }

    pub fn getsockname(&self, socket_id: u32) -> Result<SockAddrBytes> {
        let mut hdr = SlotHeader::new(OpCode::GetSockName, 0);
        hdr.socket_id = socket_id;
        let (_rh, data) = self.exchange(hdr, &[])?;
        parse_sockaddr(&data).ok_or(ClientError::Protocol("bad sockaddr"))
    }

    pub fn getpeername(&self, socket_id: u32) -> Result<SockAddrBytes> {
        let mut hdr = SlotHeader::new(OpCode::GetPeerName, 0);
        hdr.socket_id = socket_id;
        let (_rh, data) = self.exchange(hdr, &[])?;
        parse_sockaddr(&data).ok_or(ClientError::Protocol("bad sockaddr"))
    }

    /// UDP `sendto`. Pack `[sockaddr:28][payload]` and send.
    pub fn sendto(&self, socket_id: u32, addr: SockAddrBytes, data: &[u8]) -> Result<u32> {
        let mut hdr = SlotHeader::new(OpCode::SendTo, 0);
        hdr.socket_id = socket_id;
        let addr_bytes = sockaddr_bytes(&addr);
        // Avoid a temporary alloc by using a small stack-friendly vec.
        // Caller-side datagrams are small (< MTU) so this is fine.
        let mut payload = Vec::with_capacity(28 + data.len());
        payload.extend_from_slice(&addr_bytes);
        payload.extend_from_slice(data);
        let (rh, _) = self.exchange(hdr, &payload)?;
        Ok(u32::from_le_bytes([rh.args[0], rh.args[1], rh.args[2], rh.args[3]]))
    }

    /// UDP `recvfrom`. Reply: `(payload, peer)`.
    pub fn recvfrom(&self, socket_id: u32, max: u32) -> Result<(Vec<u8>, SockAddrBytes)> {
        let mut hdr = SlotHeader::new(OpCode::RecvFrom, 0);
        hdr.socket_id = socket_id;
        hdr.args = pack_u32(max);
        let (_rh, data) = self.exchange(hdr, &[])?;
        if data.len() < 28 {
            return Err(ClientError::Protocol("recvfrom reply too short"));
        }
        let peer = parse_sockaddr(&data[..28]).ok_or(ClientError::Protocol("bad peer"))?;
        Ok((data[28..].to_vec(), peer))
    }
}

// ───────────────────────────── helpers ─────────────────────────────────

fn sockaddr_bytes(a: &SockAddrBytes) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[0..2].copy_from_slice(&a.family.to_le_bytes());
    out[2..4].copy_from_slice(&a.port.to_le_bytes());
    out[4..8].copy_from_slice(&a.v6_flow.to_le_bytes());
    out[8..24].copy_from_slice(&a.addr);
    out[24..28].copy_from_slice(&a.v6_scope.to_le_bytes());
    out
}

fn parse_sockaddr(data: &[u8]) -> Option<SockAddrBytes> {
    if data.len() < 28 {
        return None;
    }
    let family = u16::from_le_bytes([data[0], data[1]]);
    let port = u16::from_le_bytes([data[2], data[3]]);
    let v6_flow = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&data[8..24]);
    let v6_scope = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    Some(SockAddrBytes {
        family,
        port,
        v6_flow,
        addr,
        v6_scope,
    })
}

fn decode_status(raw: u16) -> Option<StatusCode> {
    Some(match raw {
        1 => StatusCode::UnknownOp,
        2 => StatusCode::BadSocket,
        3 => StatusCode::WouldBlock,
        4 => StatusCode::ConnRefused,
        5 => StatusCode::NotSupported,
        6 => StatusCode::HostError,
        7 => StatusCode::ConnReset,
        8 => StatusCode::TooLarge,
        9 => StatusCode::AddrInUse,
        10 => StatusCode::AddrNotAvail,
        _ => return None,
    })
}

fn ring_err_str(_e: psroot_netstack_ipc::RingError) -> &'static str {
    "ring error"
}
