//! The daemon event loop: consume shim requests, dispatch, reply.
//!
//! The daemon is designed to run on its own thread, owned by the psroot
//! runtime. It is `Send`. A `stop_flag` (set from another thread) causes
//! it to exit cleanly after the current message is handled.
//!
//! # Message flow
//!
//! ```text
//!   shim                     daemon                 backend
//!   ────                     ──────                 ───────
//!   SlotHeader(Connect)  ─►  try_recv()  ─────────► connect()
//!                            ◄─── BResult<T> ──────
//!   SlotHeader(ok, ...)  ◄─  send()
//! ```

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use psroot_netstack_ipc::Channel;
use psroot_netstack_proto::{
    pack_u32, unpack_socket_args, unpack_u32, OpCode, SlotHeader, SockAddrBytes, StatusCode,
    DATA_CAPACITY, HEADER_SIZE,
};
use tracing::{debug, warn};

use crate::backend::Backend;

/// The host-side daemon.
pub struct Daemon<B: Backend> {
    channel: Channel,
    backend: B,
    stop: Arc<AtomicBool>,
}

impl<B: Backend> Daemon<B> {
    pub fn new(channel: Channel, backend: B, stop: Arc<AtomicBool>) -> Self {
        Self { channel, backend, stop }
    }

    /// Run the daemon until `stop` is set. Blocks the calling thread.
    pub fn run(mut self) -> io::Result<()> {
        while !self.stop.load(Ordering::Acquire) {
            // Park up to 100ms so the stop flag is checked frequently
            // without burning CPU.
            match self.channel.recv_blocking(Some(Duration::from_millis(100)))? {
                Some((hdr, data)) => {
                    if let Err(e) = self.handle(hdr, &data) {
                        warn!(error = ?e, "daemon: handler error");
                    }
                }
                None => continue,
            }
        }
        debug!("daemon: stop flag set, exiting");
        Ok(())
    }

    /// Handle one request. Always posts a reply (success or error).
    fn handle(&mut self, hdr: SlotHeader, data: &[u8]) -> io::Result<()> {
        let op = match OpCode::from_raw(hdr.opcode) {
            Some(op) => op,
            None => {
                return self.reply_err(hdr.correlation, StatusCode::UnknownOp);
            }
        };

        match op {
            OpCode::Hello => {
                // Echo back the protocol version in the args; payload is empty.
                let mut reply = SlotHeader::reply_ok(hdr.correlation, 0);
                reply.args[..4].copy_from_slice(&1u32.to_le_bytes()); // version
                self.post(reply, &[])?;
            }
            OpCode::Socket => {
                let (af, typ, proto, _flags) = unpack_socket_args(&hdr.args);
                match self.backend.socket(af, typ, proto) {
                    Ok(id) => self.post(SlotHeader::reply_ok(hdr.correlation, id), &[])?,
                    Err(s) => self.reply_err(hdr.correlation, s)?,
                }
            }
            OpCode::Bind => self.with_sockaddr(hdr, data, |b, id, a| b.bind(id, a).map(|_| 0))?,
            OpCode::Connect => {
                self.with_sockaddr(hdr, data, |b, id, a| b.connect(id, a).map(|_| 0))?
            }
            OpCode::Listen => {
                let backlog = unpack_u32(&hdr.args);
                let r = self.backend.listen(hdr.socket_id, backlog);
                self.reply_unit(hdr.correlation, hdr.socket_id, r)?;
            }
            OpCode::Accept => match self.backend.accept(hdr.socket_id) {
                Ok((new_id, peer)) => {
                    let mut buf = [0u8; 28];
                    write_sockaddr(&peer, &mut buf);
                    self.post(SlotHeader::reply_ok(hdr.correlation, new_id), &buf)?;
                }
                Err(s) => self.reply_err(hdr.correlation, s)?,
            },
            OpCode::Send => match self.backend.send(hdr.socket_id, data) {
                Ok(n) => {
                    let mut reply = SlotHeader::reply_ok(hdr.correlation, hdr.socket_id);
                    reply.args = pack_u32(n);
                    self.post(reply, &[])?;
                }
                Err(s) => self.reply_err(hdr.correlation, s)?,
            },
            OpCode::Recv => {
                let max = unpack_u32(&hdr.args);
                match self.backend.recv(hdr.socket_id, max) {
                    Ok(bytes) => {
                        // Fragmentation: if >DATA_CAPACITY, split into
                        // multiple slots with FLAG_MORE set on all but last.
                        let mut remaining = &bytes[..];
                        if remaining.is_empty() {
                            // 0-byte recv (EOF) — single empty reply.
                            self.post(
                                SlotHeader::reply_ok(hdr.correlation, hdr.socket_id),
                                &[],
                            )?;
                        } else {
                            while !remaining.is_empty() {
                                let chunk = remaining.len().min(DATA_CAPACITY);
                                let last = chunk == remaining.len();
                                let mut reply = SlotHeader::reply_ok(hdr.correlation, hdr.socket_id);
                                if !last {
                                    reply.flags |= psroot_netstack_proto::FLAG_MORE;
                                }
                                self.post(reply, &remaining[..chunk])?;
                                remaining = &remaining[chunk..];
                            }
                        }
                    }
                    Err(s) => self.reply_err(hdr.correlation, s)?,
                }
            }
            OpCode::Close => {
                let r = self.backend.close(hdr.socket_id);
                self.reply_unit(hdr.correlation, hdr.socket_id, r)?;
            }
            OpCode::Shutdown => {
                let how = unpack_u32(&hdr.args);
                let r = self.backend.shutdown(hdr.socket_id, how);
                self.reply_unit(hdr.correlation, hdr.socket_id, r)?;
            }
            OpCode::GetSockName => match self.backend.get_sock_name(hdr.socket_id) {
                Ok(a) => {
                    let mut buf = [0u8; 28];
                    write_sockaddr(&a, &mut buf);
                    self.post(SlotHeader::reply_ok(hdr.correlation, hdr.socket_id), &buf)?;
                }
                Err(s) => self.reply_err(hdr.correlation, s)?,
            },
            OpCode::GetPeerName => match self.backend.get_peer_name(hdr.socket_id) {
                Ok(a) => {
                    let mut buf = [0u8; 28];
                    write_sockaddr(&a, &mut buf);
                    self.post(SlotHeader::reply_ok(hdr.correlation, hdr.socket_id), &buf)?;
                }
                Err(s) => self.reply_err(hdr.correlation, s)?,
            },
            OpCode::SetSockOpt | OpCode::GetSockOpt => {
                // Phase 1: opt stubs — silently succeed for setsockopt,
                // return empty for getsockopt. Good enough for TCP_NODELAY,
                // SO_REUSEADDR, etc. which many apps set without checking.
                self.post(SlotHeader::reply_ok(hdr.correlation, hdr.socket_id), &[])?;
            }
            OpCode::Resolve => {
                // Phase 1: delegate to host getaddrinfo via std.
                let name = match std::str::from_utf8(data) {
                    Ok(s) => s,
                    Err(_) => return self.reply_err(hdr.correlation, StatusCode::HostError),
                };
                match (name, 0u16).to_socket_addrs_best() {
                    Ok(addr) => {
                        let mut buf = [0u8; 28];
                        write_sockaddr(&addr, &mut buf);
                        self.post(SlotHeader::reply_ok(hdr.correlation, 0), &buf)?;
                    }
                    Err(_) => self.reply_err(hdr.correlation, StatusCode::HostError)?,
                }
            }
            OpCode::SendTo => {
                // Payload: [sockaddr:28][datagram].
                let Some(addr) = read_sockaddr(data) else {
                    return self.reply_err(hdr.correlation, StatusCode::HostError);
                };
                if data.len() < 28 {
                    return self.reply_err(hdr.correlation, StatusCode::HostError);
                }
                let payload = &data[28..];
                match self.backend.sendto(hdr.socket_id, addr, payload) {
                    Ok(n) => {
                        let mut reply = SlotHeader::reply_ok(hdr.correlation, hdr.socket_id);
                        reply.args = pack_u32(n);
                        self.post(reply, &[])?;
                    }
                    Err(s) => self.reply_err(hdr.correlation, s)?,
                }
            }
            OpCode::RecvFrom => {
                let max = unpack_u32(&hdr.args);
                match self.backend.recvfrom(hdr.socket_id, max) {
                    Ok((bytes, peer)) => {
                        // Reply payload: [sockaddr:28][datagram].
                        // UDP datagrams cap at 64KiB \u2014 well below a slot's
                        // DATA_CAPACITY when we split into fragments.
                        let mut addr_buf = [0u8; 28];
                        write_sockaddr(&peer, &mut addr_buf);
                        let total_len = 28 + bytes.len();
                        if total_len <= DATA_CAPACITY {
                            let mut out = Vec::with_capacity(total_len);
                            out.extend_from_slice(&addr_buf);
                            out.extend_from_slice(&bytes);
                            self.post(
                                SlotHeader::reply_ok(hdr.correlation, hdr.socket_id),
                                &out,
                            )?;
                        } else {
                            // First fragment carries sockaddr + prefix; subsequent
                            // fragments carry the rest with FLAG_MORE.
                            let first_payload_cap = DATA_CAPACITY - 28;
                            let (first, rest) = bytes.split_at(first_payload_cap);
                            let mut out = Vec::with_capacity(DATA_CAPACITY);
                            out.extend_from_slice(&addr_buf);
                            out.extend_from_slice(first);
                            let mut h0 = SlotHeader::reply_ok(hdr.correlation, hdr.socket_id);
                            h0.flags |= psroot_netstack_proto::FLAG_MORE;
                            self.post(h0, &out)?;
                            let mut remaining = rest;
                            while !remaining.is_empty() {
                                let chunk = remaining.len().min(DATA_CAPACITY);
                                let last = chunk == remaining.len();
                                let mut h = SlotHeader::reply_ok(hdr.correlation, hdr.socket_id);
                                if !last {
                                    h.flags |= psroot_netstack_proto::FLAG_MORE;
                                }
                                self.post(h, &remaining[..chunk])?;
                                remaining = &remaining[chunk..];
                            }
                        }
                    }
                    Err(s) => self.reply_err(hdr.correlation, s)?,
                }
            }
            OpCode::Bye => {
                self.stop.store(true, Ordering::Release);
            }
        }
        let _ = HEADER_SIZE;
        Ok(())
    }

    fn with_sockaddr<F>(&mut self, hdr: SlotHeader, data: &[u8], f: F) -> io::Result<()>
    where
        F: FnOnce(&mut B, u32, SockAddrBytes) -> Result<u32, StatusCode>,
    {
        let Some(addr) = read_sockaddr(data) else {
            return self.reply_err(hdr.correlation, StatusCode::HostError);
        };
        match f(&mut self.backend, hdr.socket_id, addr) {
            Ok(_) => self.post(SlotHeader::reply_ok(hdr.correlation, hdr.socket_id), &[]),
            Err(s) => self.reply_err(hdr.correlation, s),
        }
    }

    fn reply_unit(
        &self,
        correlation: u32,
        socket_id: u32,
        r: Result<(), StatusCode>,
    ) -> io::Result<()> {
        match r {
            Ok(()) => self.post(SlotHeader::reply_ok(correlation, socket_id), &[]),
            Err(s) => self.reply_err(correlation, s),
        }
    }

    fn reply_err(&self, correlation: u32, status: StatusCode) -> io::Result<()> {
        self.post(SlotHeader::reply_err(correlation, status), &[])
    }

    fn post(&self, hdr: SlotHeader, data: &[u8]) -> io::Result<()> {
        self.channel.send(hdr, data).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("channel send: {:?}", e))
        })
    }
}

// ───────────────────────────── helpers ─────────────────────────────────

fn write_sockaddr(a: &SockAddrBytes, out: &mut [u8; 28]) {
    out[0..2].copy_from_slice(&a.family.to_le_bytes());
    out[2..4].copy_from_slice(&a.port.to_le_bytes());
    out[4..8].copy_from_slice(&a.v6_flow.to_le_bytes());
    out[8..24].copy_from_slice(&a.addr);
    out[24..28].copy_from_slice(&a.v6_scope.to_le_bytes());
}

fn read_sockaddr(data: &[u8]) -> Option<SockAddrBytes> {
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

/// Little helper: resolve a hostname to its first usable IPv4/IPv6 addr.
trait ToSocketAddrsBest {
    fn to_socket_addrs_best(&self) -> io::Result<SockAddrBytes>;
}

impl ToSocketAddrsBest for (&str, u16) {
    fn to_socket_addrs_best(&self) -> io::Result<SockAddrBytes> {
        use std::net::ToSocketAddrs;
        let (name, port) = *self;
        let mut iter = (name, port).to_socket_addrs()?;
        let first = iter
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses"))?;
        Ok(match first {
            std::net::SocketAddr::V4(v) => SockAddrBytes::v4(v.ip().octets(), v.port()),
            std::net::SocketAddr::V6(v) => {
                SockAddrBytes::v6(v.ip().octets(), v.port(), 0, v.scope_id())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psroot_netstack_ipc::{ChannelLayout, ChannelSide};
    use psroot_netstack_proto::{pack_socket_args, AF_INET_V};
    use std::net::Ipv4Addr;

    fn pair() -> (Channel, Channel) {
        let layout = ChannelLayout::new(16);
        let name = format!(
            "Local\\psroot-ns-daemon-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let host_shm = psroot_netstack_ipc::shm::SharedMemory::create(&name, layout.total_size).unwrap();
        let host = Channel::create(host_shm, layout, ChannelSide::Host);
        let shim_shm = psroot_netstack_ipc::shm::SharedMemory::open(&name, layout.total_size).unwrap();
        let shim = Channel::attach(shim_shm, layout, ChannelSide::Shim);
        (host, shim)
    }

    #[test]
    fn hello_roundtrip() {
        let (host, shim) = pair();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let d = Daemon::new(host, crate::NatBackend::new(Ipv4Addr::new(10, 88, 0, 2)), stop);
        let t = std::thread::spawn(move || d.run().unwrap());

        shim.send(SlotHeader::new(OpCode::Hello, 1), &[]).unwrap();
        let (r, _) = shim.recv_blocking(Some(Duration::from_secs(2))).unwrap().unwrap();
        assert!(r.is_ok());
        assert_eq!(r.correlation, 1);

        stop2.store(true, Ordering::Release);
        t.join().unwrap();
    }

    #[test]
    fn socket_create_reply() {
        let (host, shim) = pair();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let d = Daemon::new(host, crate::NatBackend::new(Ipv4Addr::new(10, 88, 0, 2)), stop);
        let t = std::thread::spawn(move || d.run().unwrap());

        let mut hdr = SlotHeader::new(OpCode::Socket, 99);
        hdr.args = pack_socket_args(AF_INET_V, 1, 6, 0);
        shim.send(hdr, &[]).unwrap();
        let (r, _) = shim.recv_blocking(Some(Duration::from_secs(2))).unwrap().unwrap();
        assert!(r.is_ok());
        assert!(r.socket_id >= 1);
        assert_eq!(r.correlation, 99);

        stop2.store(true, Ordering::Release);
        t.join().unwrap();
    }
}
