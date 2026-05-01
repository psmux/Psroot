//! NAT-outbound backend: Phase-1 implementation.
//!
//! Translates container socket syscalls into real host `std::net` sockets.
//! The container still thinks it owns the virtual IP assigned to it by
//! the daemon; `getsockname` / `getpeername` report the virtual address
//! while actual I/O happens on the host.
//!
//! # What this DOES deliver today
//!
//! * Port-space isolation — container can bind any port, no host
//!   conflict (we bind `127.0.0.1:0` on the host).
//! * Outbound `connect()` → real host connection to any address.
//! * Listeners + `accept()` for inbound traffic published via the
//!   existing `psroot-portmap` crate.
//! * Synthetic per-container IP visible to `getsockname`.
//!
//! # What it DOESN'T deliver yet (Phase 2)
//!
//! * True per-container L3 addressing reachable from the host or
//!   sibling containers — that needs smoltcp + a routing layer.
//! * UDP (trivial to add but not wired).
//! * Raw sockets.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket};

use psroot_netstack_proto::{SockAddrBytes, StatusCode, AF_INET_V, AF_INET6_V};
use tracing::debug;

use crate::backend::{BResult, Backend};
use crate::socket_table::SocketTable;

/// Per-socket state inside the NAT backend.
enum SockState {
    /// Socket created but not yet bound/connected.
    Fresh { af: u16, typ: u16 },
    /// TCP stream to a peer.
    Stream {
        stream: TcpStream,
        peer_virtual: SockAddrBytes,
    },
    /// TCP listener.
    Listener {
        listener: TcpListener,
        bind_virtual: SockAddrBytes,
    },
    /// UDP datagram socket. `bind_virtual` is what the container sees
    /// when it calls `getsockname`; `socket` is the real host socket.
    Dgram {
        socket: UdpSocket,
        bind_virtual: SockAddrBytes,
    },
}

/// Address translator: rewrites the destination the container asked to
/// connect to into an address the host can actually reach. Returning
/// `None` means "no rewrite — connect to the given address as-is".
///
/// Used to keep Phase-1 tests honest: the container speaks to the
/// virtual IP `10.88.0.7`, the translator points that at `127.0.0.1`,
/// and end-to-end plumbing exercises every link in the chain.
pub type AddrTranslator = Box<dyn Fn(SocketAddr) -> Option<SocketAddr> + Send + Sync>;

/// NAT-outbound backend.
pub struct NatBackend {
    table: SocketTable<SockState>,
    /// Virtual IPv4 the container is told it owns (e.g. 10.88.0.2).
    pub virtual_ipv4: Ipv4Addr,
    /// Accept-queue per listener id → stored so accept() returns them FIFO.
    pending_accepts: HashMap<u32, Vec<(TcpStream, SocketAddr)>>,
    /// Optional destination translator applied to every `connect()`.
    translator: Option<AddrTranslator>,
}

impl NatBackend {
    pub fn new(virtual_ipv4: Ipv4Addr) -> Self {
        Self {
            table: SocketTable::new(),
            virtual_ipv4,
            pending_accepts: HashMap::new(),
            translator: None,
        }
    }

    /// Replace the destination-address translator. See [`AddrTranslator`].
    pub fn with_translator(mut self, t: AddrTranslator) -> Self {
        self.translator = Some(t);
        self
    }
}

impl Backend for NatBackend {
    fn name(&self) -> &'static str {
        "nat"
    }

    fn socket(&mut self, af: u16, typ: u16, _proto: u32) -> BResult<u32> {
        // Phase 2+: AF_INET(6) with SOCK_STREAM (1) or SOCK_DGRAM (2).
        if af != AF_INET_V && af != AF_INET6_V {
            return Err(StatusCode::NotSupported);
        }
        if typ != 1 /* SOCK_STREAM */ && typ != 2 /* SOCK_DGRAM */ {
            return Err(StatusCode::NotSupported);
        }
        Ok(self.table.insert(SockState::Fresh { af, typ }))
    }

    fn bind(&mut self, socket_id: u32, addr: SockAddrBytes) -> BResult<()> {
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let (af, typ) = match state {
            SockState::Fresh { af, typ } => (*af, *typ),
            // Re-binding an already-bound UDP/TCP socket is not supported.
            _ => return Err(StatusCode::NotSupported),
        };
        if typ == 2 /* SOCK_DGRAM */ {
            // Bind a real host UDP socket on loopback:0 (ephemeral).
            // The container will always see `virtual_ipv4:<real_port>`.
            let bind_addr: SocketAddr = if af == AF_INET_V {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            } else {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
            };
            let socket = UdpSocket::bind(bind_addr).map_err(map_io_err)?;
            // Leave the UDP socket in its default *blocking* mode: the
            // daemon thread serves one client at a time in the current
            // design, and a blocking `recv_from` matches Winsock's
            // default semantics for datagram sockets (a naive
            // `recvfrom()` on a bound UDP socket waits for a datagram).
            // A 5-second read timeout guards against test hangs if
            // something upstream silently dropped the datagram.
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .ok();
            // Windows: disable the "UDP connection reset" behaviour
            // where an ICMP "port unreachable" from a previous target
            // gets delivered on the next `recvfrom` as WSAECONNRESET.
            // Loopback targets that bind briefly then drop trigger this
            // spuriously on fast handshakes; we're intentionally not
            // implementing ICMP semantics.
            #[cfg(windows)]
            disable_udp_connreset(&socket);
            let local = socket.local_addr().map_err(map_io_err)?;
            let bind_virtual = SockAddrBytes::v4(self.virtual_ipv4.octets(), local.port());
            *state = SockState::Dgram { socket, bind_virtual };
            debug!(socket_id, requested = ?addr, real = ?local, "udp bind");
            return Ok(());
        }
        // TCP: defer until listen() / connect(). Just record intent.
        let _ = addr;
        Ok(())
    }

    fn connect(&mut self, socket_id: u32, addr: SockAddrBytes) -> BResult<()> {
        let requested = sockaddr_to_std(&addr).ok_or(StatusCode::AddrNotAvail)?;
        // Apply the optional host-side translation so virtual container
        // addresses get rewritten to something the real OS can reach.
        let target = self
            .translator
            .as_ref()
            .and_then(|t| t(requested))
            .unwrap_or(requested);
        let stream = TcpStream::connect(target).map_err(map_io_err)?;
        let _ = stream.set_nodelay(true);
        *self
            .table
            .get_mut(socket_id)
            .ok_or(StatusCode::BadSocket)? = SockState::Stream {
            stream,
            // The container keeps seeing its virtual peer, not the
            // translated address.
            peer_virtual: addr,
        };
        debug!(socket_id, ?requested, ?target, "connect established");
        Ok(())
    }

    fn listen(&mut self, socket_id: u32, _backlog: u32) -> BResult<()> {
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let af = match state {
            SockState::Fresh { af, .. } => *af,
            SockState::Listener { .. } => return Ok(()),
            _ => return Err(StatusCode::NotSupported),
        };
        // Bind the real listener on 127.0.0.1:0 — ephemeral, invisible to
        // the container.
        let bind_addr: SocketAddr = if af == AF_INET_V {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        } else {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        };
        let listener = TcpListener::bind(bind_addr).map_err(map_io_err)?;
        listener.set_nonblocking(true).ok();
        // Virtual address we report to the container is `virtual_ipv4:<port>`.
        let local = listener.local_addr().map_err(map_io_err)?;
        let bind_virtual = SockAddrBytes::v4(self.virtual_ipv4.octets(), local.port());
        *state = SockState::Listener {
            listener,
            bind_virtual,
        };
        Ok(())
    }

    fn accept(&mut self, socket_id: u32) -> BResult<(u32, SockAddrBytes)> {
        let state = self.table.get(socket_id).ok_or(StatusCode::BadSocket)?;
        let listener = match state {
            SockState::Listener { listener, .. } => listener,
            _ => return Err(StatusCode::NotSupported),
        };
        match listener.accept() {
            Ok((stream, peer)) => {
                let peer_v = match peer {
                    SocketAddr::V4(v) => SockAddrBytes::v4(v.ip().octets(), v.port()),
                    SocketAddr::V6(v) => SockAddrBytes::v6(v.ip().octets(), v.port(), 0, v.scope_id()),
                };
                let _ = stream.set_nodelay(true);
                let id = self.table.insert(SockState::Stream {
                    stream,
                    peer_virtual: peer_v,
                });
                Ok((id, peer_v))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(StatusCode::WouldBlock),
            Err(e) => Err(map_io_err(e)),
        }
    }

    fn send(&mut self, socket_id: u32, data: &[u8]) -> BResult<u32> {
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let stream = match state {
            SockState::Stream { stream, .. } => stream,
            _ => return Err(StatusCode::NotSupported),
        };
        // Use write (not write_all) so partial writes surface to the
        // caller — matches Winsock send() semantics.
        let n = stream.write(data).map_err(map_io_err)?;
        Ok(n as u32)
    }

    fn recv(&mut self, socket_id: u32, max: u32) -> BResult<Vec<u8>> {
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let stream = match state {
            SockState::Stream { stream, .. } => stream,
            _ => return Err(StatusCode::NotSupported),
        };
        let cap = (max as usize).min(psroot_netstack_proto::DATA_CAPACITY);
        let mut buf = vec![0u8; cap];
        match stream.read(&mut buf) {
            Ok(0) => {
                buf.truncate(0);
                Ok(buf)
            }
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(StatusCode::WouldBlock),
            Err(e) => Err(map_io_err(e)),
        }
    }

    fn close(&mut self, socket_id: u32) -> BResult<()> {
        self.pending_accepts.remove(&socket_id);
        self.table.remove(socket_id);
        Ok(())
    }

    fn shutdown(&mut self, socket_id: u32, how: u32) -> BResult<()> {
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let stream = match state {
            SockState::Stream { stream, .. } => stream,
            _ => return Err(StatusCode::NotSupported),
        };
        let how = match how {
            0 => Shutdown::Read,
            1 => Shutdown::Write,
            _ => Shutdown::Both,
        };
        stream.shutdown(how).map_err(map_io_err)?;
        Ok(())
    }

    fn get_sock_name(&mut self, socket_id: u32) -> BResult<SockAddrBytes> {
        let state = self.table.get(socket_id).ok_or(StatusCode::BadSocket)?;
        match state {
            SockState::Fresh { .. } => Ok(SockAddrBytes::v4([0, 0, 0, 0], 0)),
            SockState::Stream { stream, .. } => {
                // Return virtual address — hide the real loopback port.
                let port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                Ok(SockAddrBytes::v4(self.virtual_ipv4.octets(), port))
            }
            SockState::Listener { bind_virtual, .. } => Ok(*bind_virtual),
            SockState::Dgram { bind_virtual, .. } => Ok(*bind_virtual),
        }
    }

    fn get_peer_name(&mut self, socket_id: u32) -> BResult<SockAddrBytes> {
        let state = self.table.get(socket_id).ok_or(StatusCode::BadSocket)?;
        match state {
            SockState::Stream { peer_virtual, .. } => Ok(*peer_virtual),
            _ => Err(StatusCode::NotSupported),
        }
    }

    fn sendto(&mut self, socket_id: u32, addr: SockAddrBytes, data: &[u8]) -> BResult<u32> {
        // Auto-bind an unbound UDP socket on first sendto, matching
        // Winsock semantics where `sendto` on an unbound socket implicitly
        // binds an ephemeral port.
        let needs_bind = matches!(
            self.table.get(socket_id),
            Some(SockState::Fresh { typ: 2, .. })
        );
        if needs_bind {
            let af_zero = SockAddrBytes::v4([0, 0, 0, 0], 0);
            self.bind(socket_id, af_zero)?;
        }
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let socket = match state {
            SockState::Dgram { socket, .. } => socket,
            _ => return Err(StatusCode::NotSupported),
        };
        let requested = sockaddr_to_std(&addr).ok_or(StatusCode::AddrNotAvail)?;
        let target = self
            .translator
            .as_ref()
            .and_then(|t| t(requested))
            .unwrap_or(requested);
        let n = socket.send_to(data, target).map_err(map_io_err)?;
        Ok(n as u32)
    }

    fn recvfrom(&mut self, socket_id: u32, max: u32) -> BResult<(Vec<u8>, SockAddrBytes)> {
        let state = self.table.get_mut(socket_id).ok_or(StatusCode::BadSocket)?;
        let socket = match state {
            SockState::Dgram { socket, .. } => socket,
            _ => return Err(StatusCode::NotSupported),
        };
        let cap = (max as usize).min(psroot_netstack_proto::DATA_CAPACITY);
        let mut buf = vec![0u8; cap];
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                buf.truncate(n);
                let peer_v = match peer {
                    SocketAddr::V4(v) => SockAddrBytes::v4(v.ip().octets(), v.port()),
                    SocketAddr::V6(v) => SockAddrBytes::v6(v.ip().octets(), v.port(), 0, v.scope_id()),
                };
                Ok((buf, peer_v))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(StatusCode::WouldBlock),
            Err(e) => Err(map_io_err(e)),
        }
    }
}

/// Disable `SIO_UDP_CONNRESET` on a `UdpSocket`.
///
/// Windows delivers ICMP "port unreachable" from a previous datagram
/// as `WSAECONNRESET` on subsequent `recvfrom` calls. That's reasonable
/// for TCP-like semantics, but breaks classic datagram patterns where
/// the peer may have already closed its socket by the time we try to
/// receive a reply. Disabling this control puts the socket back into
/// plain BSD-style UDP behaviour.
#[cfg(windows)]
fn disable_udp_connreset(sock: &UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SOCKET};
    // SIO_UDP_CONNRESET = _WSAIOW(IOC_VENDOR, 12) = 0x9800000C.
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    let raw = sock.as_raw_socket() as SOCKET;
    let mut value: u32 = 0; // FALSE
    let mut returned: u32 = 0;
    unsafe {
        // Advisory: ignore the return code. On platforms that reject
        // the IOCTL (e.g. Wine) the socket simply keeps default
        // behaviour.
        WSAIoctl(
            raw,
            SIO_UDP_CONNRESET,
            &mut value as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
            core::ptr::null_mut(),
            0,
            &mut returned,
            core::ptr::null_mut(),
            None,
        );
    }
}

// ───────────────────────────── helpers ─────────────────────────────────

fn sockaddr_to_std(a: &SockAddrBytes) -> Option<SocketAddr> {
    match a.family {
        f if f == AF_INET_V => {
            let ip = Ipv4Addr::new(a.addr[0], a.addr[1], a.addr[2], a.addr[3]);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, a.port)))
        }
        f if f == AF_INET6_V => {
            let ip = Ipv6Addr::from(a.addr);
            Some(SocketAddr::V6(SocketAddrV6::new(ip, a.port, a.v6_flow, a.v6_scope)))
        }
        _ => None,
    }
}

fn map_io_err(e: std::io::Error) -> StatusCode {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => StatusCode::ConnRefused,
        ConnectionReset | ConnectionAborted | BrokenPipe => StatusCode::ConnReset,
        AddrInUse => StatusCode::AddrInUse,
        AddrNotAvailable => StatusCode::AddrNotAvail,
        WouldBlock => StatusCode::WouldBlock,
        _ => StatusCode::HostError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_rejects_non_tcp() {
        let mut b = NatBackend::new(Ipv4Addr::new(10, 88, 0, 2));
        // SOCK_RAW (3) \u2014 not supported. SOCK_STREAM(1) and
        // SOCK_DGRAM(2) are both accepted now that UDP is wired.
        assert_eq!(b.socket(AF_INET_V, 3, 0), Err(StatusCode::NotSupported));
    }

    #[test]
    fn udp_sendto_recvfrom_roundtrip() {
        // Two UDP sockets inside the same NatBackend: one sends, one
        // receives. The peer address on recv is the real (host) address
        // because the translator isn't set here.
        let mut b = NatBackend::new(Ipv4Addr::new(10, 88, 0, 2));
        let rx = b.socket(AF_INET_V, 2, 0).unwrap();
        b.bind(rx, SockAddrBytes::v4([10, 88, 0, 2], 0)).unwrap();
        let name = b.get_sock_name(rx).unwrap();
        let rx_port = name.port;
        assert_eq!(&name.addr[..4], &[10, 88, 0, 2]);

        let tx = b.socket(AF_INET_V, 2, 0).unwrap();
        // sendto to real loopback so the real UdpSocket can deliver it.
        // In the integration test with translator, this would be the
        // virtual IP and the translator would rewrite it.
        // Use a bespoke translator via a fresh backend for that case.
        // Here, short-circuit: target the rx port on 127.0.0.1 directly.
        let target = SockAddrBytes::v4([127, 0, 0, 1], rx_port);
        let n = b.sendto(tx, target, b"ping").unwrap();
        assert_eq!(n, 4);

        // Busy-wait for the datagram.
        let (got, _peer) = loop {
            match b.recvfrom(rx, 64) {
                Ok(v) if !v.0.is_empty() => break v,
                Ok(_) => std::thread::yield_now(),
                Err(StatusCode::WouldBlock) => std::thread::yield_now(),
                Err(e) => panic!("recvfrom: {:?}", e),
            }
        };
        assert_eq!(&got, b"ping");
    }

    #[test]
    fn socket_and_close() {
        let mut b = NatBackend::new(Ipv4Addr::new(10, 88, 0, 2));
        let id = b.socket(AF_INET_V, 1, 6).unwrap();
        assert!(id >= 1);
        b.close(id).unwrap();
        // Subsequent operations fail.
        assert_eq!(b.send(id, b"x"), Err(StatusCode::BadSocket));
    }

    #[test]
    fn listen_and_accept_loopback() {
        let mut b = NatBackend::new(Ipv4Addr::new(10, 88, 0, 2));
        let lid = b.socket(AF_INET_V, 1, 6).unwrap();
        b.bind(lid, SockAddrBytes::v4([10, 88, 0, 2], 8080)).unwrap();
        b.listen(lid, 16).unwrap();

        // Discover the real host port from getsockname (we exposed it).
        let name = b.get_sock_name(lid).unwrap();
        assert_eq!(name.family, AF_INET_V);
        assert_eq!(&name.addr[..4], &[10, 88, 0, 2]); // virtual IP
        // The reported port is the REAL bound port so connecting to it
        // works in this single-process test.
        let port = name.port;

        let client_thread = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"hello").unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"WORLD");
        });

        // Busy-accept (non-blocking under the hood).
        let (cid, _peer) = loop {
            match b.accept(lid) {
                Ok(v) => break v,
                Err(StatusCode::WouldBlock) => std::thread::yield_now(),
                Err(e) => panic!("accept error: {:?}", e),
            }
        };
        // Server reads 5 bytes, writes 5 back.
        let got = loop {
            match b.recv(cid, 64) {
                Ok(v) if !v.is_empty() => break v,
                Ok(_) => std::thread::yield_now(),
                Err(StatusCode::WouldBlock) => std::thread::yield_now(),
                Err(e) => panic!("recv: {:?}", e),
            }
        };
        assert_eq!(&got, b"hello");
        let n = b.send(cid, b"WORLD").unwrap();
        assert_eq!(n, 5);

        client_thread.join().unwrap();
    }
}
