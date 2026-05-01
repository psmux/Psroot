//! **Phase 2 end-to-end.**
//!
//! This is the canonical proof that the userland netstack actually
//! transparently intercepts unmodified Winsock code:
//!
//! 1. A real TCP echo server is spawned on `127.0.0.1:<real_port>`.
//! 2. The host daemon is started with the NAT backend and a virtual IP
//!    `10.88.0.7`.
//! 3. Winsock hooks are installed on this test binary's main executable.
//! 4. A worker thread then issues raw ws2_32 calls — `socket`,
//!    `connect` (to the virtual IP `10.88.0.7:real_port`), `send`,
//!    `recv`, `closesocket` — using `windows-sys` directly, with **no
//!    knowledge** of the netstack. It's exactly what an unmodified
//!    program would do.
//! 5. Assertions verify the payload round-tripped through the daemon
//!    and came back from the real echo server.
//!
//! The daemon thread is marked bypassed so its own real-Winsock usage
//! does not recurse through the hooks.

#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use psroot_netshim::{install_main_exe, Client};
use psroot_netstack_host::{Daemon, NatBackend};
use psroot_netstack_ipc::{shm::SharedMemory, Channel, ChannelLayout, ChannelSide};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, recv, send, socket, WSACleanup, WSAGetLastError, WSAStartup, AF_INET,
    INVALID_SOCKET, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN, SOCKET_ERROR, SOCK_STREAM, WSADATA,
};

fn unique_name(tag: &str) -> String {
    format!(
        "Local\\psroot-netshim-phase2-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn pair(tag: &str) -> (Channel, Channel) {
    let layout = ChannelLayout::new(32);
    let name = unique_name(tag);
    let host_shm = SharedMemory::create(&name, layout.total_size).unwrap();
    let host = Channel::create(host_shm, layout, ChannelSide::Host);
    let shim_shm = SharedMemory::open(&name, layout.total_size).unwrap();
    let shim = Channel::attach(shim_shm, layout, ChannelSide::Shim);
    (host, shim)
}

/// Starts a thread that accepts exactly one TCP connection, echoes
/// uppercase of what it receives, and closes. Returns the port.
fn spawn_echo_server(stop_after: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut remaining = stop_after;
        let mut buf = [0u8; 128];
        while remaining > 0 {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            let up: Vec<u8> = buf[..n].iter().map(|c| c.to_ascii_uppercase()).collect();
            s.write_all(&up).unwrap();
            remaining = remaining.saturating_sub(n);
        }
    });
    port
}

/// Start the host daemon on its own thread, with a bypass guard so its
/// own real-Winsock calls skip our hooks.
fn spawn_daemon(
    host_channel: Channel,
    virt: Ipv4Addr,
    real_port: u16,
) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let t = thread::spawn(move || {
        // Critical: the daemon uses std::net internally, which uses
        // Winsock. We don't want those calls to recurse through our
        // hooks. A single guard held for the daemon's lifetime pins the
        // bypass counter at >0 for the whole thread.
        let _g = psroot_netshim::state::BypassGuard::enter();
        // Translator: the container asks for the *virtual* IP 10.88.0.7.
        // The NAT backend rewrites that to 127.0.0.1 so the real echo
        // server (listening on loopback) receives the connection.
        let translator: psroot_netstack_host::nat::AddrTranslator =
            Box::new(move |addr: std::net::SocketAddr| {
                use std::net::{SocketAddr, SocketAddrV4};
                match addr {
                    SocketAddr::V4(v) if v.ip().octets() == virt.octets() => Some(
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, real_port)),
                    ),
                    _ => None,
                }
            });
        let backend = NatBackend::new(virt).with_translator(translator);
        Daemon::new(host_channel, backend, stop2).run().unwrap();
    });
    (stop, t)
}

/// Build a raw AF_INET SOCKADDR for the given virtual address + port.
fn make_sockaddr(ip: [u8; 4], port: u16) -> (SOCKADDR, i32) {
    let sin = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip),
            },
        },
        sin_zero: [0; 8],
    };
    // Safe: SOCKADDR_IN and SOCKADDR have compatible layouts at the
    // prefix and the callee only reads up to `namelen` bytes.
    let sa: SOCKADDR = unsafe { core::mem::transmute(sin) };
    (sa, core::mem::size_of::<SOCKADDR_IN>() as i32)
}

/// The full Phase-2 test.
#[test]
fn raw_winsock_round_trip_through_hooks() {
    // ─── 1. Real echo server on host ────────────────────────────────
    let real_port = spawn_echo_server(16);

    // ─── 2. Channel + daemon with NAT backend on virtual IP 10.88.0.7
    // The daemon is also given a translator that rewrites destinations
    // matching 10.88.0.7 → 127.0.0.1:real_port, so the container's view
    // is genuinely "I connected to my virtual peer 10.88.0.7" while the
    // real socket goes to the echo server.
    let virt = Ipv4Addr::new(10, 88, 0, 7);
    let (host_ch, shim_ch) = pair("rt");
    let (stop, daemon_thread) = spawn_daemon(host_ch, virt, real_port);

    // ─── 3. Install hooks in this process. The HookGuard restores the
    // IAT on drop, so even a panic below won't leave the process with
    // broken Winsock imports.
    let client = Client::new(shim_ch);
    let _hook_guard = unsafe { install_main_exe(client) }.expect("hooks install");

    // ─── 4. Raw Winsock client on a worker thread. This thread has NO
    // bypass flag set — every ws2_32 call it makes is intercepted by
    // the netshim hooks.
    let worker = thread::spawn(move || -> Result<Vec<u8>, i32> {
        unsafe {
            let mut wsa: WSADATA = core::mem::zeroed();
            let rc = WSAStartup(0x0202, &mut wsa);
            if rc != 0 {
                return Err(rc);
            }

            let s = socket(AF_INET as i32, SOCK_STREAM as i32, 0);
            if s == INVALID_SOCKET {
                return Err(WSAGetLastError());
            }

            // Connect to the **virtual** container IP 10.88.0.7. The
            // daemon's address translator rewrites that to the real
            // echo server on 127.0.0.1:real_port. If any part of the
            // hook chain leaked the call to the real OS stack,
            // connect() would fail (nothing listens on 10.88.0.7 on
            // the dev machine) — so a successful round-trip is proof
            // the hooks intercepted every call.
            let (sa, salen) = make_sockaddr([10, 88, 0, 7], real_port);
            let rc = connect(s, &sa as *const _, salen);
            if rc == SOCKET_ERROR {
                let e = WSAGetLastError();
                closesocket(s);
                return Err(e);
            }

            let payload = b"hello via netshim";
            let sent = send(s, payload.as_ptr(), payload.len() as i32, 0);
            if sent == SOCKET_ERROR {
                let e = WSAGetLastError();
                closesocket(s);
                return Err(e);
            }

            // Read back. recv returns up to `len` bytes; loop until we
            // have the full reply.
            let mut reply = Vec::new();
            let mut buf = [0u8; 64];
            while reply.len() < payload.len() {
                let n = recv(s, buf.as_mut_ptr(), buf.len() as i32, 0);
                if n == SOCKET_ERROR {
                    let e = WSAGetLastError();
                    closesocket(s);
                    return Err(e);
                }
                if n == 0 {
                    break;
                }
                reply.extend_from_slice(&buf[..n as usize]);
            }

            closesocket(s);
            WSACleanup();
            Ok(reply)
        }
    });

    let received = worker
        .join()
        .expect("worker panicked")
        .unwrap_or_else(|e| panic!("winsock error: {}", e));

    assert_eq!(
        received,
        b"HELLO VIA NETSHIM".to_vec(),
        "payload must round-trip through hooks + daemon + echo server"
    );

    // ─── 5. Stop daemon cleanly.
    stop.store(true, Ordering::Release);
    // Give the daemon thread its 100ms poll period to notice.
    thread::sleep(Duration::from_millis(200));
    daemon_thread.join().unwrap();
}
