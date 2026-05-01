//! Phase 3 UDP end-to-end test.
//!
//! Drives raw `windows-sys` Winsock UDP (`sendto` / `recvfrom`) against
//! a virtual container IP; asserts the datagram round-trips through the
//! IAT hooks → daemon → `NatBackend::sendto` → real loopback echo server
//! → `recvfrom`.

#![cfg(windows)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use psroot_netstack_ipc::{Channel, ChannelLayout, ChannelSide};
use psroot_netstack_host::nat::NatBackend;
use psroot_netstack_host::Daemon;
use windows_sys::Win32::Networking::WinSock::{
    closesocket, recvfrom, sendto, socket, WSACleanup, WSAStartup, AF_INET, INVALID_SOCKET,
    SOCKADDR, SOCKADDR_IN, SOCK_DGRAM, WSADATA,
};

fn pair(tag: &str) -> (Channel, Channel) {
    let layout = ChannelLayout::new(16);
    let name = format!(
        "Local\\psroot-ns-udp-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let host_shm =
        psroot_netstack_ipc::shm::SharedMemory::create(&name, layout.total_size).unwrap();
    let host = Channel::create(host_shm, layout, ChannelSide::Host);
    let shim_shm =
        psroot_netstack_ipc::shm::SharedMemory::open(&name, layout.total_size).unwrap();
    let shim = Channel::attach(shim_shm, layout, ChannelSide::Shim);
    (host, shim)
}

/// Start a real loopback UDP "echo-uppercase" server. Returns its port.
fn spawn_udp_echo() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Generous read timeout so the echo server stays alive long enough
    // to receive the test's datagram even on slow CI where the IAT
    // patch + WSAStartup path takes several seconds before the first
    // hooked sendto fires.
    sock.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 256];
        // Serve datagrams in a loop; the socket is dropped when the
        // test process exits.
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    let upper: Vec<u8> =
                        buf[..n].iter().map(|c| c.to_ascii_uppercase()).collect();
                    let _ = sock.send_to(&upper, peer);
                }
                Err(_) => break,
            }
        }
    });
    port
}

fn spawn_daemon(
    host_channel: Channel,
    virt: Ipv4Addr,
    real_port: u16,
) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let t = thread::spawn(move || {
        // Daemon's own UdpSocket usage must skip our hooks.
        let _g = psroot_netshim::state::BypassGuard::enter();
        let translator: psroot_netstack_host::nat::AddrTranslator =
            Box::new(move |addr: SocketAddr| match addr {
                SocketAddr::V4(v) if v.ip().octets() == virt.octets() => Some(
                    SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, real_port)),
                ),
                _ => None,
            });
        let backend = NatBackend::new(virt).with_translator(translator);
        Daemon::new(host_channel, backend, stop2).run().unwrap();
    });
    (stop, t)
}

unsafe fn make_sockaddr_in(ip: [u8; 4], port: u16) -> (SOCKADDR_IN, i32) {
    let sin_addr = std::mem::transmute::<[u8; 4], windows_sys::Win32::Networking::WinSock::IN_ADDR>(ip);
    let sa = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr,
        sin_zero: [0; 8],
    };
    (sa, std::mem::size_of::<SOCKADDR_IN>() as i32)
}

#[test]
fn raw_winsock_udp_round_trip_through_hooks() {
    let real_port = spawn_udp_echo();
    let virt = Ipv4Addr::new(10, 88, 0, 9);
    let (host_ch, shim_ch) = pair("udp");
    let (stop, daemon_t) = spawn_daemon(host_ch, virt, real_port);

    // Give the daemon a moment to enter its recv loop.
    thread::sleep(Duration::from_millis(50));

    let client = psroot_netshim::Client::new(shim_ch);
    let guard = unsafe { psroot_netshim::install_main_exe(client) }.expect("install hooks");

    let tx = thread::spawn(move || unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        let rc = WSAStartup(0x0202, &mut wsa);
        assert_eq!(rc, 0, "WSAStartup");

        let s = socket(AF_INET as i32, SOCK_DGRAM as i32, 0);
        assert!(s != INVALID_SOCKET, "socket");

        // Send to virtual IP 10.88.0.9 — translator rewrites to 127.0.0.1.
        let (to_addr, tolen) = make_sockaddr_in([10, 88, 0, 9], real_port);
        let sent = sendto(
            s,
            b"ping via udp".as_ptr(),
            12,
            0,
            &to_addr as *const _ as *const SOCKADDR,
            tolen,
        );
        assert_eq!(sent, 12, "sendto returned {sent}");

        // Give the echo round-trip time.
        thread::sleep(Duration::from_millis(100));

        let mut buf = [0u8; 64];
        let mut from: SOCKADDR_IN = std::mem::zeroed();
        let mut fromlen: i32 = std::mem::size_of::<SOCKADDR_IN>() as i32;
        let n = recvfrom(
            s,
            buf.as_mut_ptr(),
            buf.len() as i32,
            0,
            &mut from as *mut _ as *mut SOCKADDR,
            &mut fromlen,
        );
        assert!(n > 0, "recvfrom returned {n}");
        assert_eq!(&buf[..n as usize], b"PING VIA UDP");

        closesocket(s);
        WSACleanup();
    });

    tx.join().expect("tx thread");
    drop(guard);

    stop.store(true, std::sync::atomic::Ordering::Release);
    // Nudge the daemon's recv loop out of its 100ms park.
    thread::sleep(Duration::from_millis(200));
    daemon_t.join().unwrap();
}
