//! End-to-end test: [`psroot_netshim::Client`] ↔ shared-memory channel ↔
//! [`psroot_netstack_host::Daemon`] with the NAT backend.
//!
//! This is the closest we can get in Phase 1 to what the real injected
//! shim will do in Phase 2. We skip the DLL injection machinery; the
//! request/reply protocol is identical.

#![cfg(windows)]

use std::net::{Ipv4Addr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use psroot_netshim::Client;
use psroot_netstack_host::{Daemon, NatBackend};
use psroot_netstack_ipc::{shm::SharedMemory, Channel, ChannelLayout, ChannelSide};
use psroot_netstack_proto::{SockAddrBytes, AF_INET_V};

fn unique_name() -> String {
    format!(
        "Local\\psroot-netshim-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn pair() -> (Channel, Channel) {
    let layout = ChannelLayout::new(32);
    let name = unique_name();
    let host_shm = SharedMemory::create(&name, layout.total_size).unwrap();
    let host = Channel::create(host_shm, layout, ChannelSide::Host);
    let shim_shm = SharedMemory::open(&name, layout.total_size).unwrap();
    let shim = Channel::attach(shim_shm, layout, ChannelSide::Shim);
    (host, shim)
}

fn spawn_daemon() -> (Arc<AtomicBool>, std::thread::JoinHandle<()>, Client) {
    let (host, shim) = pair();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let backend = NatBackend::new(Ipv4Addr::new(10, 88, 0, 7));
    let daemon = Daemon::new(host, backend, stop);
    let t = std::thread::spawn(move || daemon.run().unwrap());
    (stop2, t, Client::new(shim))
}

#[test]
fn hello_handshake() {
    let (stop, t, client) = spawn_daemon();
    let version = client.hello().unwrap();
    assert_eq!(version, 1);
    stop.store(true, Ordering::Release);
    t.join().unwrap();
}

#[test]
fn socket_lifecycle() {
    let (stop, t, client) = spawn_daemon();
    let s = client.socket(AF_INET_V, 1, 6).unwrap();
    assert!(s >= 1);
    // getsockname before bind/connect returns 0.0.0.0:0.
    let name = client.getsockname(s).unwrap();
    assert_eq!(name.family, AF_INET_V);
    assert_eq!(&name.addr[..4], &[0, 0, 0, 0]);
    client.close(s).unwrap();
    stop.store(true, Ordering::Release);
    t.join().unwrap();
}

#[test]
fn listen_accept_echo_roundtrip() {
    let (stop, t, client) = spawn_daemon();

    let lid = client.socket(AF_INET_V, 1, 6).unwrap();
    client
        .bind(lid, SockAddrBytes::v4([10, 88, 0, 7], 0))
        .unwrap();
    client.listen(lid, 16).unwrap();

    // getsockname reports virtual IP but the real host port, which is
    // what we connect to below (single-process test).
    let name = client.getsockname(lid).unwrap();
    assert_eq!(&name.addr[..4], &[10, 88, 0, 7]);
    let port = name.port;

    // External "client" speaks directly to the real bound port.
    let producer = std::thread::spawn(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        use std::io::{Read, Write};
        s.write_all(b"ping-over-netstack").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"PONG");
    });

    // Accept via the shim client — busy-loop because the daemon uses
    // non-blocking accept under the hood.
    let (connid, _peer) = loop {
        match client.accept(lid) {
            Ok(v) => break v,
            Err(psroot_netshim::ClientError::Status(
                psroot_netstack_proto::StatusCode::WouldBlock,
            )) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => panic!("accept: {:?}", e),
        }
    };

    // Server reads 18 bytes.
    let mut got = Vec::new();
    while got.len() < 18 {
        match client.recv(connid, 64) {
            Ok(v) if v.is_empty() => std::thread::sleep(Duration::from_millis(5)),
            Ok(v) => got.extend_from_slice(&v),
            Err(psroot_netshim::ClientError::Status(
                psroot_netstack_proto::StatusCode::WouldBlock,
            )) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => panic!("recv: {:?}", e),
        }
    }
    assert_eq!(&got, b"ping-over-netstack");

    let n = client.send(connid, b"PONG").unwrap();
    assert_eq!(n, 4);
    client.close(connid).unwrap();

    producer.join().unwrap();

    client.close(lid).unwrap();
    stop.store(true, Ordering::Release);
    t.join().unwrap();
}
