//! Phase 3 cross-process injection E2E test.
//!
//! # What this proves
//!
//! 1. `psroot-netshim` builds as a `cdylib` (`.dll`) on the developer
//!    machine using only stable Rust + windows-sys.
//! 2. `psroot-netinject::inject_dll` can load that DLL into a spawned
//!    child process via `CreateRemoteThread(LoadLibraryW)`.
//! 3. Once loaded, the DLL's `DllMain` reads `PSROOT_NS_NAME` +
//!    `PSROOT_NS_SIZE` from the child's environment, attaches to the
//!    named shared memory the parent just created, and IAT-patches the
//!    child's main executable.
//! 4. The child — which has no Rust-level awareness of psroot — makes
//!    raw `windows-sys` Winsock calls targeting a *virtual* container
//!    IP (`10.88.0.11`). Because the injected hooks rewrite those calls
//!    to SHM messages, the host daemon's NAT backend receives them,
//!    translates the virtual address to `127.0.0.1:<echo_port>` via
//!    `AddrTranslator`, connects a real TCP socket, and echoes data
//!    back. The child observes the expected uppercased payload and
//!    exits with status 0.
//!
//! Anything else — exit codes 10..=16 — would mean some link in the
//! pipeline failed silently and the test reports which one.
//!
//! # What is intentionally NOT tested here
//!
//! * AppContainer integrity-level crossing (requires Detours).
//! * Injection into a suspended/pre-resume image (requires
//!   `CreateProcessW` with `CREATE_SUSPENDED`; the current test relies
//!   on the child sleeping 800 ms to give the injector a head start).
//! * IOCP / overlapped I/O (Phase 3 roadmap).

#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use psroot_netstack_host::nat::NatBackend;
use psroot_netstack_host::Daemon;
use psroot_netstack_ipc::{Channel, ChannelLayout, ChannelSide};

/// The DLL that the child will load. Cargo builds it in the same
/// `target/<profile>/` directory as the test binaries; we compute its
/// path from `std::env::current_exe()` (tests live in
/// `target/<profile>/deps/` so the DLL is one directory up).
fn netshim_dll_path() -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    // .../target/<profile>/deps/<test>.exe
    p.pop(); // deps
    p.pop(); // <profile>
    p.push("psroot_netshim.dll");
    assert!(
        p.exists(),
        "netshim DLL not found at {} -- did cargo build the cdylib?",
        p.display()
    );
    p
}

fn test_child_path() -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for each [[bin]] in the same crate.
    PathBuf::from(env!("CARGO_BIN_EXE_psroot-netshim-testchild"))
}

/// Launch a one-shot loopback TCP echo server that uppercases whatever
/// it reads. Returns the listening port.
fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind echo");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).expect("read");
        let up: Vec<u8> = buf[..n].iter().map(|c| c.to_ascii_uppercase()).collect();
        s.write_all(&up).expect("write");
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
        // Daemon runs inside THIS test process, so its own std::net
        // calls go through the real OS stack (we have no hooks
        // installed in the parent). No BypassGuard needed here.
        let translator: psroot_netstack_host::nat::AddrTranslator =
            Box::new(move |addr: SocketAddr| match addr {
                SocketAddr::V4(v) if v.ip().octets() == virt.octets() => Some(
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, real_port)),
                ),
                _ => None,
            });
        let backend = NatBackend::new(virt).with_translator(translator);
        Daemon::new(host_channel, backend, stop2).run().unwrap();
    });
    (stop, t)
}

#[test]
fn cross_process_inject_round_trip() {
    // ── 1. Locate build artifacts.
    let dll = netshim_dll_path();
    let child_exe = test_child_path();

    // ── 2. Real echo server. The child will believe it's talking to
    // 10.88.0.11:<port>, but everything actually arrives here.
    let real_port = spawn_echo_server();

    // ── 3. Create the SHM channel the injected DLL will attach to.
    let layout = ChannelLayout::new(psroot_netstack_proto::DEFAULT_RING_SLOTS);
    let shm_name = format!(
        "Local\\psroot-ns-inject-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let host_shm =
        psroot_netstack_ipc::shm::SharedMemory::create(&shm_name, layout.total_size)
            .expect("create SHM");
    let host_channel = Channel::create(host_shm, layout, ChannelSide::Host);

    // ── 4. Start the daemon BEFORE spawning the child so the daemon
    // is already in its recv loop by the time hooks start firing.
    let virt = Ipv4Addr::new(10, 88, 0, 11);
    let (stop, daemon_t) = spawn_daemon(host_channel, virt, real_port);
    thread::sleep(Duration::from_millis(50));

    // ── 5. Spawn the test-child process with the env vars the
    // DllMain init thread needs.
    let mut child = Command::new(&child_exe)
        .env("PSROOT_NS_NAME", &shm_name)
        .env("PSROOT_NS_SIZE", layout.total_size.to_string())
        .env("PSROOT_TEST_PORT", real_port.to_string())
        .spawn()
        .expect("spawn test child");

    // ── 6. Inject the netshim DLL into the running child. The child
    // sleeps 800 ms at startup specifically to give us this window
    // before it reaches its raw Winsock calls.
    let process_handle = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    unsafe {
        psroot_netinject::inject_dll(process_handle, &dll).expect("inject_dll");
    }

    // ── 7. Wait for the child to complete its round-trip and exit.
    let status = child.wait().expect("wait child");
    assert!(
        status.success(),
        "test child exited with code {:?} (non-zero means some link in the hook->SHM->daemon->NAT chain failed; see bin/ns_testchild.rs for the exit-code legend)",
        status.code()
    );

    // ── 8. Shut the daemon down.
    stop.store(true, std::sync::atomic::Ordering::Release);
    thread::sleep(Duration::from_millis(200));
    daemon_t.join().unwrap();
}
