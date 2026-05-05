//! Test-child binary for the Phase 3 cross-process injection E2E test.
//!
//! This binary is spawned *suspended* by the parent test, which then
//! injects `psroot-netshim.dll`. The DLL's `DllMain` opens the host SHM
//! (named via the `PSROOT_NS_NAME` + `PSROOT_NS_SIZE` env vars the
//! parent set), installs IAT hooks, and only then do the raw Winsock
//! calls below fire — which means every one of them must have been
//! routed through our hook stack, not the kernel TCP/IP stack.
//!
//! Exit-code scheme:
//!
//! | Code | Meaning                                                  |
//! | ---- | -------------------------------------------------------- |
//! |    0 | Success — expected reply bytes received.                 |
//! |   10 | `WSAStartup` failed.                                     |
//! |   11 | `socket()` returned INVALID_SOCKET.                      |
//! |   12 | Environment variable `PSROOT_TEST_PORT` missing/invalid. |
//! |   13 | `connect()` returned SOCKET_ERROR.                       |
//! |   14 | `send()` didn't send the expected 5 bytes.               |
//! |   15 | `recv()` returned ≤ 0.                                   |
//! |   16 | Response bytes did not match expected payload.           |
//!
//! The parent asserts exit code 0.

#![cfg(windows)]

use std::mem::zeroed;

use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, recv, send, socket, WSACleanup, WSAStartup, AF_INET, INVALID_SOCKET,
    IN_ADDR, SOCKADDR, SOCKADDR_IN, SOCKET_ERROR, SOCK_STREAM, WSADATA,
};

fn main() {
    // Give the parent's injector thread time to (1) CreateRemoteThread
    // LoadLibraryW → (2) DllMain spawns init thread → (3) init thread
    // opens SHM + IAT-patches this process. 800 ms is comfortable on a
    // cold machine; the parent test budget is several seconds.
    std::thread::sleep(std::time::Duration::from_millis(800));

    let port: u16 = match std::env::var("PSROOT_TEST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(p) => p,
        None => std::process::exit(12),
    };

    unsafe {
        let mut wsa: WSADATA = zeroed();
        if WSAStartup(0x0202, &mut wsa) != 0 {
            std::process::exit(10);
        }

        let s = socket(AF_INET as i32, SOCK_STREAM as i32, 0);
        if s == INVALID_SOCKET {
            std::process::exit(11);
        }

        // Connect to virtual container IP 10.88.0.11:<port>. If the
        // hooks did NOT install, this would fail (no route on host).
        let mut sa_in: SOCKADDR_IN = zeroed();
        sa_in.sin_family = AF_INET;
        sa_in.sin_port = port.to_be();
        let ip: IN_ADDR = std::mem::transmute::<[u8; 4], IN_ADDR>([10, 88, 0, 11]);
        sa_in.sin_addr = ip;

        if connect(
            s,
            &sa_in as *const _ as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        ) == SOCKET_ERROR
        {
            std::process::exit(13);
        }

        let msg: &[u8] = b"hello";
        let sent = send(s, msg.as_ptr(), msg.len() as i32, 0);
        if sent != msg.len() as i32 {
            std::process::exit(14);
        }

        let mut buf = [0u8; 32];
        // Small allowance for the echo server to respond.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let n = recv(s, buf.as_mut_ptr(), buf.len() as i32, 0);
        if n <= 0 {
            std::process::exit(15);
        }
        if &buf[..n as usize] != b"HELLO" {
            std::process::exit(16);
        }

        closesocket(s);
        WSACleanup();
    }
    std::process::exit(0);
}
