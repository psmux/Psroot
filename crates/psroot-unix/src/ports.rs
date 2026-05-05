//! Host-side TCP reverse proxy for `-p HOST:CONTAINER` port mappings.
//!
//! The container runs on a private loopback alias (when root) or an
//! unprivileged ephemeral port (otherwise). The proxy bridges
//! `host_bind:host_port` to that backing endpoint.
//!
//! Implementation is a small blocking thread per mapping — Psroot port
//! mappings are typically a handful per container, not thousands.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use crate::Result;

/// Spawn a forwarder. Returns when the listener fails to bind.
pub fn spawn_forwarder(host_addr: SocketAddr, backend: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(host_addr)?;
    let backend = Arc::new(backend);
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(client) = incoming else { continue; };
            let backend = backend.clone();
            thread::spawn(move || {
                if let Ok(server) = TcpStream::connect(*backend) {
                    let _ = pump(client, server);
                }
            });
        }
    });
    Ok(())
}

fn pump(a: TcpStream, b: TcpStream) -> std::io::Result<()> {
    let a2 = a.try_clone()?;
    let b2 = b.try_clone()?;
    let t1 = thread::spawn(move || copy(a, b2));
    let _ = copy(b, a2);
    let _ = t1.join();
    Ok(())
}

fn copy(mut from: TcpStream, mut to: TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 { let _ = to.shutdown(std::net::Shutdown::Write); return Ok(()); }
        to.write_all(&buf[..n])?;
    }
}
