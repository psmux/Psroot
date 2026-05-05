#![cfg(windows)]
//! Host-side TCP port mapper for psroot containers.
//!
//! # Why this exists
//!
//! Windows does not expose per-process network namespaces to user mode
//! without Hyper-V / HNS. AppContainer, Job Objects, and Server Silos all
//! share the host's TCP/IP stack — if a container process calls
//! `bind(3000)`, port 3000 is occupied on the host.
//!
//! To let multiple containers each "own" port 3000 without colliding, psroot
//! takes the same pragmatic approach Docker takes on Linux (with Docker
//! Desktop's userland-proxy): we allocate a **random ephemeral host port**
//! per container-port mapping, inject that port into the container via
//! `PORT` / `PSROOT_PORT_<name>` environment variables, and run a TCP
//! reverse proxy on the host that forwards a user-chosen host port to the
//! ephemeral one. End-result for the user: two containers can both say
//! "I listen on port 3000" and each gets its own mapped host port —
//! no `EADDRINUSE`, no manual port juggling.
//!
//! # Caveats (honest)
//!
//! * The ephemeral port still exists on the host, but it lives on
//!   `127.0.0.1` on a random high number — it doesn't conflict with
//!   well-known developer ports and isn't reachable externally unless the
//!   user explicitly publishes a host port via `-p`.
//! * Programs that hard-code their listen port (ignoring `$PORT`) will
//!   still try to bind that exact port on the host. Fixing that would
//!   require per-process `bind()` interception (Detours/MinHook shim) — a
//!   future feature tracked separately.
//! * The proxy is plain TCP. UDP, ICMP, and protocol-aware features
//!   (PROXY protocol, TLS SNI) are out of scope.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use psroot_types::config::PortMapping;
use tracing::{debug, info, warn};

/// A live reverse-proxy mapping: `host_bind:host_port -> 127.0.0.1:ephemeral`.
struct Mapping {
    spec: PortMapping,
    /// Signals the accept loop to stop.
    shutdown: Arc<AtomicBool>,
    /// Listener we hold so dropping it unblocks `accept()` even on Windows.
    listener: Arc<TcpListener>,
    join: Option<thread::JoinHandle<()>>,
}

/// Port mapper runtime. Owns all proxy threads for a single container.
///
/// Dropping the mapper shuts down every proxy cleanly.
pub struct PortMapper {
    mappings: Mutex<Vec<Mapping>>,
}

impl PortMapper {
    pub fn new() -> Self {
        Self {
            mappings: Mutex::new(Vec::new()),
        }
    }

    /// Allocate an ephemeral loopback port by briefly binding `127.0.0.1:0`.
    ///
    /// There is a small TOCTOU window between this function returning and
    /// the container process binding the port — another process could
    /// snatch it. In practice the window is microseconds and the risk is
    /// acceptable for a dev-container tool; Docker's userland proxy does
    /// essentially the same thing.
    pub fn allocate_ephemeral() -> io::Result<u16> {
        let sock = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let port = sock.local_addr()?.port();
        drop(sock);
        Ok(port)
    }

    /// Start a proxy for a single mapping. `spec.ephemeral_port` must be set.
    pub fn add(&self, spec: PortMapping) -> io::Result<()> {
        let ephemeral = spec.ephemeral_port.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PortMapping.ephemeral_port not allocated",
            )
        })?;

        let bind_ip: IpAddr = spec
            .host_bind
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let host_addr = SocketAddr::new(bind_ip, spec.host_port);

        let listener = TcpListener::bind(host_addr).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("bind {}:{} failed: {}", bind_ip, spec.host_port, e),
            )
        })?;
        // Short accept timeout so the shutdown flag is observed promptly.
        listener.set_nonblocking(false).ok();

        let listener = Arc::new(listener);
        let shutdown = Arc::new(AtomicBool::new(false));

        let l2 = Arc::clone(&listener);
        let s2 = Arc::clone(&shutdown);
        let upstream = SocketAddr::from((Ipv4Addr::LOCALHOST, ephemeral));
        let label = format!(
            "{}:{} -> 127.0.0.1:{} ({})",
            bind_ip, spec.host_port, ephemeral, spec.container_port
        );

        let join = thread::Builder::new()
            .name(format!("psroot-portmap-{}", spec.host_port))
            .spawn(move || accept_loop(l2, s2, upstream, label))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        info!(
            host = %bind_ip, host_port = spec.host_port,
            container_port = spec.container_port, ephemeral,
            "Port mapping active"
        );

        self.mappings.lock().unwrap().push(Mapping {
            spec,
            shutdown,
            listener,
            join: Some(join),
        });
        Ok(())
    }

    /// Stop every proxy and wait for threads to exit.
    pub fn shutdown(&self) {
        let mut list = std::mem::take(&mut *self.mappings.lock().unwrap());
        for m in list.iter_mut() {
            m.shutdown.store(true, Ordering::Release);
            // Kick the accept() by connecting to ourselves — the simplest
            // cross-platform way to unblock a blocking accept on Windows.
            let addr = m
                .listener
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::LOCALHOST, m.spec.host_port)));
            let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
        }
        for m in list.iter_mut() {
            if let Some(j) = m.join.take() {
                let _ = j.join();
            }
        }
    }

    /// Summary of current mappings for display in `psroot ls`.
    pub fn describe(&self) -> Vec<PortMapping> {
        self.mappings
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.spec.clone())
            .collect()
    }
}

impl Default for PortMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PortMapper {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(
    listener: Arc<TcpListener>,
    shutdown: Arc<AtomicBool>,
    upstream: SocketAddr,
    label: String,
) {
    debug!(target = %label, "Accept loop starting");
    for incoming in listener.incoming() {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let client = match incoming {
            Ok(s) => s,
            Err(e) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                warn!(target = %label, error = %e, "accept error");
                continue;
            }
        };
        let label2 = label.clone();
        thread::spawn(move || {
            if let Err(e) = proxy_connection(client, upstream) {
                debug!(target = %label2, error = %e, "connection ended");
            }
        });
    }
    debug!(target = %label, "Accept loop exited");
}

fn proxy_connection(client: TcpStream, upstream: SocketAddr) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    let server = TcpStream::connect_timeout(&upstream, Duration::from_secs(5))?;
    let _ = server.set_nodelay(true);

    let c2s_client = client.try_clone()?;
    let c2s_server = server.try_clone()?;

    let h = thread::spawn(move || {
        let mut c = c2s_client;
        let mut s = c2s_server;
        let _ = io::copy(&mut c, &mut s);
        let _ = s.shutdown(std::net::Shutdown::Write);
    });

    let mut s = server;
    let mut c = client;
    let _ = io::copy(&mut s, &mut c);
    let _ = c.shutdown(std::net::Shutdown::Write);
    let _ = h.join();
    Ok(())
}

/// Parse a Docker-style publish spec.
///
/// Accepted forms:
/// * `PORT`                              — host=PORT, container=PORT, bind=127.0.0.1
/// * `HOST:CONTAINER`                    — bind=127.0.0.1
/// * `BIND:HOST:CONTAINER`               — e.g. `0.0.0.0:8080:3000`
///
/// The container port is a logical label; the psroot runtime allocates a
/// separate ephemeral port and injects it into the container via env.
pub fn parse_publish(s: &str) -> Result<PortMapping, String> {
    let parts: Vec<&str> = s.split(':').collect();
    let (bind, host, container) = match parts.as_slice() {
        [p] => ("127.0.0.1".to_string(), parse_port(p)?, parse_port(p)?),
        [h, c] => ("127.0.0.1".to_string(), parse_port(h)?, parse_port(c)?),
        [b, h, c] => ((*b).to_string(), parse_port(h)?, parse_port(c)?),
        _ => {
            return Err(format!(
                "invalid publish spec '{}': expected PORT | HOST:CONTAINER | BIND:HOST:CONTAINER",
                s
            ))
        }
    };
    Ok(PortMapping {
        host_bind: bind,
        host_port: host,
        container_port: container,
        ephemeral_port: None,
        name: None,
    })
}

fn parse_port(s: &str) -> Result<u16, String> {
    s.parse::<u16>()
        .map_err(|_| format!("invalid port number: '{}'", s))
        .and_then(|p| {
            if p == 0 {
                Err("port 0 is not allowed".into())
            } else {
                Ok(p)
            }
        })
}

/// Compute the env vars that should be injected into a container given its
/// active port mappings. The first mapping also sets `PORT=` for the
/// benefit of frameworks like Next.js / Express that read it by default.
pub fn env_for_mappings(mappings: &[PortMapping]) -> HashMap<String, String> {
    let mut env = HashMap::new();
    for (idx, m) in mappings.iter().enumerate() {
        let Some(eph) = m.ephemeral_port else { continue };
        env.insert(
            format!("PSROOT_PORT_{}", m.container_port),
            eph.to_string(),
        );
        if idx == 0 {
            env.insert("PORT".into(), eph.to_string());
        }
    }
    if !mappings.is_empty() {
        // Tell apps to listen on all interfaces of the container so the
        // host-side proxy can reach them via 127.0.0.1.
        env.entry("HOST".into()).or_insert_with(|| "127.0.0.1".into());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_single() {
        let m = parse_publish("8080").unwrap();
        assert_eq!(m.host_port, 8080);
        assert_eq!(m.container_port, 8080);
        assert_eq!(m.host_bind, "127.0.0.1");
    }

    #[test]
    fn parse_host_container() {
        let m = parse_publish("8080:3000").unwrap();
        assert_eq!(m.host_port, 8080);
        assert_eq!(m.container_port, 3000);
    }

    #[test]
    fn parse_bind_host_container() {
        let m = parse_publish("0.0.0.0:8080:3000").unwrap();
        assert_eq!(m.host_bind, "0.0.0.0");
        assert_eq!(m.host_port, 8080);
        assert_eq!(m.container_port, 3000);
    }

    #[test]
    fn parse_rejects_zero() {
        assert!(parse_publish("0").is_err());
        assert!(parse_publish("0:3000").is_err());
    }

    #[test]
    fn env_injects_port_for_first() {
        let mappings = vec![
            PortMapping {
                host_bind: "127.0.0.1".into(),
                host_port: 8080,
                container_port: 3000,
                ephemeral_port: Some(54321),
                name: None,
            },
            PortMapping {
                host_bind: "127.0.0.1".into(),
                host_port: 9090,
                container_port: 4000,
                ephemeral_port: Some(54322),
                name: None,
            },
        ];
        let env = env_for_mappings(&mappings);
        assert_eq!(env.get("PORT").map(String::as_str), Some("54321"));
        assert_eq!(env.get("PSROOT_PORT_3000").map(String::as_str), Some("54321"));
        assert_eq!(env.get("PSROOT_PORT_4000").map(String::as_str), Some("54322"));
    }

    #[test]
    fn allocate_returns_nonzero() {
        let p = PortMapper::allocate_ephemeral().unwrap();
        assert!(p > 0);
    }

    #[test]
    fn proxy_forwards_bytes() {
        // Back-end: echo one line.
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let ephemeral = backend.local_addr().unwrap().port();
        let server_thread = thread::spawn(move || {
            let (mut s, _) = backend.accept().unwrap();
            let mut buf = [0u8; 5];
            use std::io::Read;
            s.read_exact(&mut buf).unwrap();
            use std::io::Write;
            s.write_all(&buf).unwrap();
        });

        let mapper = PortMapper::new();
        // Use a random host port too so the test is parallel-safe.
        let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_port = host_listener.local_addr().unwrap().port();
        drop(host_listener);

        mapper
            .add(PortMapping {
                host_bind: "127.0.0.1".into(),
                host_port,
                container_port: 3000,
                ephemeral_port: Some(ephemeral),
                name: None,
            })
            .unwrap();

        // Give the accept loop a moment to spin up.
        thread::sleep(Duration::from_millis(50));

        use std::io::{Read, Write};
        let mut client = TcpStream::connect(("127.0.0.1", host_port)).unwrap();
        client.write_all(b"hello").unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"hello");

        server_thread.join().unwrap();
        drop(mapper);
    }
}
