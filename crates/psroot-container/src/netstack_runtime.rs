//! Phase 3 glue: spin up a per-container userland network daemon and
//! inject the Winsock shim DLL into the container's init process.
//!
//! This is the container-side counterpart of [`psroot_netshim`] and
//! [`psroot_netinject`]. Given a suspended child process handle, it:
//!
//! 1. Creates a named shared-memory channel large enough for the
//!    default wire protocol layout.
//! 2. Spawns the NAT backend daemon on a background thread, listening
//!    on the host side of the channel.
//! 3. Hands back env vars (`PSROOT_NS_NAME`, `PSROOT_NS_SIZE`) that the
//!    caller injects into the child's environment *before*
//!    `CreateProcessW`.
//! 4. Once the child exists (even while suspended), `inject_into`
//!    `LoadLibraryW`-injects the shim DLL so its `DllMain` attaches to
//!    the same SHM and IAT-patches the child's Winsock imports.
//!
//! The runtime is parked on the [`Container`](crate::Container) for the
//! lifetime of the container and torn down on drop.
//!
//! # Scope
//!
//! Phase 3 exercises the non-AppContainer path: the child is a normal
//! medium-integrity process started under our Job/Silo. Injection into
//! AppContainer processes is deferred to Phase 4 because
//! `CreateRemoteThread` there requires ACL-ing the shim DLL for the
//! capability SID and is better served by Detours-based static
//! injection.

#![cfg(windows)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use windows_sys::Win32::Foundation::HANDLE;

use psroot_netstack_host::nat::{AddrTranslator, NatBackend};
use psroot_netstack_host::Daemon;
use psroot_netstack_ipc::{Channel, ChannelLayout, ChannelSide};

/// Default virtual IP handed to each container's netstack. Phase 3
/// doesn't yet allocate per-container subnets, so all containers share
/// `10.88.0.x` with the low octet derived from the container id hash.
pub const DEFAULT_VIRTUAL_SUBNET: [u8; 3] = [10, 88, 0];

/// Error surface for the container-side netstack runtime. Intentionally
/// small — callers treat any failure as "fall back to OS networking".
#[derive(Debug)]
pub enum NetstackError {
    /// Could not allocate/open the named shared memory region.
    Shm(io::Error),
    /// DLL injection into the target process failed.
    Inject(psroot_netinject::InjectError),
    /// The shim DLL artefact was not found at the expected path.
    DllMissing(PathBuf),
}

impl std::fmt::Display for NetstackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shm(e) => write!(f, "netstack SHM: {e}"),
            Self::Inject(e) => write!(f, "netstack inject: {e:?}"),
            Self::DllMissing(p) => write!(f, "netstack shim DLL not found: {}", p.display()),
        }
    }
}

impl std::error::Error for NetstackError {}

/// Live per-container userland network stack. Owns the daemon thread
/// plus the stop flag that shuts it down on drop.
pub struct NetstackRuntime {
    shm_name: String,
    layout_size: usize,
    virtual_ip: Ipv4Addr,
    dll_path: PathBuf,
    stop: Arc<AtomicBool>,
    daemon: Option<JoinHandle<()>>,
}

impl NetstackRuntime {
    /// Spin up SHM + daemon for a container identified by `tag`.
    ///
    /// `dll_path` is the on-disk location of `psroot_netshim.dll` that
    /// will be `LoadLibraryW`'d into the child. `translator` optionally
    /// rewrites virtual socket addresses to real host endpoints —
    /// callers use it to publish loopback services as reachable via
    /// the container's virtual IP (mirrors the port-publish flow).
    pub fn spawn(
        tag: &str,
        dll_path: impl Into<PathBuf>,
        virtual_ip: Ipv4Addr,
        translator: Option<AddrTranslator>,
    ) -> Result<Self, NetstackError> {
        let dll_path = dll_path.into();
        if !dll_path.exists() {
            return Err(NetstackError::DllMissing(dll_path));
        }

        let layout = ChannelLayout::new(psroot_netstack_proto::DEFAULT_RING_SLOTS);
        let shm_name = unique_shm_name(tag);

        let shm =
            psroot_netstack_ipc::shm::SharedMemory::create(&shm_name, layout.total_size)
                .map_err(NetstackError::Shm)?;
        let host_channel = Channel::create(shm, layout, ChannelSide::Host);

        let stop = Arc::new(AtomicBool::new(false));
        let stop_daemon = Arc::clone(&stop);
        let daemon = thread::Builder::new()
            .name(format!("psroot-netstack-{tag}"))
            .spawn(move || {
                let mut backend = NatBackend::new(virtual_ip);
                if let Some(t) = translator {
                    backend = backend.with_translator(t);
                }
                // Daemon failures are terminal for this container's
                // networking; tracing captures the cause, the stop
                // flag ensures we exit cleanly on container teardown.
                if let Err(e) = Daemon::new(host_channel, backend, stop_daemon).run() {
                    tracing::error!(error = ?e, "netstack daemon exited with error");
                }
            })
            .expect("spawn netstack daemon thread");

        Ok(Self {
            shm_name,
            layout_size: layout.total_size,
            virtual_ip,
            dll_path,
            stop,
            daemon: Some(daemon),
        })
    }

    /// Environment variables the child process needs to locate the SHM
    /// from its `DllMain` init thread. Inject these into the child's
    /// environment block *before* `CreateProcessW`.
    pub fn child_env(&self) -> [(&'static str, String); 2] {
        [
            ("PSROOT_NS_NAME", self.shm_name.clone()),
            ("PSROOT_NS_SIZE", self.layout_size.to_string()),
        ]
    }

    /// Virtual IPv4 address the container's processes believe they own.
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }

    /// `LoadLibraryW`-inject the shim DLL into `process`.
    ///
    /// # Safety
    /// `process` must be a valid handle with
    /// `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE`
    /// rights. The caller retains ownership of the handle.
    pub unsafe fn inject_into(&self, process: HANDLE) -> Result<(), NetstackError> {
        // SAFETY: delegated to the caller's contract above.
        unsafe { psroot_netinject::inject_dll(process, &self.dll_path) }
            .map_err(NetstackError::Inject)
    }
}

impl Drop for NetstackRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.daemon.take() {
            // Best-effort join; the daemon polls `stop` on its tick and
            // will exit on the next iteration. We don't wait forever
            // to avoid blocking container teardown on a wedged thread.
            let _ = t.join();
        }
    }
}

/// Locate the shim DLL next to the current executable. Matches the
/// layout cargo produces (`target/<profile>/psroot_netshim.dll`) and
/// the Windows install layout we expect in Phase 3 — both place the
/// DLL beside the `psroot` binary. Callers can override by passing an
/// explicit path to [`NetstackRuntime::spawn`].
pub fn default_dll_path() -> Option<PathBuf> {
    let mut exe = std::env::current_exe().ok()?;
    exe.pop();
    let candidate = exe.join("psroot_netshim.dll");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Build a subnet-scoped translator that maps `virtual_ip:<port>` to
/// `127.0.0.1:<port>`. Phase 3 uses this for the default "container
/// sees its own published port on its virtual IP" story.
pub fn loopback_translator(virtual_ip: Ipv4Addr) -> AddrTranslator {
    Box::new(move |addr: SocketAddr| match addr {
        SocketAddr::V4(v) if v.ip().octets() == virtual_ip.octets() => Some(SocketAddr::V4(
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, v.port()),
        )),
        _ => None,
    })
}

fn unique_shm_name(tag: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // `Local\` prefix keeps the mapping scoped to the session, which
    // matches the `e2e_inject` test harness and avoids global
    // namespace pollution that would require SeCreateGlobalPrivilege.
    format!("Local\\psroot-ns-{tag}-{pid}-{nanos}")
}

/// Convenience: derive a deterministic per-container virtual IP in the
/// `10.88.0.0/24` range from the container id. Phase 3 doesn't yet
/// guarantee uniqueness under hash collisions — a collision simply
/// means two containers share a translator scope, which the NAT
/// backend tolerates because its socket table is per-daemon.
pub fn virtual_ip_for(container_id: &str) -> Ipv4Addr {
    let hash = container_id
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let low = ((hash % 250) + 2) as u8; // skip .0, .1, .255
    Ipv4Addr::new(
        DEFAULT_VIRTUAL_SUBNET[0],
        DEFAULT_VIRTUAL_SUBNET[1],
        DEFAULT_VIRTUAL_SUBNET[2],
        low,
    )
}

/// Ignore the unused parameter to keep `inject_into` a `pub unsafe fn`
/// on non-Windows targets if this module ever gets cfg-extended.
#[doc(hidden)]
pub fn _assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<NetstackRuntime>();
}
