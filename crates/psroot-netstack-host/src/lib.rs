//! Host-side netstack daemon for a psroot container.
//!
//! # Role
//!
//! One instance runs per container. It owns the host end of the IPC
//! [`Channel`], consumes messages from the shim, dispatches them to a
//! pluggable [`Backend`], and writes replies back.
//!
//! # Phase 1: NAT backend
//!
//! The only backend provided today is [`nat::NatBackend`]. It:
//!
//! * Translates every `Socket`/`Connect`/`Send`/`Recv` into real host
//!   sockets via `std::net`.
//! * Gives the container the *illusion* of its own IP — `getsockname`
//!   and `getpeername` report the virtual container IP, never the host's
//!   real address. Inbound connections are still routed to real sockets
//!   so the container's logical view is intact.
//! * Does not (yet) implement UDP or IPv6 beyond stub replies —
//!   Phase 2 wires smoltcp as an alternative backend.
//!
//! # Phase 2 plan (documented, not yet implemented)
//!
//! * Swap [`Backend`] for a smoltcp-based implementation that maintains a
//!   per-container TCP/IP state machine. The shim still calls the same
//!   opcodes; they are delivered as packets on an in-process interface.
//! * Add a router that bridges multiple containers on the same virtual
//!   subnet (e.g. `10.88.0.0/16`), enabling inter-container traffic
//!   without going through the host at all.
//! * Add DNS interception so `getaddrinfo("web")` inside one container
//!   resolves to the sibling container's virtual IP.

pub mod backend;
pub mod daemon;
pub mod nat;
pub mod socket_table;

pub use backend::{Backend, Event};
pub use daemon::Daemon;
pub use nat::NatBackend;
pub use socket_table::SocketTable;
