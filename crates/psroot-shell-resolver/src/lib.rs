//! psroot-shell-resolver — pure-logic resolver that produces a concrete
//! `LaunchPlan` describing how a host shell should be staged, ACL'd and spawned
//! inside an AppContainer.
//!
//! See `Psroot/PRD/05-shell-resolver.md` for full design.

pub mod catalog;
pub mod error;
pub mod plan;
pub mod probe;
pub mod resolve;
pub mod version;

pub use catalog::Catalog;
pub use error::{Result, ShellResolverError};
pub use plan::{AccessMask, AceGrant, KnownCapability, LaunchPlan, StageOp};
pub use probe::{HostProbe, HostShell, MockProbe, RealProbe};
pub use resolve::{NetworkAccess, ResolveContext, Resolver, ShellRequest};
pub use version::VersionReq;
