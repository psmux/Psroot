#![cfg(windows)]
pub mod app_stage;
pub mod container;
pub mod detect;
#[cfg(windows)]
pub mod netstack_runtime;
#[cfg(windows)]
pub mod peb_patch;
pub mod rootfs;
pub mod sandbox;
#[cfg(windows)]
pub mod setup;

pub use container::Container;
pub use detect::Capabilities;
pub use sandbox::IsolationLevel;

// Re-export desktop isolation for GUI containment.
pub use psroot_desktop;

// Re-export resolver/stager so CLI doesn't need direct deps on them.
pub use psroot_shell_resolver as shell_resolver;
pub use psroot_rootfs_stager as rootfs_stager;
