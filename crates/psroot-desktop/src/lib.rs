//! Isolated Desktop for headful GUI process containment.
//!
//! Windows supports multiple Desktop objects within a single Window Station.
//! A process launched on a separate desktop can create windows, render via
//! GPU/DWM, and run headful — but its windows are invisible to the user's
//! interactive desktop and cannot interact with windows on other desktops.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │  Window Station: WinSta0                 │
//! │                                          │
//! │  ┌──────────────┐  ┌──────────────────┐ │
//! │  │ Default      │  │ Psroot-<uuid>    │ │
//! │  │ (user sees)  │  │ (isolated GUI)   │ │
//! │  │              │  │                  │ │
//! │  │ Explorer,    │  │ Chrome runs      │ │
//! │  │ user apps    │  │ headful here     │ │
//! │  └──────────────┘  └──────────────────┘ │
//! └──────────────────────────────────────────┘
//! ```
//!
//! Key properties:
//! - Same Window Station = GPU/DWM access works (compositor is per-session)
//! - Different Desktop = windows are invisible, no cross-desktop input
//! - Chromium/Chrome runs fully headful with real rendering pipeline
//! - No hypervisor required — pure Win32 Desktop API
//!
//! # Security
//!
//! The isolated desktop gets a DACL that grants access only to:
//! - The AppContainer SID (if provided) — so sandboxed processes can use it
//! - The current user SID — so we can manage/close it
//! - SYSTEM — for DWM compositor access
//!
//! Processes on other desktops cannot:
//! - Enumerate windows on the isolated desktop
//! - Send messages to windows on the isolated desktop
//! - Read pixel content from the isolated desktop

mod desktop;

pub use desktop::{IsolatedDesktop, DesktopConfig, ProcessInfo, StartupInfoExW};
