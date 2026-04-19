//! Feature detection — what isolation layers are available?

use std::process::Command;

/// Detected system capabilities.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Always true on Windows.
    pub job_objects: bool,
    /// True when CreateBindLink is available (Windows 11 24H2+, build 26100).
    pub bind_filter: bool,
    /// True when Server Silos are available (Windows 10 1809+, build 17763).
    pub server_silos: bool,
    /// True when running as Administrator.
    pub is_admin: bool,
    /// Windows build number.
    pub build_number: u32,
}

impl Capabilities {
    /// Detect capabilities of the current system.
    pub fn detect() -> Self {
        let build_number = get_build_number();
        let is_admin = check_admin();

        Self {
            job_objects: true, // always available on Win10+
            bind_filter: build_number >= 26100 && is_admin,
            server_silos: build_number >= 17763 && is_admin,
            is_admin,
            build_number,
        }
    }
}

fn get_build_number() -> u32 {
    #[repr(C)]
    struct OsVersionInfoExW {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform_id: u32,
        csd_version: [u16; 128],
        sp_major: u16,
        sp_minor: u16,
        suite_mask: u16,
        product_type: u8,
        reserved: u8,
    }

    extern "system" {
        fn RtlGetVersion(info: *mut OsVersionInfoExW) -> i32;
    }

    let mut info: OsVersionInfoExW = unsafe { std::mem::zeroed() };
    info.size = std::mem::size_of::<OsVersionInfoExW>() as u32;
    unsafe { RtlGetVersion(&mut info) };
    info.build
}

fn check_admin() -> bool {
    Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
