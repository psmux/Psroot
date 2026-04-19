//! Bind Filter (CreateBindLink/RemoveBindLink) — filesystem redirection.
//!
//! Requires Windows 11 24H2+ (build 26100) and Administrator.
//! Uses dynamic loading since the API may not exist on older builds.

use psroot_types::error::{PsrootError, Result};
use std::sync::OnceLock;
use tracing::{debug, warn};

// Link flags
pub const FLAG_NONE: i32 = 0;
pub const FLAG_READ_ONLY: i32 = 1;
pub const FLAG_MERGED: i32 = 2;

// Function pointer types
type CreateBindLinkFn = unsafe extern "system" fn(
    *const u16, *const u16, i32, u32, *const std::ffi::c_void,
) -> i32;

type RemoveBindLinkFn = unsafe extern "system" fn(*const u16) -> i32;

struct BindApis {
    create: CreateBindLinkFn,
    remove: RemoveBindLinkFn,
}

static BIND_APIS: OnceLock<Option<BindApis>> = OnceLock::new();

fn load_apis() -> &'static Option<BindApis> {
    BIND_APIS.get_or_init(|| {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let dll_name: Vec<u16> = "bindfltapi.dll\0".encode_utf16().collect();
        let module = unsafe { LoadLibraryW(dll_name.as_ptr()) };
        if module.is_null() {
            // Try kernel32 as fallback (some builds have it there)
            let k32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
            let module = unsafe { LoadLibraryW(k32.as_ptr()) };
            if module.is_null() {
                return None;
            }
            let create = unsafe { GetProcAddress(module, b"CreateBindLink\0".as_ptr()) };
            let remove = unsafe { GetProcAddress(module, b"RemoveBindLink\0".as_ptr()) };
            if let (Some(c), Some(r)) = (create, remove) {
                return Some(BindApis {
                    create: unsafe { std::mem::transmute(c) },
                    remove: unsafe { std::mem::transmute(r) },
                });
            }
            return None;
        }

        let create = unsafe { GetProcAddress(module, b"CreateBindLink\0".as_ptr()) };
        let remove = unsafe { GetProcAddress(module, b"RemoveBindLink\0".as_ptr()) };
        if let (Some(c), Some(r)) = (create, remove) {
            Some(BindApis {
                create: unsafe { std::mem::transmute(c) },
                remove: unsafe { std::mem::transmute(r) },
            })
        } else {
            None
        }
    })
}

/// Convert &str to null-terminated UTF-16.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Options for creating a bind link.
#[derive(Debug, Clone, Default)]
pub struct BindLinkOptions {
    pub read_only: bool,
    pub merged: bool,
}

/// Managed collection of bind links with automatic cleanup.
pub struct BindFilter {
    /// Active links: virtual_path → backing_path
    links: Vec<(String, String)>,
}

impl BindFilter {
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    /// Create a bind link: `virtual_path` transparently redirects to `backing_path`.
    pub fn create(
        &mut self,
        virtual_path: &str,
        backing_path: &str,
        opts: &BindLinkOptions,
    ) -> Result<()> {
        let mut flags = FLAG_NONE;
        if opts.read_only {
            flags |= FLAG_READ_ONLY;
        }
        if opts.merged {
            flags |= FLAG_MERGED;
        }

        let vp = to_wide(virtual_path);
        let bp = to_wide(backing_path);

        let apis = load_apis().as_ref().ok_or_else(|| {
            PsrootError::Unsupported { detail: "CreateBindLink not available on this system".into() }
        })?;

        let hr = unsafe {
            (apis.create)(vp.as_ptr(), bp.as_ptr(), flags, 0, std::ptr::null())
        };

        if hr != 0 {
            return Err(PsrootError::hr("CreateBindLink", hr as u32));
        }

        debug!(virtual_path, backing_path, "Bind link created");
        self.links
            .push((virtual_path.to_string(), backing_path.to_string()));
        Ok(())
    }

    /// Remove a specific bind link.
    pub fn remove(&mut self, virtual_path: &str) -> Result<()> {
        let vp = to_wide(virtual_path);
        let apis = load_apis().as_ref().ok_or_else(|| {
            PsrootError::Unsupported { detail: "RemoveBindLink not available on this system".into() }
        })?;
        let hr = unsafe { (apis.remove)(vp.as_ptr()) };
        if hr != 0 {
            return Err(PsrootError::hr("RemoveBindLink", hr as u32));
        }
        self.links.retain(|(vp, _)| vp != virtual_path);
        debug!(virtual_path, "Bind link removed");
        Ok(())
    }

    /// Remove all bind links (in reverse order). Best-effort.
    pub fn remove_all(&mut self) {
        if let Some(apis) = load_apis().as_ref() {
            for (vp, _) in self.links.drain(..).rev() {
                let wide = to_wide(&vp);
                let hr = unsafe { (apis.remove)(wide.as_ptr()) };
                if hr != 0 {
                    warn!(virtual_path = %vp, hr, "Failed to remove bind link");
                }
            }
        } else {
            self.links.clear();
        }
    }

    /// Number of active bind links.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Check if CreateBindLink is available on this system.
    pub fn is_available() -> bool {
        // Check Windows build number >= 26100
        let ver = os_build_number();
        ver >= 26100
    }
}

impl Default for BindFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BindFilter {
    fn drop(&mut self) {
        self.remove_all();
    }
}

fn os_build_number() -> u32 {
    // Parse from os version string "10.0.26100"
    let ver = os_version_string();
    ver.split('.')
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn os_version_string() -> String {
    // Use RtlGetVersion to avoid deprecated GetVersionEx
    #[repr(C)]
    struct OsVersionInfoExW {
        os_version_info_size: u32,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        platform_id: u32,
        sz_csd_version: [u16; 128],
        service_pack_major: u16,
        service_pack_minor: u16,
        suite_mask: u16,
        product_type: u8,
        reserved: u8,
    }

    extern "system" {
        fn RtlGetVersion(lpVersionInformation: *mut OsVersionInfoExW) -> i32;
    }

    let mut info: OsVersionInfoExW = unsafe { std::mem::zeroed() };
    info.os_version_info_size = std::mem::size_of::<OsVersionInfoExW>() as u32;

    unsafe { RtlGetVersion(&mut info) };

    format!(
        "{}.{}.{}",
        info.major_version, info.minor_version, info.build_number
    )
}
