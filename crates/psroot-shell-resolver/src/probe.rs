//! Host shell discovery — registry, env vars, well-known paths.
//!
//! Trait-based for testability; the real impl is Windows-only.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct HostShell {
    /// Directory containing the shell's main executable (used as `{shell_root}`).
    pub root: PathBuf,
    /// Absolute path to the entry executable.
    pub entry: PathBuf,
    /// Detected version, e.g. "7.6.0". May be "0.0.0" if detection failed.
    pub version: String,
}

pub trait HostProbe {
    /// Resolve a probe rule chain into a HostShell. Returns Ok(None) if no
    /// rule matched (caller produces ShellNotInstalled).
    fn find(
        &self,
        catalog_entry: &crate::catalog::schema::CatalogFile,
    ) -> std::io::Result<Option<HostShell>>;
}

/// Substitute placeholders that are valid for *probe* rules:
///   {system_root}, {program_files}
fn substitute_probe(s: &str) -> String {
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    s.replace("{system_root}", &sys)
        .replace("{program_files}", &pf)
}

/// Try to read VS_FIXEDFILEINFO from a PE — returns "0.0.0.0" on failure.
#[cfg(windows)]
fn read_exe_version(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        let mut handle: u32 = 0;
        let size = GetFileVersionInfoSizeW(wide.as_ptr(), &mut handle);
        if size == 0 {
            return "0.0.0.0".into();
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide.as_ptr(), 0, size, buf.as_mut_ptr() as _) == 0 {
            return "0.0.0.0".into();
        }
        let sub: Vec<u16> = "\\\0".encode_utf16().collect();
        let mut data: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        if VerQueryValueW(buf.as_ptr() as _, sub.as_ptr(), &mut data, &mut len) == 0
            || len == 0
            || data.is_null()
        {
            return "0.0.0.0".into();
        }
        // VS_FIXEDFILEINFO: dwFileVersionMS (high/low), dwFileVersionLS (high/low) at offsets 8..24
        let p = data as *const u32;
        let ms = *p.add(2);
        let ls = *p.add(3);
        format!(
            "{}.{}.{}.{}",
            (ms >> 16) & 0xFFFF,
            ms & 0xFFFF,
            (ls >> 16) & 0xFFFF,
            ls & 0xFFFF,
        )
    }
}

#[cfg(not(windows))]
fn read_exe_version(_path: &Path) -> String {
    "0.0.0.0".into()
}

/// Read a registry value (Windows). Returns None on any failure.
#[cfg(windows)]
fn reg_read_string(hive: &str, key: &str, value: &str) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY,
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return None,
    };
    let key_w: Vec<u16> = std::ffi::OsStr::new(key).encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        let mut hk: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, key_w.as_ptr(), 0, KEY_READ, &mut hk) != ERROR_SUCCESS {
            return None;
        }
        // PowerShellCore key has subkeys per version; enumerate and pick highest.
        let mut chosen: Option<String> = None;
        let mut chosen_subkey: Option<String> = None;
        let mut idx = 0u32;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let r = RegEnumKeyExW(
                hk,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if r != ERROR_SUCCESS {
                break;
            }
            let sub = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            // Open subkey + read named value
            let sub_w: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let mut subkey: HKEY = std::ptr::null_mut();
            if RegOpenKeyExW(hk, sub_w.as_ptr(), 0, KEY_READ, &mut subkey) == ERROR_SUCCESS {
                let val_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
                let mut typ: u32 = 0;
                let mut data = [0u16; 1024];
                let mut data_bytes = (data.len() * 2) as u32;
                if RegQueryValueExW(
                    subkey,
                    val_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut typ,
                    data.as_mut_ptr() as _,
                    &mut data_bytes,
                ) == ERROR_SUCCESS
                    && typ == REG_SZ
                {
                    let chars = (data_bytes as usize / 2).saturating_sub(1).min(data.len());
                    let s = String::from_utf16_lossy(&data[..chars])
                        .trim_end_matches('\0')
                        .to_string();
                    // Pick the highest subkey name (lex-sort works for semver-ish version dirs).
                    if chosen_subkey.as_deref().map(|c| sub.as_str() > c).unwrap_or(true) {
                        chosen = Some(s);
                        chosen_subkey = Some(sub.clone());
                    }
                }
                RegCloseKey(subkey);
            }
            idx += 1;
        }
        // If no subkeys, try reading the value directly off `hk`.
        if chosen.is_none() {
            let val_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
            let mut typ: u32 = 0;
            let mut data = [0u16; 1024];
            let mut data_bytes = (data.len() * 2) as u32;
            if RegQueryValueExW(
                hk,
                val_w.as_ptr(),
                std::ptr::null_mut(),
                &mut typ,
                data.as_mut_ptr() as _,
                &mut data_bytes,
            ) == ERROR_SUCCESS
                && typ == REG_SZ
            {
                let chars = (data_bytes as usize / 2).saturating_sub(1).min(data.len());
                chosen = Some(
                    String::from_utf16_lossy(&data[..chars])
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
        }
        RegCloseKey(hk);
        chosen
    }
}

#[cfg(not(windows))]
fn reg_read_string(_h: &str, _k: &str, _v: &str) -> Option<String> {
    None
}

/// Real Windows probe.
pub struct RealProbe;

impl HostProbe for RealProbe {
    fn find(
        &self,
        cat: &crate::catalog::schema::CatalogFile,
    ) -> std::io::Result<Option<HostShell>> {
        use crate::catalog::schema::ProbeRule;

        for rule in &cat.probe {
            let candidate_root: Option<PathBuf> = match rule {
                ProbeRule::Env { var } => {
                    std::env::var(var).ok().and_then(|v| {
                        let p = PathBuf::from(v);
                        if p.is_file() {
                            p.parent().map(PathBuf::from)
                        } else if p.is_dir() {
                            Some(p)
                        } else {
                            None
                        }
                    })
                }
                ProbeRule::Path { glob } => {
                    let p = PathBuf::from(substitute_probe(glob));
                    if p.is_file() {
                        p.parent().map(PathBuf::from)
                    } else {
                        None
                    }
                }
                ProbeRule::Registry { hive, key, value } => {
                    reg_read_string(hive, key, value).map(PathBuf::from).filter(|p| p.is_dir())
                }
            };

            if let Some(root) = candidate_root {
                // Resolve actual exe under `root`. We use the catalog's launch.entry
                // basename to find the right executable name.
                let entry_name = std::path::Path::new(&cat.launch.entry)
                    .file_name()
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| std::ffi::OsString::from("shell.exe"));
                let entry = root.join(&entry_name);

                // For System32-resident shells (cmd / powershell5), the catalog's
                // launch.entry path is rootfs-relative — the basename will still be
                // correct (cmd.exe / powershell.exe), and existence at `root\<name>`
                // is what matters.
                if !entry.exists() {
                    continue;
                }

                let version = match cat.version.as_ref().map(|v| v.detect.as_str()) {
                    Some("none") => "0.0.0.0".into(),
                    _ => read_exe_version(&entry),
                };

                return Ok(Some(HostShell {
                    root,
                    entry,
                    version,
                }));
            }
        }
        Ok(None)
    }
}

/// Test double: returns canned values regardless of what the rule says.
#[derive(Default)]
pub struct MockProbe {
    pub mapping: std::collections::HashMap<String, HostShell>,
}

impl MockProbe {
    pub fn with(mut self, name: &str, shell: HostShell) -> Self {
        self.mapping.insert(name.to_string(), shell);
        self
    }
}

impl HostProbe for MockProbe {
    fn find(
        &self,
        cat: &crate::catalog::schema::CatalogFile,
    ) -> std::io::Result<Option<HostShell>> {
        Ok(self.mapping.get(&cat.name).cloned())
    }
}
