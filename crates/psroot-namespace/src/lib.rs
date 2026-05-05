#![cfg(windows)]
//! NT Object Namespace construction for Server Silos.
//!
//! Creates the directory objects and symbolic links that give a silo
//! its own isolated view: BaseNamedObjects, GLOBAL??, Device, KnownDlls,
//! drive letter mapping, and essential device symlinks.
//!
//! Uses raw ntdll.dll syscalls — no NtObjectManager dependency.

use psroot_types::error::Result;
use tracing::debug;

mod ntapi;
pub use ntapi::NtHandle;

/// A private DOS device map for a single container process.
///
/// Built as an unnamed NT directory object that **shadows `\GLOBAL??`** —
/// any DOS-device lookup not satisfied locally falls through to the global
/// map. We override `C:` (and optional extra drives) with symlinks pointing
/// at host paths via `\GLOBAL??\…`, which bypasses re-entry into the private
/// map and prevents resolution loops.
///
/// Once assigned to a process via `assign_to_process`, that process sees
/// `C:\` as the container rootfs while keeping access to system devices
/// (NUL, CON, named pipes, KnownDlls, etc.) inherited from `\GLOBAL??`.
///
/// This is the **Windows-Containers-feature-free** alternative to a Server
/// Silo's filesystem isolation. Works on every Win10/11 SKU as long as the
/// caller is admin (NtSetInformationProcess(ProcessDeviceMap) requires
/// PROCESS_SET_INFORMATION on the target — easy for a child created with
/// CREATE_SUSPENDED — and SeDebugPrivilege is NOT required).
pub struct ProcessDeviceMap {
    _global: NtHandle,
    directory: NtHandle,
    _symlinks: Vec<NtHandle>,
}

impl ProcessDeviceMap {
    /// Build a private device map.
    ///
    /// * `container_root` — host absolute path. The new `C:` symlink targets
    ///   `\GLOBAL??\<container_root>` so paths like `C:\Foo` inside the child
    ///   resolve to `<container_root>\Foo` on the host.
    /// * `extra_drives` — additional `("D:", "C:\\some\\host\\path")` mappings.
    pub fn build(container_root: &str, extra_drives: &[(&str, &str)]) -> Result<Self> {
        // The kernel's `ObSetDeviceMap` rejects (STATUS_INVALID_PARAMETER) any
        // directory that already has a DeviceMap pointer attached. A directory
        // created with `\GLOBAL??` as its shadow inherits that pointer, so we
        // must create a *plain* directory and manually link in the device
        // symlinks our processes need (NUL, CON, named pipes, mailslots, the
        // global drive letters, etc).
        let global = ntapi::open_directory("\\GLOBAL??")?;

        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let name = format!(
            "\\BaseNamedObjects\\PsrootDevMap-{}-{}",
            std::process::id(),
            n
        );
        // Plain named directory (no shadow → no inherited DeviceMap pointer).
        let dir = ntapi::create_directory(&name, None)?;
        debug!(name = %name, "device map directory created (no shadow)");

        let mut links = Vec::with_capacity(1 + extra_drives.len());

        // C: → container rootfs (target uses \GLOBAL??\ to break recursion)
        let c_target = format!("\\GLOBAL??\\{}", container_root);
        let c_link = ntapi::create_symlink("C:", &c_target, Some(dir.raw()))?;
        links.push(c_link);
        debug!(target = %c_target, "device map: C: → rootfs");

        for (letter, host) in extra_drives {
            let target = format!("\\GLOBAL??\\{}", host);
            let link = ntapi::create_symlink(letter, &target, Some(dir.raw()))?;
            links.push(link);
            debug!(letter, host, "device map: extra drive");
        }

        Ok(Self { _global: global, directory: dir, _symlinks: links })
    }

    /// Assign this device map to the given (typically suspended) process.
    pub fn assign_to_process(&self, process: isize) -> Result<()> {
        ntapi::set_process_device_map(process, self.directory.raw())
    }

    /// Assign this device map to the **current** process. Children created
    /// after this call inherit it. Use `swap_current` if you want to atomically
    /// swap-in for a CreateProcess and restore afterwards.
    pub fn assign_to_current(&self) -> Result<()> {
        // Pseudo-handle for current process.
        let cur: isize = -1;
        ntapi::set_process_device_map(cur, self.directory.raw())
    }
}

/// All handles created for a silo namespace. Must be kept alive while
/// the silo is running. Drop to clean up.
pub struct SiloNamespace {
    /// The \Silos parent directory handle (kept alive).
    _silos_parent: NtHandle,
    /// The root directory handle (\Silos\<id>).
    pub root: NtHandle,
    /// All child handles (directories and symlinks).
    children: Vec<NtHandle>,
}

impl SiloNamespace {
    /// Build the minimum namespace for a working Server Silo.
    ///
    /// # Arguments
    /// * `silo_id` — kernel silo ID (from JobObjectSiloBasicInformation)
    /// * `container_root` — absolute host path to the container's rootfs
    pub fn build(silo_id: u32, container_root: &str) -> Result<Self> {
        Self::build_with_extra_drives(silo_id, container_root, &[])
    }

    /// Build namespace with additional drive letter mappings.
    ///
    /// `extra_drives` is a slice of `(letter, host_path)` tuples, e.g.
    /// `[("P:", "C:\\Users\\gj\\.psroot\\cache\\shells")]`.
    pub fn build_with_extra_drives(
        silo_id: u32,
        container_root: &str,
        extra_drives: &[(&str, &str)],
    ) -> Result<Self> {
        let silo_path = format!("\\Silos\\{}", silo_id);

        // Step 0: Ensure \Silos parent directory exists.
        // On systems without Windows Containers feature, this directory
        // may not be pre-created in the NT object namespace. OBJ_OPENIF
        // makes this idempotent — opens if it already exists.
        let silos_parent = ntapi::create_directory("\\Silos", None)?;

        // Step 1: Create silo root directory in NT namespace
        let root = ntapi::create_directory(&silo_path, None)?;
        debug!(silo_id, path = %silo_path, "Silo root directory created");

        // Use a closure to ensure cleanup on failure
        let result = (|| -> Result<Vec<NtHandle>> {
            let mut ch = Vec::with_capacity(16);

            // Step 2: BaseNamedObjects
            let bno = ntapi::create_directory("BaseNamedObjects", Some(root.raw()))?;
            ch.push(bno);
            let restricted = ntapi::create_directory("Restricted", Some(ch[0].raw()))?;
            ch.push(restricted);

            // Step 3: Sessions\0\BaseNamedObjects -> silo BNO
            let sessions = ntapi::create_directory("Sessions", Some(root.raw()))?;
            ch.push(sessions);
            let s0 = ntapi::create_directory("0", Some(ch[2].raw()))?;
            ch.push(s0);
            let s0_bno = ntapi::create_symlink(
                "BaseNamedObjects",
                &format!("{}\\BaseNamedObjects", silo_path),
                Some(ch[3].raw()),
            )?;
            ch.push(s0_bno);

            // Step 4: GLOBAL?? with drive letter
            let global = ntapi::create_directory("GLOBAL??", Some(root.raw()))?;
            let global_handle = global.raw();
            ch.push(global);

            // Map C: to container root via \??\ prefix (kernel resolves it)
            let drive_target = format!("\\??\\{}", container_root);
            let drive = ntapi::create_symlink("C:", &drive_target, Some(global_handle))?;
            ch.push(drive);

            // Extra drive letter mappings (e.g. P: → cache root)
            for (letter, host_path) in extra_drives {
                let target = format!("\\??\\{}", host_path);
                let link = ntapi::create_symlink(letter, &target, Some(global_handle))?;
                ch.push(link);
                debug!(letter, host_path, "Extra drive mapped");
            }

            // Essential devices in GLOBAL??
            let nul = ntapi::create_symlink("NUL", "\\Device\\Null", Some(global_handle))?;
            ch.push(nul);
            let con = ntapi::create_symlink("CON", "\\Device\\ConDrv", Some(global_handle))?;
            ch.push(con);
            let conin = ntapi::create_symlink(
                "CONIN$",
                "\\Device\\ConDrv\\CurrentIn",
                Some(global_handle),
            )?;
            ch.push(conin);
            let conout = ntapi::create_symlink(
                "CONOUT$",
                "\\Device\\ConDrv\\CurrentOut",
                Some(global_handle),
            )?;
            ch.push(conout);

            // Step 5: Device directory
            let device = ntapi::create_directory("Device", Some(root.raw()))?;
            let device_handle = device.raw();
            ch.push(device);
            let dev_null = ntapi::create_symlink("Null", "\\Device\\Null", Some(device_handle))?;
            ch.push(dev_null);
            let dev_con = ntapi::create_symlink("ConDrv", "\\Device\\ConDrv", Some(device_handle))?;
            ch.push(dev_con);

            // Step 6: KnownDlls
            let known = ntapi::create_directory("KnownDlls", Some(root.raw()))?;
            ch.push(known);

            debug!(silo_id, entries = ch.len(), "Namespace built");
            Ok(ch)
        })();

        match result {
            Ok(ch) => {
                Ok(Self { _silos_parent: silos_parent, root, children: ch })
            }
            Err(e) => {
                // root and silos_parent will be dropped automatically via NtHandle::Drop
                Err(e)
            }
        }
    }

    /// Raw root directory handle for SetInformationJobObject.
    pub fn root_handle(&self) -> isize {
        self.root.raw()
    }
}

impl Drop for SiloNamespace {
    fn drop(&mut self) {
        // Children dropped in reverse order automatically via Vec::drop
        // (each NtHandle closes itself)
        self.children.clear();
    }
}
