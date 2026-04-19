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

/// All handles created for a silo namespace. Must be kept alive while
/// the silo is running. Drop to clean up.
pub struct SiloNamespace {
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
        let silo_path = format!("\\Silos\\{}", silo_id);
        let mut children = Vec::with_capacity(16);

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
            ch.push(global);

            // Map C: to container root via \??\ prefix (kernel resolves it)
            let drive_target = format!("\\??\\{}", container_root);
            let drive = ntapi::create_symlink("C:", &drive_target, Some(ch[5].raw()))?;
            ch.push(drive);

            // Essential devices in GLOBAL??
            let nul = ntapi::create_symlink("NUL", "\\Device\\Null", Some(ch[5].raw()))?;
            ch.push(nul);
            let con = ntapi::create_symlink("CON", "\\Device\\ConDrv", Some(ch[5].raw()))?;
            ch.push(con);
            let conin = ntapi::create_symlink(
                "CONIN$",
                "\\Device\\ConDrv\\CurrentIn",
                Some(ch[5].raw()),
            )?;
            ch.push(conin);
            let conout = ntapi::create_symlink(
                "CONOUT$",
                "\\Device\\ConDrv\\CurrentOut",
                Some(ch[5].raw()),
            )?;
            ch.push(conout);

            // Step 5: Device directory
            let device = ntapi::create_directory("Device", Some(root.raw()))?;
            ch.push(device);
            let dev_null = ntapi::create_symlink("Null", "\\Device\\Null", Some(ch[11].raw()))?;
            ch.push(dev_null);
            let dev_con = ntapi::create_symlink("ConDrv", "\\Device\\ConDrv", Some(ch[11].raw()))?;
            ch.push(dev_con);

            // Step 6: KnownDlls
            let known = ntapi::create_directory("KnownDlls", Some(root.raw()))?;
            ch.push(known);

            debug!(silo_id, entries = ch.len(), "Namespace built");
            Ok(ch)
        })();

        match result {
            Ok(ch) => {
                children = ch;
                Ok(Self { root, children })
            }
            Err(e) => {
                // root will be dropped automatically via NtHandle::Drop
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
