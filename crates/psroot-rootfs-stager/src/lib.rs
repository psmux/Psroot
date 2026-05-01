//! psroot-rootfs-stager — apply a `LaunchPlan` to disk.
//!
//! Operations supported:
//!   - EnsureDir   : mkdir -p
//!   - HardlinkTree: walk src, create hardlinks for every file under dst,
//!                   excluding glob patterns. Falls back to copy per-file
//!                   when CreateHardLinkW returns ERROR_NOT_SAME_DEVICE
//!                   or any other failure that is recoverable.
//!   - CopyTree    : plain recursive copy with excludes.
//!   - Junction    : NTFS directory junction (no admin / dev mode required).
//!   - Symlink     : NTFS symlink (requires SeCreateSymbolicLinkPrivilege OR
//!                   Developer Mode; falls back to junction for directories).
//!
//! After staging, applies AceGrants via `icacls /grant "*<sid>:(OI)(CI)(RX)"`
//! and writes a manifest `.psroot.manifest.json` to the cache directory.
//!
//! See `Psroot/PRD/02-rootfs-staging.md`.

#![cfg(windows)]

use psroot_shell_resolver::{AceGrant, KnownCapability, LaunchPlan, StageOp};
use psroot_types::error::{PsrootError, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use windows_sys::Win32::Storage::FileSystem::CreateHardLinkW;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CacheManifest {
    pub shell_name: String,
    pub host_source_version: String,
    pub cache_key: String,
    pub created_at: String,
    pub stage_ops: usize,
    /// AC SID strings that have been granted RX.
    pub granted_ac_sids: Vec<String>,
    /// Container IDs currently using this cache (refcount).
    pub referenced_by: Vec<String>,
}

impl CacheManifest {
    fn path(cache_dir: &Path) -> PathBuf {
        cache_dir.join(".psroot.manifest.json")
    }

    pub fn load(cache_dir: &Path) -> Option<Self> {
        let p = Self::path(cache_dir);
        let s = fs::read_to_string(&p).ok()?;
        serde_json::from_str(&s).ok()
    }

    pub fn save(&self, cache_dir: &Path) -> Result<()> {
        let p = Self::path(cache_dir);
        let s = serde_json::to_string_pretty(self)?;
        fs::write(&p, s)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AceGrantRecord {
    pub path: String,
    pub sid: String,
    pub mask: String, // "RX"
    pub inherit: bool,
}

/// Result of `apply_plan` — what the caller should persist into container.json
/// for later revocation.
#[derive(Debug, Default)]
pub struct StageOutcome {
    pub cache_dir: PathBuf,
    pub cache_hit: bool,
    pub aces_applied: Vec<AceGrantRecord>,
    pub stage_ops_run: usize,
    pub stage_ops_skipped: usize,
}

/// Apply a LaunchPlan: stage files, grant ACEs.
///
/// `ac_sid_string` must be the AppContainer SID in string form (e.g.
/// "S-1-15-2-…"). It is what icacls receives.
pub fn apply_plan(plan: &LaunchPlan, ac_sid_string: &str, container_id: &str) -> Result<StageOutcome> {
    let mut outcome = StageOutcome {
        cache_dir: plan.cache_dir.clone(),
        ..Default::default()
    };

    // Ensure cache root exists.
    if let Some(parent) = plan.cache_dir.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::create_dir_all(&plan.cache_dir).ok();

    // Cache hit detection: manifest present + all hardlink/copy targets exist.
    let existing = CacheManifest::load(&plan.cache_dir);
    let mut needs_stage = existing.is_none();

    if !needs_stage {
        // Sanity: for every Hardlink/Copy op, check at least the dst directory
        // exists and is non-empty.
        for op in &plan.stage {
            match op {
                StageOp::HardlinkTree { dst, .. } | StageOp::CopyTree { dst, .. } => {
                    if !dst.exists()
                        || fs::read_dir(dst).map(|mut i| i.next().is_none()).unwrap_or(true)
                    {
                        needs_stage = true;
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    if needs_stage {
        info!(
            shell = %plan.shell_name,
            cache_dir = %plan.cache_dir.display(),
            ops = plan.stage.len(),
            "staging shell"
        );
        for op in &plan.stage {
            run_stage_op(op)?;
            outcome.stage_ops_run += 1;
        }
    } else {
        debug!(shell = %plan.shell_name, "cache hit — skipping stage ops");
        outcome.cache_hit = true;
        outcome.stage_ops_skipped = plan.stage.len();
        // Always re-run EnsureDir + Junction + WriteText so per-container paths exist.
        for op in &plan.stage {
            match op {
                StageOp::EnsureDir { .. } | StageOp::Junction { .. } | StageOp::Symlink { .. } | StageOp::WriteText { .. } => {
                    run_stage_op(op)?;
                    outcome.stage_ops_run += 1;
                    outcome.stage_ops_skipped -= 1;
                }
                _ => {}
            }
        }
    }

    // Apply ACE grants.
    for ace in &plan.aces {
        match grant_ace(&ace.path, ac_sid_string, ace.inherit) {
            Ok(()) => {
                outcome.aces_applied.push(AceGrantRecord {
                    path: ace.path.display().to_string(),
                    sid: ac_sid_string.to_string(),
                    mask: "RX".into(),
                    inherit: ace.inherit,
                });
                info!(path = %ace.path.display(), sid = ac_sid_string, "ace.granted");
            }
            Err(e) => {
                warn!(path = %ace.path.display(), error = %e, "ace.grant failed (continuing)");
            }
        }
    }

    // Update manifest.
    let mut manifest = existing.unwrap_or_default();
    manifest.shell_name = plan.shell_name.clone();
    manifest.host_source_version = plan.host_source_version.clone();
    manifest.cache_key = plan.cache_key.clone();
    if manifest.created_at.is_empty() {
        manifest.created_at = chrono_now();
    }
    manifest.stage_ops = plan.stage.len();
    if !manifest.granted_ac_sids.contains(&ac_sid_string.to_string()) {
        manifest.granted_ac_sids.push(ac_sid_string.to_string());
    }
    if !manifest.referenced_by.contains(&container_id.to_string()) {
        manifest.referenced_by.push(container_id.to_string());
    }
    manifest.save(&plan.cache_dir)?;

    let _ = plan; // silence unused if ignored above
    let _ = caps_into_strings;
    Ok(outcome)
}

/// Revoke an ACE recorded by `apply_plan`. Idempotent.
pub fn revoke_ace_record(rec: &AceGrantRecord) -> Result<()> {
    let path = std::path::PathBuf::from(&rec.path);
    if !path.exists() {
        return Ok(()); // nothing to revoke
    }
    let result = std::process::Command::new("icacls")
        .args([
            &rec.path,
            "/remove",
            &format!("*{}", rec.sid),
            "/T",
            "/Q",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match result {
        Ok(s) if s.success() => {
            info!(path = %rec.path, sid = %rec.sid, "ace.revoked");
            Ok(())
        }
        Ok(s) => {
            warn!(path = %rec.path, sid = %rec.sid, code = ?s.code(), "icacls /remove non-zero");
            Ok(())
        }
        Err(e) => {
            warn!(error = %e, "icacls /remove failed");
            Ok(())
        }
    }
}

/// Decrement refcount on the cache. Caller can later call `prune_cache` to
/// reclaim disk for caches with no references.
pub fn unreference_cache(cache_dir: &Path, container_id: &str) -> Result<()> {
    if let Some(mut m) = CacheManifest::load(cache_dir) {
        m.referenced_by.retain(|c| c != container_id);
        m.save(cache_dir)?;
    }
    Ok(())
}

// ── stage op runners ──────────────────────────────────────────────────────

fn run_stage_op(op: &StageOp) -> Result<()> {
    match op {
        StageOp::EnsureDir { dst } => {
            fs::create_dir_all(dst)?;
            debug!(dst = %dst.display(), "stage.ensure_dir");
            Ok(())
        }
        StageOp::HardlinkTree { src, dst, exclude } => {
            hardlink_or_copy_tree(src, dst, exclude, true)
        }
        StageOp::CopyTree { src, dst, exclude } => hardlink_or_copy_tree(src, dst, exclude, false),
        StageOp::Junction { src, dst } => create_junction(src, dst),
        StageOp::Symlink { src, dst } => create_symlink(src, dst),
        StageOp::WriteText { dst, content } => write_text_file(dst, content),
    }
}

fn write_text_file(dst: &Path, content: &str) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(dst, content)?;
    debug!(dst = %dst.display(), bytes = content.len(), "stage.write_text");
    Ok(())
}

fn hardlink_or_copy_tree(src: &Path, dst: &Path, excludes: &[String], try_hardlink: bool) -> Result<()> {
    if !src.exists() {
        return Err(PsrootError::Other(format!(
            "stage source missing: {}",
            src.display()
        )));
    }
    fs::create_dir_all(dst)?;

    let started = std::time::Instant::now();
    let mut linked = 0u64;
    let mut copied = 0u64;
    let mut skipped = 0u64;

    walk_and_link(src, dst, src, excludes, try_hardlink, &mut linked, &mut copied, &mut skipped)?;
    info!(
        src = %src.display(),
        dst = %dst.display(),
        linked,
        copied,
        skipped,
        took_ms = started.elapsed().as_millis() as u64,
        "stage.hardlink_tree"
    );
    Ok(())
}

fn walk_and_link(
    cur: &Path,
    dst_root: &Path,
    src_root: &Path,
    excludes: &[String],
    try_hardlink: bool,
    linked: &mut u64,
    copied: &mut u64,
    skipped: &mut u64,
) -> Result<()> {
    for ent in fs::read_dir(cur)? {
        let ent = ent?;
        let p = ent.path();
        let rel = p.strip_prefix(src_root).unwrap_or(&p);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        if matches_any(&rel_str, excludes) {
            *skipped += 1;
            continue;
        }

        let target = dst_root.join(rel);
        let ft = ent.file_type()?;
        if ft.is_dir() {
            fs::create_dir_all(&target)?;
            walk_and_link(&p, dst_root, src_root, excludes, try_hardlink, linked, copied, skipped)?;
        } else if ft.is_file() {
            // Skip if already present and same size (cache reuse).
            if let Ok(meta_dst) = fs::metadata(&target) {
                if let Ok(meta_src) = fs::metadata(&p) {
                    if meta_dst.len() == meta_src.len() {
                        *skipped += 1;
                        continue;
                    }
                }
                // size mismatch: replace
                let _ = fs::remove_file(&target);
            }
            if try_hardlink && hardlink(&p, &target).is_ok() {
                *linked += 1;
            } else {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                if let Err(e) = fs::copy(&p, &target) {
                    warn!(file = %p.display(), error = %e, "copy failed");
                } else {
                    *copied += 1;
                }
            }
        }
    }
    Ok(())
}

fn matches_any(rel: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pat| glob_match(pat, rel))
}

/// Minimal glob matcher: supports `*`, `**`, `?`. Case-insensitive on Windows.
fn glob_match(pat: &str, text: &str) -> bool {
    let pat = pat.replace('\\', "/").to_lowercase();
    let text = text.to_lowercase();
    glob_match_inner(pat.as_bytes(), text.as_bytes())
}

fn glob_match_inner(p: &[u8], t: &[u8]) -> bool {
    // Very small recursive matcher; not optimised but plenty for our excludes.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            // ** behaves like * for our purposes (matches any chars including /)
            while pi < p.len() && p[pi] == b'*' {
                pi += 1;
            }
            if pi == p.len() {
                return true;
            }
            star = Some((pi, ti));
        } else if let Some((sp, st)) = star {
            pi = sp;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn hardlink(src: &Path, dst: &Path) -> std::io::Result<()> {
    let src_w: Vec<u16> = std::ffi::OsStr::new(src).encode_wide().chain(std::iter::once(0)).collect();
    let dst_w: Vec<u16> = std::ffi::OsStr::new(dst).encode_wide().chain(std::iter::once(0)).collect();
    let ok = unsafe { CreateHardLinkW(dst_w.as_ptr(), src_w.as_ptr(), std::ptr::null()) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Create an NTFS directory junction (no admin / dev mode required).
/// Replaces an existing target if present.
fn create_junction(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        if dst.is_dir() {
            // Already pointing somewhere — try to detect & skip if same.
            if let Ok(canonical_target) = std::fs::canonicalize(dst) {
                if let Ok(canonical_src) = std::fs::canonicalize(src) {
                    if canonical_target == canonical_src {
                        return Ok(());
                    }
                }
            }
            // Different — remove and recreate.
            let _ = fs::remove_dir(dst);
        } else {
            let _ = fs::remove_file(dst);
        }
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    // Use cmd /c mklink /J <dst> <src>. Source must already exist.
    if !src.exists() {
        fs::create_dir_all(src).ok();
    }
    let status = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/J",
            &dst.display().to_string(),
            &src.display().to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(PsrootError::Other(format!(
            "mklink /J {} -> {} failed (code {:?})",
            dst.display(),
            src.display(),
            status.code()
        )));
    }
    debug!(src = %src.display(), dst = %dst.display(), "stage.junction");
    Ok(())
}

fn create_symlink(src: &Path, dst: &Path) -> Result<()> {
    // For directories, junction is just as good and needs no privilege.
    if src.is_dir() {
        return create_junction(src, dst);
    }
    if dst.exists() {
        let _ = fs::remove_file(dst);
    }
    std::os::windows::fs::symlink_file(src, dst).map_err(|e| {
        PsrootError::Other(format!("symlink {} -> {}: {}", dst.display(), src.display(), e))
    })?;
    Ok(())
}

// ── ACE grant ─────────────────────────────────────────────────────────────

fn grant_ace(path: &Path, sid: &str, inherit: bool) -> Result<()> {
    let path_str = path.display().to_string();
    let mut args: Vec<OsString> = vec![
        OsString::from(&path_str),
        OsString::from("/grant"),
    ];
    let inh = if inherit { "(OI)(CI)(RX)" } else { "(RX)" };
    args.push(OsString::from(format!("*{}:{}", sid, inh)));
    if inherit {
        args.push(OsString::from("/T"));
    }
    args.push(OsString::from("/Q"));

    let out = std::process::Command::new("icacls")
        .args(&args)
        .output()
        .map_err(|e| PsrootError::Other(format!("spawn icacls: {}", e)))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(PsrootError::Other(format!(
            "icacls grant {} -> {} failed: {}{}",
            path_str,
            sid,
            stderr.trim(),
            stdout.trim()
        )));
    }
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────

fn caps_into_strings(caps: &[KnownCapability]) -> Vec<String> {
    caps.iter()
        .map(|c| match c {
            KnownCapability::InternetClient => "internetClient".into(),
            KnownCapability::InternetClientServer => "internetClientServer".into(),
            KnownCapability::PrivateNetworkClientServer => "privateNetworkClientServer".into(),
        })
        .collect()
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basic() {
        assert!(glob_match("*.pdb", "x.pdb"));
        assert!(glob_match("**/ref/**", "abc/ref/foo/bar.dll"));
        assert!(glob_match("**/cs/**", "Modules/cs/Microsoft.PowerShell.Commands.Utility.resources.dll"));
        assert!(!glob_match("*.pdb", "x.dll"));
    }
}

/// Sanity: also enable the lib for non-windows builds with stubs for tooling.
pub fn _link_marker() {}
