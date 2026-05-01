//! Generic app staging — run ANY Windows app inside psroot without a catalog.
//!
//! Instead of manually writing a .toml catalog for each app, this module
//! takes an arbitrary exe path, discovers its app root directory, and
//! stages the entire tree into a container rootfs.
//!
//! # How It Works
//!
//! Most Windows apps are self-contained in their install directory:
//! - Chrome: `C:\Program Files\Google\Chrome\Application\` (500+ files)
//! - VS Code: `C:\Program Files\Microsoft VS Code\` (1000+ files)  
//! - Firefox: `C:\Program Files\Mozilla Firefox\` (200+ files)
//! - Discord: `%LOCALAPPDATA%\Discord\app-*\` (100+ files)
//! - Any portable app: single folder with everything
//!
//! We detect the "app root" (the directory containing the exe), hardlink
//! the entire tree into `{rootfs}\App\`, and launch from there.
//!
//! # Usage
//!
//! ```rust
//! use psroot_container::app_stage::{AppStageConfig, stage_and_run_gui};
//!
//! let config = AppStageConfig::from_exe(r"C:\Program Files\SomeApp\app.exe")?;
//! stage_and_run_gui(&config)?;
//! ```

use psroot_desktop::{DesktopConfig, IsolatedDesktop};
use psroot_types::error::{PsrootError, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Configuration for staging a generic app into a container.
#[derive(Debug, Clone)]
pub struct AppStageConfig {
    /// Full path to the executable on the host.
    pub exe_path: PathBuf,

    /// The "app root" — directory to stage. Defaults to exe's parent dir.
    /// For deep layouts (exe is in `bin/` subfolder), override this.
    pub app_root: PathBuf,

    /// Name for this container (used for rootfs dir, desktop name, etc.)
    pub container_name: String,

    /// Extra arguments to pass to the exe.
    pub args: Vec<String>,

    /// Where to place the rootfs. Defaults to temp dir.
    pub rootfs_base: PathBuf,

    /// Patterns to exclude from staging (glob-style).
    /// Defaults: ["*.pdb", "**/Installer/**", "**/*.log"]
    pub exclude: Vec<String>,

    /// Whether the app needs network access.
    pub network: bool,

    /// Extra host directories to stage (e.g. shared DLLs, plugins).
    pub extra_dirs: Vec<(PathBuf, String)>, // (host_path, mount_name_in_rootfs)
}

impl AppStageConfig {
    /// Create config from an exe path. Automatically detects app root.
    pub fn from_exe(exe_path: impl AsRef<Path>) -> Result<Self> {
        let exe_path = exe_path.as_ref().to_path_buf();

        if !exe_path.exists() {
            return Err(PsrootError::Other(format!(
                "Executable not found: {}",
                exe_path.display()
            )));
        }

        if !exe_path.is_file() {
            return Err(PsrootError::Other(format!(
                "Not a file: {}",
                exe_path.display()
            )));
        }

        let app_root = detect_app_root(&exe_path);
        let exe_name = exe_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let container_name = format!("{}-{}", exe_name, std::process::id());

        let rootfs_base = std::env::temp_dir().join("psroot-containers");

        Ok(Self {
            exe_path,
            app_root,
            container_name,
            args: Vec::new(),
            rootfs_base,
            exclude: vec![
                "*.pdb".into(),
                "**/Installer/**".into(),
                "**/*.log".into(),
                "**/SetupMetrics/**".into(),
            ],
            network: true,
            extra_dirs: Vec::new(),
        })
    }

    /// Set custom arguments for the app.
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Override the app root directory (for non-standard layouts).
    pub fn with_app_root(mut self, root: impl AsRef<Path>) -> Self {
        self.app_root = root.as_ref().to_path_buf();
        self
    }

    /// Add an extra host directory to stage into the container.
    pub fn with_extra_dir(mut self, host_path: impl AsRef<Path>, mount_name: &str) -> Self {
        self.extra_dirs
            .push((host_path.as_ref().to_path_buf(), mount_name.to_string()));
        self
    }

    /// Set exclude patterns.
    pub fn with_excludes(mut self, excludes: Vec<String>) -> Self {
        self.exclude = excludes;
        self
    }

    /// The rootfs path for this container.
    pub fn rootfs_path(&self) -> PathBuf {
        self.rootfs_base.join(&self.container_name)
    }

    /// The path where the app will be staged inside the rootfs.
    pub fn staged_app_dir(&self) -> PathBuf {
        self.rootfs_path().join("App")
    }

    /// The path to the staged exe inside the rootfs.
    pub fn staged_exe_path(&self) -> PathBuf {
        let rel = self
            .exe_path
            .strip_prefix(&self.app_root)
            .unwrap_or(&self.exe_path);
        self.staged_app_dir().join(rel)
    }
}

/// Stage and run a GUI app in an isolated container.
///
/// This is the all-in-one function:
/// 1. Prepares rootfs directory structure
/// 2. Hardlinks the app tree into rootfs
/// 3. Creates an isolated Desktop
/// 4. Launches the app from inside the container
/// 5. Waits for exit
/// 6. Cleans up
///
/// Returns the process exit code.
pub fn stage_and_run_gui(config: &AppStageConfig) -> Result<u32> {
    let rootfs = config.rootfs_path();

    info!(
        exe = %config.exe_path.display(),
        app_root = %config.app_root.display(),
        rootfs = %rootfs.display(),
        "Staging app into container"
    );

    // 1. Prepare rootfs
    prepare_rootfs(&rootfs)?;

    // 2. Stage app
    let stats = stage_app(config)?;
    info!(
        files = stats.files_staged,
        hardlinked = stats.hardlinked,
        copied = stats.copied,
        skipped = stats.skipped,
        "App staged into container"
    );

    // 3. Stage extra directories
    for (host_path, mount_name) in &config.extra_dirs {
        let dst = rootfs.join(mount_name);
        std::fs::create_dir_all(&dst).map_err(|e| {
            PsrootError::Other(format!("create dir {}: {}", dst.display(), e))
        })?;
        let extra_stats = hardlink_tree(host_path, &dst, &config.exclude);
        info!(
            src = %host_path.display(),
            dst = %mount_name,
            files = extra_stats.files_staged,
            "Extra dir staged"
        );
    }

    // 4. Create isolated desktop
    let desktop_config = DesktopConfig {
        appcontainer_sid: None,
        name: Some(config.container_name.clone()),
    };
    let desktop = IsolatedDesktop::create(&desktop_config)?;

    // 5. Build command line
    let staged_exe = config.staged_exe_path();
    let mut cmdline = quote_arg(&staged_exe.display().to_string());
    for arg in &config.args {
        cmdline.push(' ');
        cmdline.push_str(&quote_arg(arg));
    }

    info!(
        cmd = %cmdline,
        desktop = %desktop.lpdesktop_name(),
        "Launching app on isolated desktop"
    );

    // 6. Launch
    let proc = desktop.spawn_process(
        &cmdline,
        Some(&rootfs.display().to_string()),
        false,
        0,
        None,
    )?;

    info!(pid = proc.process_id, "App started");

    // 7. Wait
    let exit_code = proc.wait();

    // 8. Cleanup
    info!("Cleaning up container rootfs");
    let _ = std::fs::remove_dir_all(&rootfs);

    Ok(exit_code)
}

/// Stage and run a GUI app WITHOUT blocking (returns handles for async control).
pub fn stage_and_spawn_gui(
    config: &AppStageConfig,
) -> Result<(IsolatedDesktop, psroot_desktop::ProcessInfo, PathBuf)> {
    let rootfs = config.rootfs_path();

    prepare_rootfs(&rootfs)?;
    let stats = stage_app(config)?;
    info!(files = stats.files_staged, "App staged");

    for (host_path, mount_name) in &config.extra_dirs {
        let dst = rootfs.join(mount_name);
        std::fs::create_dir_all(&dst).ok();
        hardlink_tree(host_path, &dst, &config.exclude);
    }

    let desktop_config = DesktopConfig {
        appcontainer_sid: None,
        name: Some(config.container_name.clone()),
    };
    let desktop = IsolatedDesktop::create(&desktop_config)?;

    let staged_exe = config.staged_exe_path();
    let mut cmdline = quote_arg(&staged_exe.display().to_string());
    for arg in &config.args {
        cmdline.push(' ');
        cmdline.push_str(&quote_arg(arg));
    }

    let proc = desktop.spawn_process(
        &cmdline,
        Some(&rootfs.display().to_string()),
        false,
        0,
        None,
    )?;

    Ok((desktop, proc, rootfs))
}

// ═══════════════════════════════════════════════════════════════════
//  INTERNAL
// ═══════════════════════════════════════════════════════════════════

/// Statistics from staging.
#[derive(Debug, Default)]
pub struct StageStats {
    pub files_staged: u64,
    pub hardlinked: u64,
    pub copied: u64,
    pub skipped: u64,
}

/// Detect the app root directory from an exe path.
///
/// Heuristic:
/// - If exe is in a system directory (System32, SysWOW64, Windows), use just the exe file
///   by creating a wrapper directory containing only the exe. Returns the exe's parent but
///   `is_system_dir` flag is set so the stager knows to only link the single file.
/// - If exe is in a `bin\` or `app\` subfolder, go up one level
/// - Otherwise: use the exe's parent directory
fn detect_app_root(exe_path: &Path) -> PathBuf {
    let parent = exe_path.parent().unwrap_or(exe_path);
    let parent_lower = parent.to_string_lossy().to_lowercase();

    // For system directories, we'll stage just the exe (handled in stage_app)
    if is_system_dir(&parent_lower) {
        debug!(
            exe = %exe_path.display(),
            "System dir detected — will stage single exe only"
        );
        return parent.to_path_buf();
    }

    // Check if parent is a "bin" or "app" folder — if so, go up
    if let Some(dir_name) = parent.file_name() {
        let name = dir_name.to_string_lossy().to_lowercase();
        if name == "bin" || name == "app" || name == "cli" {
            if let Some(grandparent) = parent.parent() {
                debug!(
                    exe = %exe_path.display(),
                    app_root = %grandparent.display(),
                    "Detected subfolder layout, using grandparent"
                );
                return grandparent.to_path_buf();
            }
        }
    }

    // Default: use the exe's parent directory
    parent.to_path_buf()
}

/// Returns true if the path is a system directory that should NOT be fully staged.
fn is_system_dir(path_lower: &str) -> bool {
    let markers = [
        "\\windows\\system32",
        "\\windows\\syswow64",
        "\\windows\\system",
        "\\windows\\winsxs",
    ];
    markers.iter().any(|m| path_lower.contains(m))
}

/// Prepare rootfs directory structure.
fn prepare_rootfs(rootfs: &Path) -> Result<()> {
    let dirs = [
        rootfs.join("App"),
        rootfs.join("Users").join("ContainerUser"),
        rootfs.join("Temp"),
    ];

    for dir in &dirs {
        std::fs::create_dir_all(dir).map_err(|e| {
            PsrootError::Other(format!("create dir {}: {}", dir.display(), e))
        })?;
    }

    Ok(())
}

/// Stage the app into the rootfs.
fn stage_app(config: &AppStageConfig) -> Result<StageStats> {
    let dst = config.staged_app_dir();
    std::fs::create_dir_all(&dst).map_err(|e| {
        PsrootError::Other(format!("create app dir {}: {}", dst.display(), e))
    })?;

    // If the app root is a system directory, only stage the exe file itself
    let parent_lower = config.app_root.to_string_lossy().to_lowercase();
    if is_system_dir(&parent_lower) {
        let target = dst.join(config.exe_path.file_name().unwrap());
        let mut stats = StageStats::default();
        if std::fs::hard_link(&config.exe_path, &target).is_ok() {
            stats.hardlinked += 1;
            stats.files_staged += 1;
        } else {
            std::fs::copy(&config.exe_path, &target).map_err(|e| {
                PsrootError::Other(format!(
                    "copy exe {}: {}",
                    config.exe_path.display(),
                    e
                ))
            })?;
            stats.copied += 1;
            stats.files_staged += 1;
        }
        info!(
            exe = %config.exe_path.display(),
            "System dir — staged single exe only"
        );
        return Ok(stats);
    }

    Ok(hardlink_tree(&config.app_root, &dst, &config.exclude))
}

/// Recursively hardlink a directory tree. Falls back to copy on failure.
fn hardlink_tree(src: &Path, dst: &Path, excludes: &[String]) -> StageStats {
    let mut stats = StageStats::default();
    walk_and_stage(src, dst, src, excludes, &mut stats);
    stats
}

fn walk_and_stage(
    current: &Path,
    dst_root: &Path,
    src_root: &Path,
    excludes: &[String],
    stats: &mut StageStats,
) {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %current.display(), error = %e, "Cannot read directory");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(src_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        // Check exclude patterns
        if matches_glob(&rel, excludes) {
            stats.skipped += 1;
            continue;
        }

        let target = dst_root.join(
            path.strip_prefix(src_root).unwrap_or(&path),
        );

        if path.is_dir() {
            std::fs::create_dir_all(&target).ok();
            walk_and_stage(&path, dst_root, src_root, excludes, stats);
        } else if path.is_file() {
            // Skip if target already exists with same size
            if let (Ok(src_meta), Ok(dst_meta)) =
                (std::fs::metadata(&path), std::fs::metadata(&target))
            {
                if src_meta.len() == dst_meta.len() {
                    stats.skipped += 1;
                    continue;
                }
            }

            // Try hardlink first (zero disk space)
            if std::fs::hard_link(&path, &target).is_ok() {
                stats.hardlinked += 1;
                stats.files_staged += 1;
            } else {
                // Fallback to copy (cross-device, etc.)
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                match std::fs::copy(&path, &target) {
                    Ok(_) => {
                        stats.copied += 1;
                        stats.files_staged += 1;
                    }
                    Err(e) => {
                        debug!(file = %path.display(), error = %e, "skip file");
                        stats.skipped += 1;
                    }
                }
            }
        }
    }
}

/// Simple glob matching for exclude patterns.
fn matches_glob(path: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if glob_match(pattern, path) {
            return true;
        }
    }
    false
}

/// Minimal glob matcher supporting `*`, `**`, and `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Handle ** (matches any path segment)
    if pattern.contains("**/") {
        let suffix = pattern.split("**/").last().unwrap_or("");
        if suffix.is_empty() {
            return true; // **/ matches everything
        }
        // Check if any path segment matches the suffix
        for segment in text.split('/') {
            if simple_glob(suffix, segment) {
                return true;
            }
        }
        // Also check the full remaining path
        if let Some(pos) = pattern.find("**/") {
            let after = &pattern[pos + 3..];
            if text.len() >= after.len() && simple_glob(after, &text[text.len() - after.len()..]) {
                return true;
            }
        }
        return false;
    }

    // Simple pattern (just filename matching)
    let filename = text.rsplit('/').next().unwrap_or(text);
    simple_glob(pattern, filename)
}

/// Simple glob: `*` matches any chars, `?` matches one char.
fn simple_glob(pattern: &str, text: &str) -> bool {
    let mut pi = pattern.chars().peekable();
    let mut ti = text.chars().peekable();

    // Use recursive approach for simplicity
    glob_recursive(pattern.as_bytes(), text.as_bytes())
}

fn glob_recursive(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    match pattern[0] {
        b'*' => {
            // * matches zero or more characters
            // Try matching zero chars, then one, then two, etc.
            for i in 0..=text.len() {
                if glob_recursive(&pattern[1..], &text[i..]) {
                    return true;
                }
            }
            false
        }
        b'?' => {
            // ? matches exactly one character
            if text.is_empty() {
                false
            } else {
                glob_recursive(&pattern[1..], &text[1..])
            }
        }
        c => {
            if text.is_empty() {
                false
            } else if text[0].to_ascii_lowercase() == c.to_ascii_lowercase() {
                glob_recursive(&pattern[1..], &text[1..])
            } else {
                false
            }
        }
    }
}

/// Quote a path for Windows command line.
fn quote_arg(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if s.chars().any(|c| c.is_whitespace() || c == '"') {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}
