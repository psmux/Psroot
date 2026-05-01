//! resolve(): turn a `ShellRequest` + `ResolveContext` + Catalog + Probe into a concrete `LaunchPlan`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::catalog::schema::{CatalogFile, StageRule};
use crate::catalog::Catalog;
use crate::error::{Result, ShellResolverError};
use crate::plan::{AccessMask, AceGrant, KnownCapability, LaunchPlan, StageOp};
use crate::probe::{HostProbe, HostShell, RealProbe};
use crate::version::VersionReq;

#[derive(Debug, Clone)]
pub struct ShellRequest {
    pub name: String,
    pub version: Option<VersionReq>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl ShellRequest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            args: Vec::new(),
            env: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccess {
    None,
    Outbound,
    Full,
    /// Userland netstack — provides connectivity itself, no caps needed.
    Netstack,
}

#[derive(Debug, Clone)]
pub struct ResolveContext<'a> {
    pub container_id: &'a str,
    pub rootfs: &'a Path,
    pub network: NetworkAccess,
    pub cache_root: &'a Path,
    pub allow_admin: bool,
}

/// Top-level resolver — uses Catalog::builtin and the real probe by default.
pub struct Resolver<P: HostProbe = RealProbe> {
    catalog: Catalog,
    probe: P,
}

impl Default for Resolver<RealProbe> {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver<RealProbe> {
    pub fn new() -> Self {
        let mut cat = Catalog::builtin();
        // Auto-merge user catalog directory if present.
        if let Some(home) = dirs_home() {
            let dir = home.join(".psroot").join("shell-catalog.d");
            cat.merge_dir(&dir);
        }
        Self {
            catalog: cat,
            probe: RealProbe,
        }
    }
}

impl<P: HostProbe> Resolver<P> {
    pub fn with_catalog(catalog: Catalog, probe: P) -> Self {
        Self { catalog, probe }
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn lookup(&self, name: &str) -> Option<&CatalogFile> {
        self.catalog.lookup(name)
    }

    pub fn list_known(&self) -> Vec<&str> {
        self.catalog.list_known()
    }

    pub fn resolve(&self, req: &ShellRequest, ctx: &ResolveContext) -> Result<LaunchPlan> {
        let entry = self
            .catalog
            .lookup(&req.name)
            .ok_or_else(|| ShellResolverError::UnknownShell(req.name.clone()))?;

        // 1. Probe — find host shell.
        let host = self.probe.find(entry)?.ok_or_else(|| {
            ShellResolverError::ShellNotInstalled {
                shell: entry.name.clone(),
                hint: format!(
                    "install it (e.g. `winget install Microsoft.{}`) or set the env override",
                    entry.name
                ),
            }
        })?;

        // 2. Version constraint.
        if let Some(req_ver) = &req.version {
            if !req_ver.matches(&host.version) {
                return Err(ShellResolverError::VersionMismatch {
                    shell: entry.name.clone(),
                    wanted: req_ver.raw().to_string(),
                    found: host.version.clone(),
                });
            }
        }
        if let Some(ver_rule) = entry.version.as_ref() {
            if let Some(min) = ver_rule.min.as_ref() {
                if let Some(min_req) = VersionReq::parse(&format!(">={min}")) {
                    if !min_req.matches(&host.version) {
                        return Err(ShellResolverError::VersionMismatch {
                            shell: entry.name.clone(),
                            wanted: format!(">={min}"),
                            found: host.version.clone(),
                        });
                    }
                }
            }
        }

        // 3. Cache key + cache dir.
        let cache_key = format!("{}-{}", entry.name, host.version);
        let cache_dir = ctx.cache_root.join(&cache_key);

        // 4. Build substitution table.
        let vars = build_vars(ctx, &host, &cache_dir);

        // 5. Substitute stage ops.
        let stage = entry
            .stage
            .iter()
            .map(|s| substitute_stage(s, &vars))
            .collect::<Result<Vec<_>>>()?;

        // 6. Substitute ACE grants.
        let aces = entry
            .ace
            .iter()
            .map(|a| {
                Ok(AceGrant {
                    path: PathBuf::from(substitute(&a.path, &vars)?),
                    access: match a.access.as_str() {
                        "RX" | "rx" => AccessMask::ReadExecute,
                        other => {
                            return Err(ShellResolverError::PlaceholderUnknown(format!(
                                "access mask {other}"
                            )))
                        }
                    },
                    inherit: a.inherit,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // 7. Launch substitution.
        let launch_entry = PathBuf::from(substitute(&entry.launch.entry, &vars)?);
        let cwd = PathBuf::from(substitute(&entry.launch.cwd, &vars)?);
        let mut args: Vec<String> = entry
            .launch
            .args
            .iter()
            .map(|a| substitute(a, &vars))
            .collect::<Result<Vec<_>>>()?;
        args.extend(req.args.iter().cloned());

        let mut env: Vec<(String, String)> = entry
            .launch
            .env
            .iter()
            .map(|(k, v)| Ok((k.clone(), substitute(v, &vars)?)))
            .collect::<Result<Vec<_>>>()?;
        env.extend(req.env.iter().cloned());

        // 8. Capability selection per network mode.
        let cap_names: Vec<&String> = match ctx.network {
            NetworkAccess::None | NetworkAccess::Netstack => vec![],
            NetworkAccess::Outbound => entry.caps_when_outbound.iter().collect(),
            NetworkAccess::Full => entry.caps_when_full.iter().collect(),
        };
        let mut caps = Vec::with_capacity(cap_names.len());
        for c in cap_names {
            caps.push(KnownCapability::from_name(c).ok_or_else(|| {
                ShellResolverError::InvalidCapability {
                    shell: entry.name.clone(),
                    cap: c.clone(),
                }
            })?);
        }

        Ok(LaunchPlan {
            shell_name: entry.name.clone(),
            host_source_version: host.version.clone(),
            cache_key,
            cache_dir,
            entry: launch_entry,
            args,
            cwd,
            env,
            stage,
            aces,
            caps,
        })
    }
}

fn build_vars(ctx: &ResolveContext, host: &HostShell, cache_dir: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("rootfs".into(), ctx.rootfs.display().to_string());
    m.insert("shell_root".into(), host.root.display().to_string());
    m.insert("cache_dir".into(), cache_dir.display().to_string());
    m.insert("cache_root".into(), ctx.cache_root.display().to_string());
    m.insert("container_id".into(), ctx.container_id.to_string());
    m.insert(
        "system_root".into(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()),
    );
    m.insert(
        "program_files".into(),
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()),
    );
    m
}

fn substitute(s: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let key = &after[..close];
            match vars.get(key) {
                Some(val) => out.push_str(val),
                None => return Err(ShellResolverError::PlaceholderUnknown(key.to_string())),
            }
            rest = &after[close + 1..];
        } else {
            // Stray `{` — emit as-is.
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    Ok(out)
}

fn substitute_stage(rule: &StageRule, vars: &BTreeMap<String, String>) -> Result<StageOp> {
    let dst = PathBuf::from(substitute(&rule.dst, vars)?);
    let src = match rule.src.as_ref() {
        Some(s) => Some(PathBuf::from(substitute(s, vars)?)),
        None => None,
    };
    Ok(match rule.op.as_str() {
        "ensure_dir" => StageOp::EnsureDir { dst },
        "hardlink_tree" => StageOp::HardlinkTree {
            src: src.ok_or_else(|| ShellResolverError::PlaceholderUnknown("src".into()))?,
            dst,
            exclude: rule.exclude.clone(),
        },
        "copy_tree" => StageOp::CopyTree {
            src: src.ok_or_else(|| ShellResolverError::PlaceholderUnknown("src".into()))?,
            dst,
            exclude: rule.exclude.clone(),
        },
        "junction" => StageOp::Junction {
            src: src.ok_or_else(|| ShellResolverError::PlaceholderUnknown("src".into()))?,
            dst,
        },
        "symlink" => StageOp::Symlink {
            src: src.ok_or_else(|| ShellResolverError::PlaceholderUnknown("src".into()))?,
            dst,
        },
        "write_text" => {
            let raw = rule.content.as_deref().ok_or_else(|| {
                ShellResolverError::PlaceholderUnknown("write_text requires 'content'".into())
            })?;
            let content = if let Some(key) = raw.strip_prefix("@builtin:") {
                crate::catalog::builtin_module(key)
                    .ok_or_else(|| ShellResolverError::PlaceholderUnknown(format!("unknown builtin module: {key}")))?                    .to_string()
            } else {
                substitute(raw, vars)?
            };
            StageOp::WriteText { dst, content }
        }
        other => {
            return Err(ShellResolverError::PlaceholderUnknown(format!(
                "stage op {other}"
            )))
        }
    })
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
}
