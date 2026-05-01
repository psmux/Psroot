use psroot_shell_resolver::*;
use std::path::PathBuf;

fn ctx<'a>(rootfs: &'a std::path::Path, cache_root: &'a std::path::Path) -> ResolveContext<'a> {
    ResolveContext {
        container_id: "test-id",
        rootfs,
        network: NetworkAccess::Outbound,
        cache_root,
        allow_admin: false,
    }
}

#[test]
fn builtin_catalog_loads() {
    let cat = Catalog::builtin();
    assert!(cat.lookup("pwsh").is_some());
    assert!(cat.lookup("PWSH").is_some(), "lookup is case-insensitive");
    assert!(cat.lookup("cmd").is_some());
    assert!(cat.lookup("powershell").is_some());
}

#[test]
fn alias_lookup_works() {
    let cat = Catalog::builtin();
    assert!(cat.lookup("powershell-core").is_some());
    assert!(cat.lookup("pwsh7").is_some());
}

#[test]
fn unknown_shell_errors() {
    let cat = Catalog::builtin();
    let r = Resolver::with_catalog(cat, MockProbe::default());
    let rootfs = PathBuf::from("C:\\rootfs");
    let cache = PathBuf::from("C:\\cache");
    let res = r.resolve(&ShellRequest::new("xyz-not-real"), &ctx(&rootfs, &cache));
    assert!(matches!(res, Err(ShellResolverError::UnknownShell(_))));
}

#[test]
fn pwsh_outbound_has_internet_client() {
    let cat = Catalog::builtin();
    let probe = MockProbe::default().with(
        "pwsh",
        HostShell {
            root: PathBuf::from("C:\\PF\\PowerShell\\7"),
            entry: PathBuf::from("C:\\PF\\PowerShell\\7\\pwsh.exe"),
            version: "7.6.0".into(),
        },
    );
    let r = Resolver::with_catalog(cat, probe);
    let rootfs = PathBuf::from("C:\\rootfs");
    let cache = PathBuf::from("C:\\cache");
    let plan = r
        .resolve(&ShellRequest::new("pwsh"), &ctx(&rootfs, &cache))
        .unwrap();
    assert!(plan.entry.to_string_lossy().contains("PSH\\pwsh.exe"));
    assert_eq!(plan.caps, vec![KnownCapability::InternetClient]);
    assert_eq!(plan.host_source_version, "7.6.0");
    assert_eq!(plan.cache_key, "pwsh-7.6.0");
}

#[test]
fn pwsh_no_network_no_caps() {
    let cat = Catalog::builtin();
    let probe = MockProbe::default().with(
        "pwsh",
        HostShell {
            root: PathBuf::from("C:\\PF\\PowerShell\\7"),
            entry: PathBuf::from("C:\\PF\\PowerShell\\7\\pwsh.exe"),
            version: "7.6.0".into(),
        },
    );
    let r = Resolver::with_catalog(cat, probe);
    let rootfs = PathBuf::from("C:\\rootfs");
    let cache = PathBuf::from("C:\\cache");
    let mut c = ctx(&rootfs, &cache);
    c.network = NetworkAccess::None;
    let plan = r.resolve(&ShellRequest::new("pwsh"), &c).unwrap();
    assert!(plan.caps.is_empty());
}

#[test]
fn min_version_enforced() {
    let cat = Catalog::builtin();
    let probe = MockProbe::default().with(
        "pwsh",
        HostShell {
            root: PathBuf::from("C:\\PF\\PowerShell\\7"),
            entry: PathBuf::from("C:\\PF\\PowerShell\\7\\pwsh.exe"),
            version: "6.0.0".into(),
        },
    );
    let r = Resolver::with_catalog(cat, probe);
    let rootfs = PathBuf::from("C:\\rootfs");
    let cache = PathBuf::from("C:\\cache");
    let res = r.resolve(&ShellRequest::new("pwsh"), &ctx(&rootfs, &cache));
    assert!(matches!(res, Err(ShellResolverError::VersionMismatch { .. })));
}

#[test]
fn placeholders_substituted() {
    let cat = Catalog::builtin();
    let probe = MockProbe::default().with(
        "pwsh",
        HostShell {
            root: PathBuf::from("C:\\PF\\PowerShell\\7"),
            entry: PathBuf::from("C:\\PF\\PowerShell\\7\\pwsh.exe"),
            version: "7.6.0".into(),
        },
    );
    let r = Resolver::with_catalog(cat, probe);
    let rootfs = PathBuf::from("C:\\rootfs");
    let cache = PathBuf::from("C:\\cache");
    let plan = r
        .resolve(&ShellRequest::new("pwsh"), &ctx(&rootfs, &cache))
        .unwrap();

    // entry path prefixed with rootfs
    assert!(plan.entry.starts_with(&rootfs));
    // cwd inside rootfs
    assert!(plan.cwd.starts_with(&rootfs));
    // env contains DOTNET_ROOT pointing into rootfs
    assert!(plan
        .env
        .iter()
        .any(|(k, v)| k == "DOTNET_ROOT" && v.contains("rootfs")));
    // cache_dir under cache_root
    assert!(plan.cache_dir.starts_with(&cache));
    // ace path is the cache dir
    assert_eq!(plan.aces.len(), 1);
    assert_eq!(plan.aces[0].path, plan.cache_dir);
}
