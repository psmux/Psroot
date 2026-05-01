use psroot_shell_resolver::catalog::schema::CatalogFile;

fn main() {
    const PWSH: &str = include_str!("../catalog/pwsh.toml");
    const CMD: &str = include_str!("../catalog/cmd.toml");
    const PS: &str = include_str!("../catalog/powershell.toml");
    for (name, src) in [("pwsh", PWSH), ("cmd", CMD), ("powershell", PS)] {
        match toml::from_str::<CatalogFile>(src) {
            Ok(c) => println!("OK  {} -> name={} aliases={:?}", name, c.name, c.aliases),
            Err(e) => println!("ERR {}: {}", name, e),
        }
    }
}
