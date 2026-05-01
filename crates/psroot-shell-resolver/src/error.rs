use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShellResolverError {
    #[error("unknown shell '{0}' (catalog has no entry or alias for it)")]
    UnknownShell(String),

    #[error("shell '{shell}' is not installed on this host. {hint}")]
    ShellNotInstalled { shell: String, hint: String },

    #[error("shell '{shell}' version {found} does not satisfy constraint {wanted}")]
    VersionMismatch { shell: String, wanted: String, found: String },

    #[error("catalog parse error in {path}: {source}")]
    CatalogParse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("catalog entry '{shell}' has invalid capability '{cap}' (must be a KnownCapability)")]
    InvalidCapability { shell: String, cap: String },

    #[error("placeholder {{{0}}} could not be substituted")]
    PlaceholderUnknown(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ShellResolverError>;
