use thiserror::Error;

/// Unified error type for all Psroot operations.
#[derive(Debug, Error)]
pub enum PsrootError {
    #[error("Win32 error in {op}: code {code} (0x{code:08x})")]
    Win32 { op: &'static str, code: u32 },

    #[error("NT status in {op}: 0x{status:08x}")]
    NtStatus { op: &'static str, status: u32 },

    #[error("HRESULT in {op}: 0x{hr:08x}")]
    HResult { op: &'static str, hr: u32 },

    #[error("Container '{id}' is in state {current}, expected {expected}")]
    InvalidState {
        id: String,
        current: String,
        expected: String,
    },

    #[error("Container '{id}' not found")]
    NotFound { id: String },

    #[error("Requires Administrator privileges for: {op}")]
    AdminRequired { op: &'static str },

    #[error("Platform unsupported: {detail}")]
    Unsupported { detail: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl PsrootError {
    /// Create from GetLastError() result.
    pub fn last_win32(op: &'static str) -> Self {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::Win32 { op, code }
    }

    pub fn win32(op: &'static str, code: u32) -> Self {
        Self::Win32 { op, code }
    }

    pub fn nt(op: &'static str, status: u32) -> Self {
        Self::NtStatus { op, status }
    }

    pub fn hr(op: &'static str, hr: u32) -> Self {
        Self::HResult { op, hr }
    }

    /// Numeric error code for FFI returns.
    pub fn code(&self) -> i32 {
        match self {
            Self::Win32 { code, .. } => *code as i32,
            Self::NtStatus { status, .. } => *status as i32,
            Self::HResult { hr, .. } => *hr as i32,
            _ => -1,
        }
    }
}

pub type Result<T> = std::result::Result<T, PsrootError>;

// We need windows_sys just for GetLastError in error.rs
// Add a feature-gated dependency via lib.rs
