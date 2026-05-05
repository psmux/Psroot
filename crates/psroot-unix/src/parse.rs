use crate::{Error, Result};

/// Parse a memory limit like "512M", "1G", "1024" (bytes).
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() { return Err(Error::Invalid("empty size".into())); }
    let (num_str, mult) = match s.chars().last().unwrap() {
        'k' | 'K' => (&s[..s.len()-1], 1024u64),
        'm' | 'M' => (&s[..s.len()-1], 1024u64 * 1024),
        'g' | 'G' => (&s[..s.len()-1], 1024u64 * 1024 * 1024),
        _ => (s, 1u64),
    };
    let n: u64 = num_str.trim().parse().map_err(|_| Error::Invalid(format!("bad size: {s}")))?;
    Ok(n.saturating_mul(mult))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn k() { assert_eq!(parse_size("4K").unwrap(), 4096); }
    #[test] fn m() { assert_eq!(parse_size("64M").unwrap(), 64*1024*1024); }
    #[test] fn g() { assert_eq!(parse_size("1G").unwrap(), 1024*1024*1024); }
    #[test] fn raw() { assert_eq!(parse_size("12345").unwrap(), 12345); }
}
