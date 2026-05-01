//! Lightweight version constraint matching.
//!
//! Supports: exact "7.5.0", ">=7.4", ">7.3", "<8", "~7.5" (>=7.5.0 <7.6.0).
//! Whitespace tolerant.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionReq {
    raw: String,
    op: Op,
    target: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    Tilde,
}

fn parse_version(s: &str) -> Vec<u32> {
    s.trim()
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect()
}

fn cmp_versions(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => {}
            o => return o,
        }
    }
    std::cmp::Ordering::Equal
}

impl VersionReq {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (op, rest) = if let Some(r) = s.strip_prefix(">=") {
            (Op::Ge, r)
        } else if let Some(r) = s.strip_prefix("<=") {
            (Op::Le, r)
        } else if let Some(r) = s.strip_prefix('>') {
            (Op::Gt, r)
        } else if let Some(r) = s.strip_prefix('<') {
            (Op::Lt, r)
        } else if let Some(r) = s.strip_prefix('~') {
            (Op::Tilde, r)
        } else if let Some(r) = s.strip_prefix('=') {
            (Op::Eq, r)
        } else {
            (Op::Eq, s)
        };
        let target = parse_version(rest);
        if target.is_empty() {
            return None;
        }
        Some(Self {
            raw: s.to_string(),
            op,
            target,
        })
    }

    pub fn matches(&self, version: &str) -> bool {
        let v = parse_version(version);
        let ord = cmp_versions(&v, &self.target);
        match self.op {
            Op::Eq => ord == std::cmp::Ordering::Equal
                || (v.len() >= self.target.len() && v[..self.target.len()] == self.target[..]),
            Op::Ge => ord != std::cmp::Ordering::Less,
            Op::Gt => ord == std::cmp::Ordering::Greater,
            Op::Le => ord != std::cmp::Ordering::Greater,
            Op::Lt => ord == std::cmp::Ordering::Less,
            Op::Tilde => {
                // ~7.5  -> >=7.5  AND <7.(5+1)? Treat as same major+minor band.
                if v.len() < self.target.len() {
                    return false;
                }
                if cmp_versions(&v, &self.target) == std::cmp::Ordering::Less {
                    return false;
                }
                if self.target.len() >= 2 {
                    let mut upper = self.target.clone();
                    upper.truncate(2);
                    upper[1] += 1;
                    return cmp_versions(&v, &upper) == std::cmp::Ordering::Less;
                }
                if self.target.len() == 1 {
                    let mut upper = self.target.clone();
                    upper[0] += 1;
                    return cmp_versions(&v, &upper) == std::cmp::Ordering::Less;
                }
                true
            }
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ge_works() {
        let r = VersionReq::parse(">=7.4").unwrap();
        assert!(r.matches("7.4.0"));
        assert!(r.matches("7.6.0"));
        assert!(!r.matches("7.3.99"));
    }

    #[test]
    fn tilde_works() {
        let r = VersionReq::parse("~7.5").unwrap();
        assert!(r.matches("7.5.0"));
        assert!(r.matches("7.5.99"));
        assert!(!r.matches("7.6.0"));
        assert!(!r.matches("7.4.99"));
    }

    #[test]
    fn exact_prefix_match() {
        let r = VersionReq::parse("7.5").unwrap();
        assert!(r.matches("7.5.0"));
        assert!(r.matches("7.5.99"));
        assert!(!r.matches("7.4.0"));
    }
}
