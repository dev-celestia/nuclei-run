//! Honeypot detection based on match concentration, mirroring nuclei's
//! `pkg/protocols/common/honeypotdetector`.
//!
//! A host that matches many *distinct* vulnerability templates is a strong
//! catch-all / honeypot signal. The detector counts distinct template IDs per
//! normalized host and flags the host once the configured threshold is reached.
//! When suppression is enabled, results for flagged hosts are dropped.

use std::collections::{HashMap, HashSet};

/// Detector tracks distinct matched templates per normalized host.
pub struct Detector {
    threshold: usize,
    hosts: HashMap<String, HostState>,
}

struct HostState {
    template_ids: HashSet<String>,
    flagged: bool,
}

impl Detector {
    /// Create a detector; a threshold of 0 is treated as 1.
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold: threshold.max(1),
            hosts: HashMap::new(),
        }
    }

    /// The distinct-template threshold required to flag a host.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Record a match for `host` + `template_id`. Returns true only when the
    /// host has *just* crossed the flagging threshold.
    pub fn record_match(&mut self, host: &str, template_id: &str) -> bool {
        let key = Self::normalize_host_key(host);
        if key.is_empty() || template_id.is_empty() {
            return false;
        }

        let state = self.hosts.entry(key).or_insert_with(|| HostState {
            template_ids: HashSet::new(),
            flagged: false,
        });

        if state.flagged || !state.template_ids.insert(template_id.to_string()) {
            return false;
        }

        if state.template_ids.len() >= self.threshold {
            state.flagged = true;
            state.template_ids.clear();
            return true;
        }
        false
    }

    /// Whether the given host is flagged as a potential honeypot.
    pub fn is_flagged(&self, host: &str) -> bool {
        let key = Self::normalize_host_key(host);
        self.hosts.get(&key).map(|s| s.flagged).unwrap_or(false)
    }

    /// Short summary string with the number of flagged hosts.
    pub fn summary(&self) -> String {
        let flagged = self.hosts.values().filter(|s| s.flagged).count();
        format!("honeypot-detected hosts: {}", flagged)
    }

    /// Normalize host strings so different input formats map to the same key.
    pub fn normalize_host_key(input: &str) -> String {
        let mut s = input.trim().to_string();
        if s.is_empty() {
            return String::new();
        }
        // Strip trailing slashes.
        while s.ends_with('/') {
            s.pop();
        }

        // Absolute URL: extract authority (host and optional explicit port).
        if s.contains("://") {
            if let Ok(u) = url::Url::parse(&s) {
                if let Some(host) = u.host_str() {
                    let host = normalize_host_without_port(host);
                    // The `url` crate normalizes away default ports (e.g. `:443`
                    // for https), but Go's url.Parse preserves the explicit
                    // port — extract it from the authority string directly.
                    return match explicit_port(&s) {
                        Some(port) => format!("{}:{}", host, port),
                        None => host,
                    };
                }
                return String::new();
            }
            // fall through on parse failure
        }

        // Remove any path suffix.
        if let Some(idx) = s.find('/') {
            s.truncate(idx);
        }

        // Bracketed IPv6, possibly with port: [::1]:8080 or [::1].
        if s.starts_with('[') {
            if let Some(end) = s.find(']') {
                let host = normalize_host_without_port(&s[1..end]);
                let rest = &s[end + 1..];
                return match rest.strip_prefix(':') {
                    Some(port) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                        format!("{}:{}", host, port)
                    }
                    _ => host,
                };
            }
        }

        // Bare host:port (exactly one colon, numeric port).
        let colons = s.matches(':').count();
        if colons == 1 {
            if let Some(colon) = s.find(':') {
                let (host_part, port_part) = s.split_at(colon);
                let port_part = &port_part[1..];
                if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
                    let host = normalize_host_without_port(host_part);
                    if !host.is_empty() {
                        return format!("{}:{}", host, port_part);
                    }
                }
            }
        }

        // Bare host or bare IPv6.
        normalize_host_without_port(&s)
    }
}

fn normalize_host_without_port(host: &str) -> String {
    let mut h = host.trim().to_string();
    if h.starts_with('[') {
        h.remove(0);
    }
    if h.ends_with(']') {
        h.pop();
    }
    h = h.to_lowercase();
    if h.is_empty() {
        return String::new();
    }
    // Normalize IPs to their canonical form.
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    h
}

/// Extract the explicit port from an absolute URL's authority, if present.
fn explicit_port(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // Strip userinfo (user:pass@).
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);

    // Bracketed IPv6: [::1]:8080
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return authority[end + 1..].strip_prefix(':').map(|p| p.to_string());
    }

    // host:port — the port must be numeric.
    let (host, port) = authority.rsplit_once(':')?;
    if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
        Some(port.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_host_key() {
        assert_eq!(Detector::normalize_host_key("https://Example.COM:443/path"), "example.com:443");
        assert_eq!(Detector::normalize_host_key("http://example.com/"), "example.com");
        assert_eq!(Detector::normalize_host_key("Example.com:8080"), "example.com:8080");
        assert_eq!(Detector::normalize_host_key("192.168.1.1:80"), "192.168.1.1:80");
        assert_eq!(Detector::normalize_host_key("[2001:db8::1]:8080"), "2001:db8::1:8080");
        assert_eq!(Detector::normalize_host_key("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(Detector::normalize_host_key("2001:db8::1"), "2001:db8::1");
        assert_eq!(Detector::normalize_host_key(""), "");
    }

    #[test]
    fn test_record_match_flags_at_threshold() {
        let mut d = Detector::new(3);
        let host = "https://Example.com/";
        assert!(!d.record_match(host, "a"));
        assert!(!d.record_match(host, "b"));
        assert!(!d.is_flagged(host));
        assert!(d.record_match(host, "c")); // crosses threshold
        assert!(d.is_flagged(host));

        // Duplicate template IDs don't advance the counter.
        let mut d2 = Detector::new(2);
        assert!(!d2.record_match("h", "x"));
        assert!(!d2.record_match("h", "x"));
        assert!(!d2.is_flagged("h"));
        assert!(d2.record_match("h", "y"));
        assert!(d2.is_flagged("h"));
    }

    #[test]
    fn test_summary() {
        let mut d = Detector::new(2);
        d.record_match("h", "a");
        d.record_match("h", "b");
        assert_eq!(d.summary(), "honeypot-detected hosts: 1");
    }
}
