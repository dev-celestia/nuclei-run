use url::Url;

/// Resolves standard Nuclei variable placeholders in a path or string.
///
/// Semantics mirror Go nuclei's `generateVariables`
/// (`pkg/protocols/utils/variables.go`):
/// - `{{BaseURL}}`  — full target URL without trailing slash
/// - `{{RootURL}}`  — scheme + host, including the port when explicitly given
/// - `{{Hostname}}` — host with port when the target specifies one
/// - `{{Host}}`     — hostname only, without port
/// - `{{Port}}`     — port number (defaults to 80/443 for http/https)
/// - `{{Path}}`     — directory portion of the path (`path.Dir`), empty for bare hosts
/// - `{{Query}}`    — `?` + query pairs sorted by key, empty when absent
/// - `{{File}}`     — last path segment (`path.Base`)
/// - `{{Scheme}}`   — http or https
/// - `{{Input}}`    — the target exactly as supplied
/// - `{{FQDN}}` / `{{RDN}}` / `{{DN}}` / `{{TLD}}` / `{{SD}}` — DNS-derived
///   via the Public Suffix List (only FQDN is set when no suffix applies)
pub struct VariableResolver;

impl VariableResolver {
    /// Replace all standard Nuclei placeholders with values derived from the target URL.
    pub fn resolve(input: &str, target_url: &str) -> String {
        let parsed = match Url::parse(target_url) {
            Ok(u) => u,
            Err(_) => return input.to_string(),
        };

        let host = parsed.host_str().unwrap_or_default().to_string();
        // Go's parsed.Host carries the port only when the input URL does.
        let hostname = match parsed.port() {
            Some(p) => format!("{}:{}", host, p),
            None => host.clone(),
        };
        let port = match parsed.port_or_known_default() {
            Some(p) => p.to_string(),
            None => match parsed.scheme() {
                "https" => "443".to_string(),
                "http" => "80".to_string(),
                _ => String::new(),
            },
        };

        let raw_path = raw_path_of(target_url, &parsed);
        let path = dir_of(&raw_path);
        let file = base_of(&raw_path);
        let query = query_of(&parsed);

        let mut out = input
            .replace("{{BaseURL}}", target_url.trim_end_matches('/'))
            .replace(
                "{{RootURL}}",
                &format!("{}://{}", parsed.scheme(), hostname),
            )
            .replace("{{Hostname}}", &hostname)
            .replace("{{Host}}", &host)
            .replace("{{Port}}", &port)
            .replace("{{Path}}", &path)
            .replace("{{Query}}", &query)
            .replace("{{File}}", &file)
            .replace("{{Scheme}}", parsed.scheme())
            .replace("{{Input}}", target_url);

        out = out.replace("{{FQDN}}", &host);
        if let Some((rdn, dn, tld, sd)) = split_domain(&host) {
            out = out
                .replace("{{RDN}}", &rdn)
                .replace("{{DN}}", &dn)
                .replace("{{TLD}}", &tld)
                .replace("{{SD}}", &sd);
        }

        out
    }

    /// Resolve a raw path into a full URL using the target as context.
    /// If the path already starts with http:// or https://, resolve variables inline.
    /// Otherwise, join the path to the base URL.
    #[allow(dead_code)]
    pub fn resolve_path(raw_path: &str, target_url: &str) -> Option<String> {
        let resolved = Self::resolve(raw_path, target_url);

        // If the resolved path is already a full URL, return it as-is.
        if resolved.starts_with("http://") || resolved.starts_with("https://") {
            return Some(resolved);
        }

        // Otherwise, join the path to the target URL base.
        let base = target_url.trim_end_matches('/');
        let path = if resolved.starts_with('/') {
            &resolved
        } else {
            return Some(format!("{}/{}", base, resolved));
        };

        Some(format!("{}{}", base, path))
    }
}

/// Path portion of the target as written (percent-encoding preserved).
/// Empty when the URL has no path component.
fn raw_path_of(target: &str, parsed: &Url) -> String {
    let idx = parsed.scheme().len() + 3; // skip "scheme://"
    if target.len() <= idx {
        return String::new();
    }
    let after = &target[idx..];
    match after.find(['/', '?', '#']) {
        Some(pos) if after.as_bytes()[pos] == b'/' => after[pos..]
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

/// Go `path.Dir` semantics: the directory portion of a path.
fn dir_of(p: &str) -> String {
    let stripped = p.trim_end_matches('/');
    let dir = if stripped.is_empty() {
        if p.is_empty() {
            "."
        } else {
            "/"
        }
    } else {
        match stripped.rfind('/') {
            None => ".",
            Some(0) => "/",
            Some(i) => &stripped[..i],
        }
    };
    if dir == "." {
        String::new()
    } else {
        dir.to_string()
    }
}

/// Go `path.Base` semantics: the last segment of a path.
fn base_of(p: &str) -> String {
    let stripped = p.trim_end_matches('/');
    let base = if stripped.is_empty() {
        if p.is_empty() {
            "."
        } else {
            "/"
        }
    } else {
        match stripped.rfind('/') {
            None => stripped,
            Some(i) => &stripped[i + 1..],
        }
    };
    if base == "." {
        String::new()
    } else {
        base.to_string()
    }
}

/// Go-style query variable: `?` + pairs sorted by key, empty when absent.
fn query_of(parsed: &Url) -> String {
    match parsed.query() {
        Some(q) if !q.is_empty() => {
            let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            format!("?{}", encoded)
        }
        _ => String::new(),
    }
}

/// Split a hostname into (RDN, DN, TLD, SD) using the Public Suffix List,
/// mirroring Go's `splitDomain`. Returns None when no suffix applies
/// (Go then only exposes FQDN).
fn split_domain(host: &str) -> Option<(String, String, String, String)> {
    let normalized = host.trim_end_matches('.');
    let rdn = psl::domain_str(normalized)?.to_string();
    let tld = psl::suffix_str(normalized)?.to_string();
    let dn = rdn.strip_suffix(&format!(".{}", tld))?.to_string();
    if dn.is_empty() || dn == rdn {
        return None;
    }
    let sd = normalized
        .strip_suffix(&format!(".{}", rdn))
        .unwrap_or("")
        .to_string();
    Some((rdn, dn, tld, sd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_url_substitution() {
        let result = VariableResolver::resolve("{{BaseURL}}/admin", "https://example.com");
        assert_eq!(result, "https://example.com/admin");
    }

    #[test]
    fn test_default_port_url() {
        // No explicit port: Hostname == Host, RootURL omits the port.
        let target = "https://example.com/api/v1";
        assert_eq!(
            VariableResolver::resolve("{{Hostname}}", target),
            "example.com"
        );
        assert_eq!(VariableResolver::resolve("{{Host}}", target), "example.com");
        assert_eq!(
            VariableResolver::resolve("{{RootURL}}", target),
            "https://example.com"
        );
        assert_eq!(VariableResolver::resolve("{{Port}}", target), "443");
        assert_eq!(VariableResolver::resolve("{{Path}}", target), "/api");
        assert_eq!(VariableResolver::resolve("{{File}}", target), "v1");
        assert_eq!(VariableResolver::resolve("{{Scheme}}", target), "https");
    }

    #[test]
    fn test_explicit_port_url() {
        // Explicit port: Hostname carries it, Host does not, RootURL keeps it.
        let target = "http://127.0.0.1:8080/sub/dir/page.html?b=2&a=1";
        assert_eq!(
            VariableResolver::resolve("{{Hostname}}", target),
            "127.0.0.1:8080"
        );
        assert_eq!(VariableResolver::resolve("{{Host}}", target), "127.0.0.1");
        assert_eq!(
            VariableResolver::resolve("{{RootURL}}", target),
            "http://127.0.0.1:8080"
        );
        assert_eq!(VariableResolver::resolve("{{Port}}", target), "8080");
        assert_eq!(VariableResolver::resolve("{{Path}}", target), "/sub/dir");
        assert_eq!(VariableResolver::resolve("{{File}}", target), "page.html");
        assert_eq!(VariableResolver::resolve("{{Query}}", target), "?a=1&b=2");
        assert_eq!(VariableResolver::resolve("{{Input}}", target), target);
    }

    #[test]
    fn test_bare_host_and_root_path() {
        assert_eq!(
            VariableResolver::resolve("{{Path}}", "https://example.com"),
            ""
        );
        assert_eq!(
            VariableResolver::resolve("{{File}}", "https://example.com"),
            ""
        );
        assert_eq!(
            VariableResolver::resolve("{{Query}}", "https://example.com"),
            ""
        );
        assert_eq!(
            VariableResolver::resolve("{{Path}}", "https://example.com/"),
            "/"
        );
        assert_eq!(
            VariableResolver::resolve("{{File}}", "https://example.com/"),
            "/"
        );
        assert_eq!(
            VariableResolver::resolve("{{BaseURL}}", "https://example.com/"),
            "https://example.com"
        );
    }

    #[test]
    fn test_single_segment_path() {
        assert_eq!(
            VariableResolver::resolve("{{Path}}", "https://example.com/admin"),
            "/"
        );
        assert_eq!(
            VariableResolver::resolve("{{File}}", "https://example.com/admin"),
            "admin"
        );
    }

    #[test]
    fn test_dns_variables() {
        let target = "https://sub.example.co.uk/x";
        assert_eq!(
            VariableResolver::resolve("{{FQDN}}", target),
            "sub.example.co.uk"
        );
        assert_eq!(
            VariableResolver::resolve("{{RDN}}", target),
            "example.co.uk"
        );
        assert_eq!(VariableResolver::resolve("{{DN}}", target), "example");
        assert_eq!(VariableResolver::resolve("{{TLD}}", target), "co.uk");
        assert_eq!(VariableResolver::resolve("{{SD}}", target), "sub");

        // No subdomain -> SD empty.
        let target = "https://example.com/";
        assert_eq!(VariableResolver::resolve("{{RDN}}", target), "example.com");
        assert_eq!(VariableResolver::resolve("{{TLD}}", target), "com");
        assert_eq!(VariableResolver::resolve("{{SD}}", target), "");
    }

    #[test]
    fn test_compose_roundtrip() {
        let result = VariableResolver::resolve(
            "{{Scheme}}://{{Hostname}}{{Path}}/{{File}}",
            "https://example.com:8443/api/v1",
        );
        assert_eq!(result, "https://example.com:8443/api/v1");
    }

    #[test]
    fn test_resolve_path_full_url() {
        let result =
            VariableResolver::resolve_path("{{BaseURL}}/wp-login.php", "https://target.com");
        assert_eq!(result, Some("https://target.com/wp-login.php".to_string()));
    }

    #[test]
    fn test_resolve_path_relative() {
        let result = VariableResolver::resolve_path("/api/debug", "https://target.com");
        assert_eq!(result, Some("https://target.com/api/debug".to_string()));
    }
}
