use url::Url;

/// Resolves standard Nuclei variable placeholders in a path or string.
pub struct VariableResolver;

impl VariableResolver {
    /// Replace all standard Nuclei placeholders with values derived from the target URL.
    ///
    /// Supported placeholders:
    /// - `{{BaseURL}}` — full target URL without trailing slash
    /// - `{{RootURL}}` — scheme + host (no port, no path)
    /// - `{{Hostname}}` — hostname without port
    /// - `{{Host}}` — hostname:port
    /// - `{{Port}}` — port number (defaults to 80/443)
    /// - `{{Path}}` — URL path component
    /// - `{{Scheme}}` — http or https
    pub fn resolve(input: &str, target_url: &str) -> String {
        let parsed = match Url::parse(target_url) {
            Ok(u) => u,
            Err(_) => return input.to_string(),
        };

        let base_url = target_url.trim_end_matches('/');
        let host = parsed.host_str().unwrap_or_default();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let root_url = format!("{}://{}", parsed.scheme(), host);

        input
            .replace("{{BaseURL}}", base_url)
            .replace("{{RootURL}}", &root_url)
            .replace("{{Hostname}}", host)
            .replace("{{Host}}", &format!("{}:{}", host, port))
            .replace("{{Port}}", &port.to_string())
            .replace("{{Path}}", parsed.path())
            .replace("{{Scheme}}", parsed.scheme())
    }

    /// Resolve a raw path into a full URL using the target as context.
    /// If the path already starts with http:// or https://, resolve variables inline.
    /// Otherwise, join the path to the base URL.
    #[allow(dead_code)]
    pub fn resolve_path(raw_path: &str, target_url: &str) -> Option<String> {
        let resolved = Self::resolve(raw_path, target_url);

        // If the resolved path is already a full URL, return as-is.
        if resolved.starts_with("http://") || resolved.starts_with("https://") {
            return Some(resolved);
        }

        // Otherwise, join path to the target URL base.
        let base = target_url.trim_end_matches('/');
        let path = if resolved.starts_with('/') {
            &resolved
        } else {
            return Some(format!("{}/{}", base, resolved));
        };

        Some(format!("{}{}", base, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_url_substitution() {
        let result = VariableResolver::resolve(
            "{{BaseURL}}/admin",
            "https://example.com",
        );
        assert_eq!(result, "https://example.com/admin");
    }

    #[test]
    fn test_all_variables() {
        let result = VariableResolver::resolve(
            "{{Scheme}}://{{Hostname}}:{{Port}}{{Path}}",
            "https://example.com:8443/api/v1",
        );
        assert_eq!(result, "https://example.com:8443/api/v1");
    }

    #[test]
    fn test_resolve_path_full_url() {
        let result = VariableResolver::resolve_path(
            "{{BaseURL}}/wp-login.php",
            "https://target.com",
        );
        assert_eq!(result, Some("https://target.com/wp-login.php".to_string()));
    }

    #[test]
    fn test_resolve_path_relative() {
        let result = VariableResolver::resolve_path(
            "/api/debug",
            "https://target.com",
        );
        assert_eq!(result, Some("https://target.com/api/debug".to_string()));
    }
}
