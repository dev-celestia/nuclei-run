use crate::engine::dsl::TemplateDsl;
use crate::models::template::{HttpBlock, TemplateMatcher};
use std::collections::HashMap;

/// Interactsh poll cadence and the post-scan cooldown applied before stopping
/// the poller. The cooldown exceeds one poll interval so that a final poll
/// reliably runs after the last request is registered.
pub const INTERACTSH_POLL_SECS: u64 = 5;
pub const INTERACTSH_COOLDOWN_SECS: u64 = INTERACTSH_POLL_SECS + 2;

/// Convert a YAML scalar value from a template's `variables:` map to a string.
pub fn yaml_value_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Interpolate dynamic variables into matcher patterns (nuclei resolves
/// template variables in operators too — e.g. `{{randstr}}` correlation).
pub fn interpolate_matchers(
    matchers: &[TemplateMatcher],
    target: &str,
    vars: &HashMap<String, String>,
) -> Vec<TemplateMatcher> {
    matchers
        .iter()
        .map(|m| {
            let mut m = m.clone();
            for w in m.words.iter_mut() {
                *w = TemplateDsl::interpolate(w, target, vars);
            }
            for r in m.regex.iter_mut() {
                *r = TemplateDsl::interpolate(r, target, vars);
            }
            for d in m.dsl.iter_mut() {
                *d = TemplateDsl::interpolate(d, target, vars);
            }
            m
        })
        .collect()
}

/// Check if a string still contains unresolved Nuclei template variables.
pub fn has_unresolved_variables(s: &str) -> bool {
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        if let Some(end) = rest[start..].find("}}") {
            let inner = &rest[start + 2..start + end];
            // Skip empty braces and known URL-safe patterns.
            if !inner.is_empty() && !inner.contains("http") {
                return true;
            }
            rest = &rest[start + end + 2..];
        } else {
            break;
        }
    }
    false
}

/// Internal representation of a request to be sent.
#[derive(Debug, Clone)]
pub enum RequestSpec {
    Standard {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
    Raw(String),
}

/// Build the concrete requests (raw or path-based) for one http block.
pub fn build_http_requests(
    http_block: &HttpBlock,
    target: &str,
    extracted_vars: &HashMap<String, String>,
) -> Vec<RequestSpec> {
    if !http_block.raw.is_empty() {
        http_block
            .raw
            .iter()
            .map(|raw| {
                let interpolated = TemplateDsl::interpolate(raw, target, extracted_vars);
                RequestSpec::Raw(interpolated)
            })
            .collect()
    } else {
        let method = http_block.method.as_deref().unwrap_or("GET").to_uppercase();

        http_block
            .path
            .iter()
            .map(|path| {
                let resolved = TemplateDsl::interpolate(path, target, extracted_vars);
                let url = if resolved.starts_with("http://") || resolved.starts_with("https://") {
                    resolved
                } else {
                    let base = target.trim_end_matches('/');
                    if resolved.starts_with('/') {
                        format!("{}{}", base, resolved)
                    } else {
                        format!("{}/{}", base, resolved)
                    }
                };

                let mut headers = HashMap::new();
                for (k, v) in &http_block.headers {
                    headers.insert(
                        k.clone(),
                        TemplateDsl::interpolate(v, target, extracted_vars),
                    );
                }
                let body = http_block
                    .body
                    .as_ref()
                    .map(|b| TemplateDsl::interpolate(b, target, extracted_vars));

                RequestSpec::Standard {
                    method: method.clone(),
                    url,
                    headers,
                    body,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::template::HttpBlock;

    #[test]
    fn test_yaml_value_to_string() {
        assert_eq!(
            yaml_value_to_string(&serde_yaml::Value::String("x".to_string())),
            Some("x".to_string())
        );
        assert_eq!(
            yaml_value_to_string(&serde_yaml::Value::Number(5.into())),
            Some("5".to_string())
        );
        assert_eq!(
            yaml_value_to_string(&serde_yaml::Value::Number(serde_yaml::Number::from(1.5f64))),
            Some("1.5".to_string())
        );
        assert_eq!(
            yaml_value_to_string(&serde_yaml::Value::Bool(true)),
            Some("true".to_string())
        );
        assert_eq!(yaml_value_to_string(&serde_yaml::Value::Null), None);
        assert_eq!(
            yaml_value_to_string(&serde_yaml::Value::Sequence(vec![])),
            None
        );
        assert_eq!(
            yaml_value_to_string(&serde_yaml::Value::Mapping(serde_yaml::Mapping::new())),
            None
        );
    }

    #[test]
    fn test_interpolate_matchers() {
        let yaml_matcher = r#"
type: word
part: body
words:
  - "token-{{randstr}}"
regex:
  - "{{Hostname}}"
dsl:
  - "contains(body, '{{token}}')"
status:
  - 200
"#;
        let matcher: TemplateMatcher = serde_yaml::from_str(yaml_matcher).unwrap();
        let mut vars = HashMap::new();
        vars.insert("randstr".to_string(), "abc123".to_string());
        vars.insert("Hostname".to_string(), "example.com".to_string());
        vars.insert("token".to_string(), "secret".to_string());

        let interpolated = interpolate_matchers(&[matcher], "http://example.com", &vars);
        assert_eq!(interpolated.len(), 1);
        let m = &interpolated[0];
        assert_eq!(m.words, vec!["token-abc123"]);
        assert_eq!(m.regex, vec!["example.com"]);
        assert_eq!(m.dsl, vec!["contains(body, 'secret')"]);
        assert_eq!(m.part.as_deref(), Some("body"));
        assert_eq!(m.matcher_type, "word");
        assert_eq!(m.status, vec![200]);
    }

    #[test]
    fn test_has_unresolved_variables() {
        assert!(has_unresolved_variables("{{var}}"));
        assert!(has_unresolved_variables("{{BaseURL}}/x"));
        assert!(!has_unresolved_variables("http://host"));
        assert!(!has_unresolved_variables("{{}}"));
        assert!(!has_unresolved_variables("literal"));
        assert!(has_unresolved_variables("prefix {{x}} suffix"));
    }

    #[test]
    fn test_build_http_requests_raw_vs_path() {
        let mut vars = HashMap::new();
        vars.insert("custom_val".to_string(), "foo123".to_string());

        // Raw block
        let raw_yaml = r#"
raw:
  - |
    GET /test/{{custom_val}} HTTP/1.1
    Host: {{Hostname}}
"#;
        let raw_block: HttpBlock = serde_yaml::from_str(raw_yaml).unwrap();
        let raw_reqs = build_http_requests(&raw_block, "http://localhost:8080", &vars);
        assert_eq!(raw_reqs.len(), 1);
        match &raw_reqs[0] {
            RequestSpec::Raw(content) => {
                assert!(content.contains("/test/foo123"));
                assert!(
                    content.contains("Host: localhost:8080") || content.contains("Host: localhost")
                );
            }
            _ => panic!("expected RequestSpec::Raw"),
        }

        // Path block
        let path_yaml = r#"
method: POST
path:
  - "{{BaseURL}}/a"
  - "b"
  - "http://other-host.com/c"
headers:
  X-Header: "val-{{custom_val}}"
body: "payload={{custom_val}}"
"#;
        let path_block: HttpBlock = serde_yaml::from_str(path_yaml).unwrap();
        let path_reqs = build_http_requests(&path_block, "http://localhost:8080", &vars);
        assert_eq!(path_reqs.len(), 3);

        match &path_reqs[0] {
            RequestSpec::Standard {
                method,
                url,
                headers,
                body,
            } => {
                assert_eq!(method, "POST");
                assert_eq!(url, "http://localhost:8080/a");
                assert_eq!(
                    headers.get("X-Header").map(|s| s.as_str()),
                    Some("val-foo123")
                );
                assert_eq!(body.as_deref(), Some("payload=foo123"));
            }
            _ => panic!("expected RequestSpec::Standard"),
        }

        match &path_reqs[1] {
            RequestSpec::Standard { url, .. } => {
                assert_eq!(url, "http://localhost:8080/b");
            }
            _ => panic!("expected RequestSpec::Standard"),
        }

        match &path_reqs[2] {
            RequestSpec::Standard { url, .. } => {
                assert_eq!(url, "http://other-host.com/c");
            }
            _ => panic!("expected RequestSpec::Standard"),
        }
    }
}
