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
                    headers.insert(k.clone(), TemplateDsl::interpolate(v, target, extracted_vars));
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
