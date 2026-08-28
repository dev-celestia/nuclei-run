pub mod extractors;
pub mod parts;

pub use extractors::{extract_json_path, extract_regex, extract_xpath};
pub use parts::get_content;

use crate::engine::http_client::HttpResponse;
use crate::models::template::TemplateExtractor;
use std::collections::HashMap;

/// Extractor engine that pulls values from HTTP responses.
/// Supports regex (with capture groups), kval (header key-value), and json (dot-path).
pub struct ExtractorEngine;

impl ExtractorEngine {
    /// Run a single extractor against the response and return extracted values.
    /// Returns a map of `name -> extracted_value` for chaining into subsequent requests.
    pub fn extract(
        extractor: &TemplateExtractor,
        response: &HttpResponse,
    ) -> HashMap<String, String> {
        let mut results = HashMap::new();
        let name = extractor
            .name
            .clone()
            .unwrap_or_else(|| extractor.extractor_type.clone());

        match extractor.extractor_type.as_str() {
            "regex" => {
                let content = get_content(extractor, response);
                if let Some(value) = extract_regex(
                    &extractor.regex,
                    &content,
                    extractor.regex_group.unwrap_or(0),
                ) {
                    results.insert(name, value);
                }
            }
            "kval" => {
                for key in &extractor.kval {
                    let lower_key = key.to_lowercase();
                    if let Some(value) = response.headers_map.get(&lower_key) {
                        let kval_name = if extractor.kval.len() == 1 {
                            name.clone()
                        } else {
                            key.clone()
                        };
                        results.insert(kval_name, value.clone());
                    }
                }
            }
            "json" => {
                let content = get_content(extractor, response);
                for path in &extractor.json {
                    if let Some(value) = extract_json_path(&content, path) {
                        let json_name = if extractor.json.len() == 1 {
                            name.clone()
                        } else {
                            path.clone()
                        };
                        results.insert(json_name, value);
                    }
                }
            }
            "xpath" => {
                let content = get_content(extractor, response);
                for path in &extractor.xpath {
                    if let Some(value) = extract_xpath(&content, path, extractor.attribute.as_deref()) {
                        let xpath_name = if extractor.xpath.len() == 1 {
                            name.clone()
                        } else {
                            path.clone()
                        };
                        results.insert(xpath_name, value);
                    }
                }
            }
            "dsl" => {
                let content = get_content(extractor, response);
                for dsl_expr in &extractor.dsl {
                    let val = crate::engine::dsl::TemplateDsl::interpolate(dsl_expr, &content, &HashMap::new());
                    results.insert(name.clone(), val);
                }
            }
            _ => {}
        }

        results
    }

    /// Run all extractors and merge results.
    /// Internal extractors are included (for chaining) but can be filtered at output.
    pub fn extract_all(
        extractors: &[TemplateExtractor],
        response: &HttpResponse,
    ) -> HashMap<String, String> {
        let mut all_results = HashMap::new();
        for ext in extractors {
            let extracted = Self::extract(ext, response);
            all_results.extend(extracted);
        }
        all_results
    }

    /// Get non-internal extracted values (for output display).
    pub fn extract_output_values(
        extractors: &[TemplateExtractor],
        response: &HttpResponse,
    ) -> Vec<String> {
        let mut values = Vec::new();
        for ext in extractors {
            if ext.internal {
                continue; // Skip internal extractors from output.
            }
            let extracted = Self::extract(ext, response);
            for (_, v) in extracted {
                if !v.is_empty() {
                    values.push(v);
                }
            }
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response() -> HttpResponse {
        let mut headers_map = HashMap::new();
        headers_map.insert("content-type".to_string(), "application/json".to_string());
        headers_map.insert("x-powered-by".to_string(), "Express".to_string());

        HttpResponse {
            status: 200,
            headers_raw: "content-type: application/json\nx-powered-by: Express\n".to_string(),
            body: r#"{"user": "admin", "role": "superuser", "tokens": ["abc", "def"]}"#
                .to_string(),
            headers_map,
            duration_secs: 0.0,
        }
    }

    #[test]
    fn test_regex_extractor() {
        let ext = TemplateExtractor {
            extractor_type: "regex".to_string(),
            name: Some("version".to_string()),
            part: Some("body".to_string()),
            regex: vec![r#""user":\s*"([^"]+)""#.to_string()],
            regex_group: Some(1),
            kval: vec![],
            json: vec![],
            xpath: vec![],
            attribute: None,
            dsl: vec![],
            internal: false,
        };

        let resp = make_response();
        let result = ExtractorEngine::extract(&ext, &resp);
        assert_eq!(result.get("version"), Some(&"admin".to_string()));
    }

    #[test]
    fn test_kval_extractor() {
        let ext = TemplateExtractor {
            extractor_type: "kval".to_string(),
            name: Some("server_tech".to_string()),
            part: None,
            regex: vec![],
            regex_group: None,
            kval: vec!["x-powered-by".to_string()],
            json: vec![],
            xpath: vec![],
            attribute: None,
            dsl: vec![],
            internal: false,
        };

        let resp = make_response();
        let result = ExtractorEngine::extract(&ext, &resp);
        assert_eq!(result.get("server_tech"), Some(&"Express".to_string()));
    }

    #[test]
    fn test_json_extractor() {
        let ext = TemplateExtractor {
            extractor_type: "json".to_string(),
            name: Some("user_role".to_string()),
            part: None,
            regex: vec![],
            regex_group: None,
            kval: vec![],
            json: vec![".role".to_string()],
            xpath: vec![],
            attribute: None,
            dsl: vec![],
            internal: false,
        };

        let resp = make_response();
        let result = ExtractorEngine::extract(&ext, &resp);
        assert_eq!(result.get("user_role"), Some(&"superuser".to_string()));
    }

    #[test]
    fn test_json_array_extractor() {
        let ext = TemplateExtractor {
            extractor_type: "json".to_string(),
            name: Some("first_token".to_string()),
            part: None,
            regex: vec![],
            regex_group: None,
            kval: vec![],
            json: vec![".tokens[0]".to_string()],
            xpath: vec![],
            attribute: None,
            dsl: vec![],
            internal: false,
        };

        let resp = make_response();
        let result = ExtractorEngine::extract(&ext, &resp);
        assert_eq!(result.get("first_token"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_internal_extractor_excluded_from_output() {
        let ext = TemplateExtractor {
            extractor_type: "regex".to_string(),
            name: Some("internal_token".to_string()),
            part: Some("body".to_string()),
            regex: vec![r#""user":\s*"([^"]+)""#.to_string()],
            regex_group: Some(1),
            kval: vec![],
            json: vec![],
            xpath: vec![],
            attribute: None,
            dsl: vec![],
            internal: true, // Should NOT appear in output values.
        };

        let resp = make_response();
        let output = ExtractorEngine::extract_output_values(&[ext], &resp);
        assert!(output.is_empty());
    }

    #[test]
    fn test_xpath_extractor() {
        let ext = TemplateExtractor {
            extractor_type: "xpath".to_string(),
            name: Some("admin_name".to_string()),
            part: Some("body".to_string()),
            regex: vec![],
            regex_group: None,
            kval: vec![],
            json: vec![],
            xpath: vec!["//user[@role='admin']".to_string()],
            attribute: None,
            dsl: vec![],
            internal: false,
        };

        let mut resp = make_response();
        resp.body = "<users><user role='admin'>Alice</user></users>".to_string();

        let result = ExtractorEngine::extract(&ext, &resp);
        assert_eq!(result.get("admin_name"), Some(&"Alice".to_string()));
    }
}
