pub mod matchers;
pub mod parts;

#[allow(unused_imports)]
pub use matchers::{
    match_binary, match_dsl, match_regex, match_size, match_status, match_words, match_xpath,
};
#[allow(unused_imports)]
pub use parts::{contains_bytes, get_part, hex_decode, parse_condition, EvaluatedResponse, MatchCondition};

use crate::models::template::TemplateMatcher;

/// High-performance matcher engine supporting word (Aho-Corasick), regex, status,
/// binary, and DSL matcher types.
pub struct MatcherEngine;

impl MatcherEngine {
    /// Evaluate a single matcher against the response.
    /// Returns `true` if the matcher condition is satisfied (accounting for `negative` flag).
    pub fn evaluate(matcher: &TemplateMatcher, resp: &EvaluatedResponse) -> bool {
        // Interactsh-backed parts only carry data from real out-of-band
        // interactions. Without a recorded callback the matcher never matches
        // (nuclei only evaluates these parts when an interaction arrives), so
        // they must not fall back to the response body — including `negative`
        // matchers, which would otherwise match every request.
        if let Some(part) = matcher.part.as_deref() {
            let interaction_data = match part {
                "interactsh_protocol" => Some(resp.interactsh_protocol),
                "interactsh_request" => Some(resp.interactsh_request),
                "interactsh_response" => Some(resp.interactsh_response),
                _ => None,
            };
            if matches!(interaction_data, Some(None)) {
                return false;
            }
        }

        let is_match = match matcher.matcher_type.as_str() {
            "status" => match_status(&matcher.status, resp.status),
            "word" => {
                let content = get_part(matcher, resp);
                let condition = parse_condition(matcher);
                if matcher.case_insensitive {
                    let lower_content = content.to_lowercase();
                    let lower_words: Vec<String> =
                        matcher.words.iter().map(|w| w.to_lowercase()).collect();
                    match_words(&lower_words, &lower_content, condition)
                } else {
                    match_words(&matcher.words, &content, condition)
                }
            }
            "regex" => {
                let content = get_part(matcher, resp);
                let condition = parse_condition(matcher);
                match_regex(&matcher.regex, &content, condition, matcher.case_insensitive)
            }
            "binary" => {
                let content = get_part(matcher, resp);
                match_binary(&matcher.binary, &content)
            }
            "dsl" => match_dsl(&matcher.dsl, resp),
            "size" => match_size(&matcher.size, resp.body.len()),
            "xpath" => {
                let content = get_part(matcher, resp);
                match_xpath(&matcher.xpath, &content)
            }
            _ => false,
        };

        if matcher.negative {
            !is_match
        } else {
            is_match
        }
    }

    /// Evaluate multiple matchers with a top-level condition (and/or).
    /// `condition` is the `matchers-condition` field from the HttpBlock.
    pub fn evaluate_all(
        matchers: &[TemplateMatcher],
        condition: &str,
        resp: &EvaluatedResponse,
    ) -> bool {
        if matchers.is_empty() {
            return false;
        }

        match condition.to_lowercase().as_str() {
            "and" => matchers.iter().all(|m| Self::evaluate(m, resp)),
            _ => matchers.iter().any(|m| Self::evaluate(m, resp)), // Default: "or"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_matcher(matcher_type: &str) -> TemplateMatcher {
        TemplateMatcher {
            matcher_type: matcher_type.to_string(),
            part: None,
            words: vec![],
            regex: vec![],
            status: vec![],
            dsl: vec![],
            binary: vec![],
            size: vec![],
            xpath: vec![],
            time: vec![],
            condition: None,
            negative: false,
            case_insensitive: false,
            encoding: None,
            name: None,
            internal: false,
        }
    }

    #[test]
    fn test_status_matcher() {
        let mut m = make_matcher("status");
        m.status = vec![200, 301];

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_404 = EvaluatedResponse {
            status: 404,
            headers: "",
            body: "",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_404));
    }

    #[test]
    fn test_word_matcher_or() {
        let mut m = make_matcher("word");
        m.words = vec!["admin".to_string(), "root".to_string()];

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Welcome to the admin panel",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_word_matcher_and() {
        let mut m = make_matcher("word");
        m.words = vec!["admin".to_string(), "panel".to_string()];
        m.condition = Some("and".to_string());

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Welcome to the admin panel",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_partial = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Welcome to the admin area",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_partial));
    }

    #[test]
    fn test_regex_matcher() {
        let mut m = make_matcher("regex");
        m.regex = vec![r"root:x:\d+:\d+".to_string()];

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "root:x:0:0:root:/root:/bin/bash",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_negative_matcher() {
        let mut m = make_matcher("word");
        m.words = vec!["error".to_string()];
        m.negative = true;

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Success! All good.",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_dsl_matcher() {
        let mut m = make_matcher("dsl");
        m.dsl = vec!["status_code == 200 && contains(body, \"admin\")".to_string()];

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "admin panel active",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_case_insensitive_word() {
        let mut m = make_matcher("word");
        m.words = vec!["ADMIN".to_string()];
        m.case_insensitive = true;

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "welcome admin",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_internal_matcher_deserialization() {
        let yaml = r#"
type: status
status:
  - 403
  - 401
internal: true
"#;
        let matcher: TemplateMatcher = serde_yaml::from_str(yaml).unwrap();
        assert!(matcher.internal);
        assert_eq!(matcher.status, vec![403, 401]);
    }

    #[test]
    fn test_size_matcher() {
        let mut m = make_matcher("size");
        m.size = vec![12, 100];

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Hello World!", // len = 12
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_wrong = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Wrong",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_wrong));
    }

    #[test]
    fn test_xpath_matcher() {
        let mut m = make_matcher("xpath");
        m.xpath = vec!["//user[@role='admin']".to_string()];

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "<users><user role='admin'>Alice</user></users>",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_no_match = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "<users><user role='guest'>Bob</user></users>",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_no_match));
    }
}
