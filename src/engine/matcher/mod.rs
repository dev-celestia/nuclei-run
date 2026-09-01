pub mod matchers;
pub mod parts;

#[allow(unused_imports)]
pub use matchers::{
    match_binary, match_dsl, match_regex, match_size, match_status, match_words, match_xpath,
};
#[allow(unused_imports)]
pub use parts::{
    contains_bytes, get_part, hex_decode, parse_condition, EvaluatedResponse, MatchCondition,
};

use crate::models::template::TemplateMatcher;
use std::borrow::Cow;

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
                let hex_encoded = matcher.encoding.as_deref() == Some("hex");
                // Go's CompileMatchers hex-decodes words first, then applies
                // CaseInsensitive to the decoded words.
                let words: Vec<Vec<u8>> = matcher
                    .words
                    .iter()
                    .map(|word| {
                        let mut bytes = if hex_encoded {
                            hex_decode(word)
                                .filter(|decoded| !decoded.is_empty())
                                .unwrap_or_else(|| word.as_bytes().to_vec())
                        } else {
                            word.as_bytes().to_vec()
                        };
                        if matcher.case_insensitive {
                            bytes = lowercase_bytes(&bytes);
                        }
                        bytes
                    })
                    .collect();
                let content_bytes: Cow<[u8]> = if matcher.case_insensitive {
                    Cow::Owned(content.to_lowercase().into_bytes())
                } else {
                    Cow::Borrowed(content.as_bytes())
                };
                match_words(&words, &content_bytes, condition)
            }
            "regex" => {
                let content = get_part(matcher, resp);
                let condition = parse_condition(matcher);
                match_regex(
                    &matcher.regex,
                    &content,
                    condition,
                    matcher.case_insensitive,
                )
            }
            "binary" => {
                let content = get_part(matcher, resp);
                match_binary(&matcher.binary, &content)
            }
            "dsl" => match_dsl(&matcher.dsl, resp),
            "size" => match_size(&matcher.size, resp.body.len()),
            "xpath" => {
                let content = get_part(matcher, resp);
                let condition = parse_condition(matcher);
                match_xpath(&matcher.xpath, &content, condition)
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

    /// Name of a matcher responsible for a match, respecting the top-level
    /// `matchers-condition`. Returns the first named matcher that contributes
    /// to the match (or the first matching matcher when unnamed). Used to
    /// populate the `matcher_name` field of a finding.
    pub fn matched_matcher_name(
        matchers: &[TemplateMatcher],
        condition: &str,
        resp: &EvaluatedResponse,
    ) -> Option<String> {
        if matchers.is_empty() {
            return None;
        }
        let first_named = matchers
            .iter()
            .filter(|m| Self::evaluate(m, resp))
            .find_map(|m| m.name.clone());
        match condition.to_lowercase().as_str() {
            "and" => {
                if matchers.iter().all(|m| Self::evaluate(m, resp)) {
                    first_named
                } else {
                    None
                }
            }
            _ => first_named,
        }
    }
}

/// Lowercase matcher word bytes like Go's `strings.ToLower` (Unicode-aware
/// for valid UTF-8), falling back to ASCII lowercasing for arbitrary bytes.
fn lowercase_bytes(bytes: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_lowercase().into_bytes(),
        Err(_) => bytes.iter().map(|b| b.to_ascii_lowercase()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    #[test]
    fn test_hex_encoded_word_matcher() {
        // Go nuclei TestHexEncoding: "50494e47" decodes to "PING".
        let mut m = make_matcher("word");
        m.words = vec!["50494e47".to_string()];
        m.encoding = Some("hex".to_string());

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "received PING from server",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        // The literal hex string must not match once encoding is declared.
        let resp_literal = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "the text 50494e47 appears literally",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_literal));
    }

    #[test]
    fn test_hex_encoded_word_case_insensitive() {
        let mut m = make_matcher("word");
        m.words = vec!["50494E47".to_string()]; // "PING", uppercase hex
        m.encoding = Some("hex".to_string());
        m.case_insensitive = true;

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "got ping back",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_invalid_hex_word_kept_literally() {
        // Go's CompileMatchers keeps words that fail hex decoding unchanged.
        let mut m = make_matcher("word");
        m.words = vec!["zz".to_string()];
        m.encoding = Some("hex".to_string());

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "the zz marker",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));
    }

    #[test]
    fn test_match_words_raw_bytes() {
        // Decoded patterns need not be valid UTF-8.
        let patterns = vec![vec![0xde, 0xad, 0xbe, 0xef]];
        let text: Vec<u8> = vec![0x00, 0xde, 0xad, 0xbe, 0xef, 0x11];
        assert!(match_words(&patterns, &text, MatchCondition::Or));

        let text_missing: Vec<u8> = vec![0xde, 0xad, 0x00, 0xbe, 0xef];
        assert!(!match_words(&patterns, &text_missing, MatchCondition::Or));
    }

    #[test]
    fn test_dsl_matcher_with_extracted_variables() {
        let mut m = make_matcher("dsl");
        m.dsl = vec!["contains(token, \"SECRET\")".to_string()];

        let mut named = HashMap::new();
        named.insert("token".to_string(), "SECRET_value".to_string());

        let resp = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "the token never appears in the body",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: Some(&named),
            duration_secs: 0.0,
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_without = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "the token never appears in the body",
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
            duration_secs: 0.0,
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_without));
    }
}
