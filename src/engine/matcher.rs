use crate::engine::dsl::TemplateDsl;
use crate::models::template::TemplateMatcher;
use aho_corasick::AhoCorasick;
use regex::Regex;
use std::borrow::Cow;

/// Response data prepared for matcher evaluation.
pub struct EvaluatedResponse<'a> {
    pub status: u16,
    pub headers: &'a str,
    pub body: &'a str,
}

/// High-performance matcher engine supporting word (Aho-Corasick), regex, status,
/// binary, and DSL matcher types.
pub struct MatcherEngine;

impl MatcherEngine {
    /// Evaluate a single matcher against the response.
    /// Returns `true` if the matcher condition is satisfied (accounting for `negative` flag).
    pub fn evaluate(matcher: &TemplateMatcher, resp: &EvaluatedResponse) -> bool {
        let is_match = match matcher.matcher_type.as_str() {
            "status" => Self::match_status(&matcher.status, resp.status),
            "word" => {
                let content = Self::get_part(matcher, resp);
                let condition = Self::parse_condition(matcher);
                if matcher.case_insensitive {
                    let lower_content = content.to_lowercase();
                    let lower_words: Vec<String> =
                        matcher.words.iter().map(|w| w.to_lowercase()).collect();
                    Self::match_words(&lower_words, &lower_content, condition)
                } else {
                    Self::match_words(&matcher.words, &content, condition)
                }
            }
            "regex" => {
                let content = Self::get_part(matcher, resp);
                let condition = Self::parse_condition(matcher);
                Self::match_regex(&matcher.regex, &content, condition, matcher.case_insensitive)
            }
            "binary" => {
                let content = Self::get_part(matcher, resp);
                Self::match_binary(&matcher.binary, &content)
            }
            "dsl" => Self::match_dsl(&matcher.dsl, resp),
            "size" => Self::match_size(&matcher.size, resp.body.len()),
            "xpath" => {
                let content = Self::get_part(matcher, resp);
                Self::match_xpath(&matcher.xpath, &content)
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

    // -----------------------------------------------------------------------
    // Status Matcher
    // -----------------------------------------------------------------------

    fn match_status(expected: &[u16], actual: u16) -> bool {
        expected.contains(&actual)
    }

    // -----------------------------------------------------------------------
    // Word Matcher (SIMD-accelerated via Aho-Corasick)
    // -----------------------------------------------------------------------

    fn match_words(patterns: &[String], text: &str, condition: MatchCondition) -> bool {
        if patterns.is_empty() {
            return false;
        }

        let ac = match AhoCorasick::new(patterns) {
            Ok(ac) => ac,
            Err(_) => return false,
        };

        match condition {
            MatchCondition::Or => ac.find(text).is_some(),
            MatchCondition::And => {
                let mut matched = vec![false; patterns.len()];
                for mat in ac.find_iter(text) {
                    matched[mat.pattern().as_usize()] = true;
                    // Early exit: if all matched, stop scanning.
                    if matched.iter().all(|&m| m) {
                        return true;
                    }
                }
                matched.iter().all(|&m| m)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Regex Matcher
    // -----------------------------------------------------------------------

    fn match_regex(
        patterns: &[String],
        text: &str,
        condition: MatchCondition,
        case_insensitive: bool,
    ) -> bool {
        if patterns.is_empty() {
            return false;
        }

        let compile = |pat: &str| -> Option<Regex> {
            let pat_str = if case_insensitive {
                format!("(?i){}", pat)
            } else {
                pat.to_string()
            };
            Regex::new(&pat_str).ok()
        };

        match condition {
            MatchCondition::Or => patterns
                .iter()
                .any(|pat| compile(pat).map(|re| re.is_match(text)).unwrap_or(false)),
            MatchCondition::And => patterns
                .iter()
                .all(|pat| compile(pat).map(|re| re.is_match(text)).unwrap_or(false)),
        }
    }

    // -----------------------------------------------------------------------
    // Binary Matcher (hex byte sequence)
    // -----------------------------------------------------------------------

    fn match_binary(hex_patterns: &[String], text: &str) -> bool {
        let text_bytes = text.as_bytes();

        for hex_str in hex_patterns {
            let clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
            if let Some(pattern_bytes) = hex_decode(&clean) {
                if contains_bytes(text_bytes, &pattern_bytes) {
                    return true;
                }
            }
        }

        false
    }

    // -----------------------------------------------------------------------
    // DSL Matcher
    // -----------------------------------------------------------------------

    fn match_dsl(expressions: &[String], resp: &EvaluatedResponse) -> bool {
        let content_length = resp.body.len();

        // DSL matchers default to AND condition between expressions.
        expressions.iter().all(|expr| {
            TemplateDsl::evaluate_dsl(expr, resp.status, resp.headers, resp.body, content_length)
        })
    }

    // -----------------------------------------------------------------------
    // Size Matcher
    // -----------------------------------------------------------------------

    fn match_size(expected_sizes: &[usize], actual_size: usize) -> bool {
        if expected_sizes.is_empty() {
            return false;
        }
        expected_sizes.contains(&actual_size)
    }

    // -----------------------------------------------------------------------
    // XPath Matcher
    // -----------------------------------------------------------------------

    fn match_xpath(xpath_expressions: &[String], xml_content: &str) -> bool {
        if xpath_expressions.is_empty() {
            return false;
        }

        let package = match sxd_document::parser::parse(xml_content) {
            Ok(pkg) => pkg,
            Err(_) => return false,
        };
        let document = package.as_document();

        for expr_str in xpath_expressions {
            let factory = sxd_xpath::Factory::new();
            if let Ok(xpath) = factory.build(expr_str) {
                if let Some(xpath) = xpath {
                    let context = sxd_xpath::Context::new();
                    if let Ok(value) = xpath.evaluate(&context, document.root()) {
                        match value {
                            sxd_xpath::Value::Nodeset(nodes) => {
                                if nodes.size() > 0 {
                                    return true;
                                }
                            }
                            sxd_xpath::Value::Boolean(b) => {
                                if b {
                                    return true;
                                }
                            }
                            sxd_xpath::Value::String(s) => {
                                if !s.is_empty() {
                                    return true;
                                }
                            }
                            sxd_xpath::Value::Number(n) => {
                                if n != 0.0 && !n.is_nan() {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Select the response part to match against based on the matcher's `part` field.
    /// Returns a `Cow<str>` so "response" can concatenate headers + body without
    /// requiring all callers to allocate.
    fn get_part<'a>(matcher: &TemplateMatcher, resp: &'a EvaluatedResponse) -> Cow<'a, str> {
        match matcher.part.as_deref().unwrap_or("body") {
            "header" | "all_headers" => Cow::Borrowed(resp.headers),
            "response" => {
                // "response" means the full HTTP response (headers + body).
                let mut full = String::with_capacity(resp.headers.len() + resp.body.len() + 1);
                full.push_str(resp.headers);
                full.push('\n');
                full.push_str(resp.body);
                Cow::Owned(full)
            }
            "status" => Cow::Borrowed(""), // Status matchers don't use string content.
            _ => Cow::Borrowed(resp.body), // Default: body
        }
    }

    /// Parse the per-matcher condition field.
    fn parse_condition(matcher: &TemplateMatcher) -> MatchCondition {
        match matcher.condition.as_deref() {
            Some("and") => MatchCondition::And,
            _ => MatchCondition::Or,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MatchCondition {
    And,
    Or,
}

/// Decode a hex string into bytes.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Check if `haystack` contains the byte sequence `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
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
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_404 = EvaluatedResponse {
            status: 404,
            headers: "",
            body: "",
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
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_partial = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Welcome to the admin area",
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
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_wrong = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "Wrong",
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
        };
        assert!(MatcherEngine::evaluate(&m, &resp));

        let resp_no_match = EvaluatedResponse {
            status: 200,
            headers: "",
            body: "<users><user role='guest'>Bob</user></users>",
        };
        assert!(!MatcherEngine::evaluate(&m, &resp_no_match));
    }
}
