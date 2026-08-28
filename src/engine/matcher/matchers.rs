use crate::engine::dsl::TemplateDsl;
use crate::engine::matcher::parts::{contains_bytes, hex_decode, EvaluatedResponse, MatchCondition};
use aho_corasick::AhoCorasick;
use regex::Regex;

pub fn match_status(expected: &[u16], actual: u16) -> bool {
    expected.contains(&actual)
}

pub fn match_words(patterns: &[String], text: &str, condition: MatchCondition) -> bool {
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

pub fn match_regex(
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

pub fn match_binary(hex_patterns: &[String], text: &str) -> bool {
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

pub fn match_dsl(expressions: &[String], resp: &EvaluatedResponse) -> bool {
    let content_length = resp.body.len();

    // DSL matchers default to AND condition between expressions.
    expressions.iter().all(|expr| {
        TemplateDsl::evaluate_dsl(
            expr,
            resp.status,
            resp.headers,
            resp.body,
            content_length,
            resp.duration_secs,
        )
    })
}

pub fn match_size(expected_sizes: &[usize], actual_size: usize) -> bool {
    if expected_sizes.is_empty() {
        return false;
    }
    expected_sizes.contains(&actual_size)
}

pub fn match_xpath(xpath_expressions: &[String], xml_content: &str) -> bool {
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
