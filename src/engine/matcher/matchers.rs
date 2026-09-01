use crate::engine::dsl::TemplateDsl;
use crate::engine::matcher::parts::{
    calculate_content_length, contains_bytes, hex_decode, response_variables, EvaluatedResponse,
    MatchCondition,
};
use aho_corasick::AhoCorasick;
use regex::Regex;

pub fn match_status(expected: &[u16], actual: u16) -> bool {
    expected.contains(&actual)
}

pub fn match_words(patterns: &[Vec<u8>], text: &[u8], condition: MatchCondition) -> bool {
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
    let content_length = calculate_content_length(resp.headers, resp.body);

    // Go evaluates DSL against the full response data map: header and cookie
    // variables plus extracted values merged in by ExecuteOperators.
    let mut vars = response_variables(resp.headers);
    if let Some(named) = resp.named_parts {
        for (key, value) in named {
            vars.insert(key.clone(), value.clone());
        }
    }

    // DSL matchers default to AND condition between expressions.
    expressions.iter().all(|expr| {
        TemplateDsl::evaluate_dsl_with_vars(
            expr,
            resp.status,
            resp.headers,
            resp.body,
            content_length,
            resp.duration_secs,
            &vars,
        )
    })
}

pub fn match_size(expected_sizes: &[usize], actual_size: usize) -> bool {
    if expected_sizes.is_empty() {
        return false;
    }
    expected_sizes.contains(&actual_size)
}

pub fn match_xpath(xpath_expressions: &[String], content: &str, condition: MatchCondition) -> bool {
    if xpath_expressions.is_empty() {
        return false;
    }

    let mut matches: usize = 0;
    for expr_str in xpath_expressions {
        let count = match crate::engine::dom::query_xpath_count(content, expr_str) {
            // Invalid expression or unparseable corpus: skip, as Go does on
            // QueryAll/Parse errors.
            None => continue,
            Some(c) => c,
        };

        if count == 0 {
            match condition {
                // AND fails as soon as any expression matches nothing.
                MatchCondition::And => return false,
                MatchCondition::Or => continue,
            }
        }

        // OR succeeds on the first expression that returns nodes.
        if matches!(condition, MatchCondition::Or) {
            return true;
        }
        matches += count;
    }

    matches > 0
}
