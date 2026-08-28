use crate::models::template::TemplateMatcher;
use std::borrow::Cow;
use std::collections::HashMap;

/// Response data prepared for matcher evaluation.
pub struct EvaluatedResponse<'a> {
    pub status: u16,
    pub headers: &'a str,
    pub body: &'a str,
    /// Protocol of a recorded Interactsh callback (e.g. "http", "dns").
    /// `None` when no out-of-band interaction was received for this request.
    pub interactsh_protocol: Option<&'a str>,
    /// Raw request of the recorded Interactsh callback.
    pub interactsh_request: Option<&'a str>,
    /// Raw response of the recorded Interactsh callback.
    pub interactsh_response: Option<&'a str>,
    /// Named dynamic parts (e.g. headless script results keyed by `name:`).
    /// When a matcher's `part` is not a standard part, it is looked up here
    /// before falling back to the body.
    pub named_parts: Option<&'a HashMap<String, String>>,
    /// Request round-trip time in seconds (DSL `duration` variable).
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Copy)]
pub enum MatchCondition {
    And,
    Or,
}

/// Select the response part to match against based on the matcher's `part` field.
/// Returns a `Cow<str>` so "response" can concatenate headers + body without
/// requiring all callers to allocate.
pub fn get_part<'a>(matcher: &TemplateMatcher, resp: &'a EvaluatedResponse) -> Cow<'a, str> {
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
        // Out-of-band interaction parts — populated only from recorded
        // Interactsh callbacks, never from the HTTP response itself.
        "interactsh_protocol" => Cow::Borrowed(resp.interactsh_protocol.unwrap_or("")),
        "interactsh_request" => Cow::Borrowed(resp.interactsh_request.unwrap_or("")),
        "interactsh_response" => Cow::Borrowed(resp.interactsh_response.unwrap_or("")),
        part => {
            // Named dynamic parts (e.g. headless script results) are looked
            // up by name before falling back to the body.
            if let Some(named) = resp.named_parts {
                if let Some(value) = named.get(part) {
                    return Cow::Borrowed(value.as_str());
                }
            }
            Cow::Borrowed(resp.body) // Default: body
        }
    }
}

/// Parse the per-matcher condition field.
pub fn parse_condition(matcher: &TemplateMatcher) -> MatchCondition {
    match matcher.condition.as_deref() {
        Some("and") => MatchCondition::And,
        _ => MatchCondition::Or,
    }
}

/// Decode a hex string into bytes.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
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
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
