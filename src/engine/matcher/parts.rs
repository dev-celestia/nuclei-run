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
        "all" => {
            // Go: body + all_headers concatenated.
            let mut full = String::with_capacity(resp.body.len() + resp.headers.len() + 1);
            full.push_str(resp.body);
            if !resp.headers.is_empty() {
                full.push('\n');
                full.push_str(resp.headers);
            }
            Cow::Owned(full)
        }
        "response" => {
            // Go: FullResponseString() — status line + raw headers + body
            // with \r\n wire format. For header-less protocols (ssl/dns/network)
            // the body already is the response payload, so no prepending.
            if resp.headers.is_empty() && resp.body.is_empty() {
                return Cow::Borrowed(resp.body);
            }
            let mut full =
                String::with_capacity(20 + resp.headers.len() + resp.body.len() + 2);
            full.push_str(&format!("HTTP/1.1 {}\r\n", resp.status));
            if !resp.headers.is_empty() {
                full.push_str(&resp.headers.replace('\n', "\r\n"));
                full.push_str("\r\n");
            }
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

/// Effective content length, mirroring Go nuclei's `utils.CalculateContentLength`:
/// the Content-Length header value wins when present, otherwise the body size.
pub fn calculate_content_length(headers: &str, body: &str) -> usize {
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(len) = value.trim().parse::<usize>() {
                    return len;
                }
            }
        }
    }
    body.len()
}

/// Build the per-response DSL variable map from raw headers, mirroring Go
/// nuclei's `responseToDSLMap`: every header becomes a variable named
/// lowercased with `-` replaced by `_` (multiple values joined by a space),
/// and every Set-Cookie cookie name (lowercased) maps to its value.
pub fn response_variables(headers: &str) -> HashMap<String, String> {
    let mut vars: HashMap<String, String> = HashMap::new();
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();

        // Cookies are inserted first, as in Go (header keys win on collision).
        let key = name.trim().to_lowercase().replace('-', "_");
        if key == "set_cookie" {
            if let Some(pair) = value.split(';').next() {
                if let Some((cookie_name, cookie_value)) = pair.split_once('=') {
                    let cookie_name = cookie_name.trim().to_lowercase();
                    if !cookie_name.is_empty() {
                        vars.entry(cookie_name)
                            .or_insert_with(|| cookie_value.trim().to_string());
                    }
                }
            }
        }

        let value = value.to_string();
        vars.entry(key)
            .and_modify(|existing| {
                existing.push(' ');
                existing.push_str(&value);
            })
            .or_insert(value);
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_content_length_header_wins() {
        assert_eq!(
            calculate_content_length("Content-Length: 1000\n", "small"),
            1000
        );
        assert_eq!(
            calculate_content_length("Server: x\ncontent-length: 7\n", "small"),
            7
        );
    }

    #[test]
    fn test_calculate_content_length_fallback() {
        assert_eq!(calculate_content_length("Server: x\n", "small"), 5);
        // Unparseable header falls back to the body size, like Go's -1.
        assert_eq!(calculate_content_length("Content-Length: abc\n", "small"), 5);
        assert_eq!(calculate_content_length("", ""), 0);
    }

    #[test]
    fn test_response_variables_headers() {
        let vars = response_variables("X-Powered-By: PHP/8.1\nContent-Type: application/json\n");
        assert_eq!(vars.get("x_powered_by").map(String::as_str), Some("PHP/8.1"));
        assert_eq!(
            vars.get("content_type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn test_response_variables_multi_value_and_cookies() {
        let vars = response_variables(
            "Set-Cookie: session=abc123; Path=/\nSet-Cookie: csrf=t0k; HttpOnly\nServer: a\nServer: b\n",
        );
        assert_eq!(vars.get("session").map(String::as_str), Some("abc123"));
        assert_eq!(vars.get("csrf").map(String::as_str), Some("t0k"));
        // The raw header variable also exists, multi-values joined by space.
        assert_eq!(vars.get("server").map(String::as_str), Some("a b"));
        assert!(vars.get("set_cookie").is_some());
    }
}
