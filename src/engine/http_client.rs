use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use std::collections::HashMap;
use std::time::Duration;

/// Parsed HTTP response for matcher evaluation.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// All response headers serialized as a single string (key: value\n format).
    pub headers_raw: String,
    /// Response body content.
    pub body: String,
    /// Individual header key-value pairs.
    pub headers_map: HashMap<String, String>,
    /// Request round-trip time in seconds (exposed as the `duration` DSL var).
    pub duration_secs: f64,
}

/// Redirect-following policy for a request block. Mirrors Go nuclei's
/// `RedirectFlow` (pkg/protocols/http/httpclientpool/clientpool.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectFlow {
    /// Never follow redirects; the 30x response itself is returned.
    DontFollow,
    /// Follow all redirects (`redirects: true` / `-fr`).
    FollowAll,
    /// Follow only redirects back to the original host
    /// (`host-redirects: true` / `-fhr`).
    FollowSameHost,
}

/// Go nuclei's default redirect cap (clientpool.go `defaultMaxRedirects`).
pub const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Per-request-block HTTP behavior: redirect flow, redirect cap, and cookie
/// reuse. Mirrors Go's per-request `ConnectionConfiguration` compiled in
/// `http.go` Compile(), including the global `-mr` override and the
/// maxRedirects==0 → default-10 rule from `checkMaxRedirects`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestPolicy {
    pub flow: RedirectFlow,
    pub max_redirects: usize,
    pub disable_cookies: bool,
}

impl RequestPolicy {
    pub fn new(flow: RedirectFlow, max_redirects: usize, disable_cookies: bool) -> Self {
        Self {
            flow,
            max_redirects: if max_redirects == 0 {
                DEFAULT_MAX_REDIRECTS
            } else {
                max_redirects
            },
            disable_cookies,
        }
    }
}

impl Default for RequestPolicy {
    fn default() -> Self {
        Self::new(RedirectFlow::DontFollow, DEFAULT_MAX_REDIRECTS, false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClientKey {
    flow: RedirectFlow,
    max_redirects: usize,
    cookies: bool,
}

/// Configurable async HTTP client with connection pooling.
///
/// Mirrors nuclei's semantics: requests do NOT follow redirects by default.
/// Clients are cached per (redirect flow, max redirects, cookie policy) —
/// like Go's per-configuration client pool — so each distinct behavior gets
/// its own cookie jar, matching Go's per-client `cookiejar`.
pub struct HttpClient {
    timeout_secs: u64,
    proxy_url: Option<String>,
    custom_headers: Vec<(String, String)>,
    retries: u32,
    clients: std::sync::Mutex<HashMap<ClientKey, reqwest::Client>>,
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration.
    pub fn new(
        timeout_secs: u64,
        proxy_url: Option<&str>,
        custom_headers: &[(String, String)],
        retries: u32,
    ) -> Self {
        Self {
            timeout_secs,
            proxy_url: proxy_url.map(|s| s.to_string()),
            custom_headers: custom_headers.to_vec(),
            retries,
            clients: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Get (or lazily build) the pooled client for the given policy.
    fn client_for(&self, policy: &RequestPolicy) -> reqwest::Client {
        let key = ClientKey {
            flow: policy.flow,
            max_redirects: policy.max_redirects,
            cookies: !policy.disable_cookies,
        };
        let mut clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(&key) {
            return client.clone();
        }
        let client = self.build_client(policy);
        clients.insert(key, client.clone());
        client
    }

    fn build_client(&self, policy: &RequestPolicy) -> reqwest::Client {
        let max = policy.max_redirects;
        let redirect_policy = match policy.flow {
            RedirectFlow::DontFollow => Policy::none(),
            RedirectFlow::FollowAll => Policy::custom(move |attempt| {
                // Go checkMaxRedirects: stop once the chain exceeds the cap
                // and return the redirect response itself (reqwest's
                // Policy::limited would error with TooManyRedirects instead).
                if attempt.previous().len() > max {
                    return attempt.stop();
                }
                attempt.follow()
            }),
            RedirectFlow::FollowSameHost => Policy::custom(move |attempt| {
                // Go checkMaxRedirects: stop once the chain exceeds the cap.
                if attempt.previous().len() > max {
                    return attempt.stop();
                }
                // Go FollowSameHostRedirect compares against the *original*
                // request host (via[0]), not the previous hop.
                let Some(original) = attempt.previous().first() else {
                    return attempt.stop();
                };
                if normalize_host(attempt.url()) != normalize_host(original) {
                    return attempt.stop();
                }
                attempt.follow()
            }),
        };

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .danger_accept_invalid_certs(true)
            .redirect(redirect_policy)
            .cookie_store(!policy.disable_cookies)
            .pool_max_idle_per_host(20)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        if let Some(ref proxy) = self.proxy_url {
            if let Ok(p) = reqwest::Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
        }

        if !self.custom_headers.is_empty() {
            let mut headers = HeaderMap::new();
            for (k, v) in &self.custom_headers {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }
            builder = builder.default_headers(headers);
        }

        builder.build().unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Send an HTTP request honoring the given request policy.
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &Option<String>,
        policy: &RequestPolicy,
    ) -> Result<HttpResponse, reqwest::Error> {
        let client = self.client_for(policy);
        self.execute(&client, method, url, headers, body).await
    }

    async fn execute(
        &self,
        client: &reqwest::Client,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &Option<String>,
    ) -> Result<HttpResponse, reqwest::Error> {
        let method = match method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "PATCH" => reqwest::Method::PATCH,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };

        let mut last_err = None;
        for _attempt in 0..=self.retries {
            let mut request = client.request(method.clone(), url);

            for (k, v) in headers {
                request = request.header(k.as_str(), v.as_str());
            }
            if let Some(body_content) = body {
                request = request.body(body_content.clone());
            }

            let started = std::time::Instant::now();
            match request.send().await {
                Ok(response) => {
                    let duration_secs = started.elapsed().as_secs_f64();
                    return Ok(parse_response(response, duration_secs).await);
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.expect("at least one request attempt"))
    }

    /// Parse a raw HTTP request string and send it.
    /// Raw format: METHOD PATH HTTP/1.1\r\nHeader: value\r\n\r\nBody
    pub async fn send_raw(
        &self,
        raw: &str,
        target_url: &str,
        policy: &RequestPolicy,
    ) -> Result<HttpResponse, String> {
        let parsed = parse_raw_request(raw, target_url)?;
        self.send(&parsed.method, &parsed.url, &parsed.headers, &parsed.body, policy)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Normalize a URL host for same-host redirect comparison, mirroring Go's
/// `normalizeHost`: default ports (80/http, 443/https) are stripped and
/// bare IPv6 hosts are bracketed.
fn normalize_host(url: &url::Url) -> String {
    // url::Url::host_str() returns IPv6 hosts already bracketed; Go's
    // net.SplitHostPort works on the bare form, so strip first.
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    let strip_default_port = matches!(
        (url.scheme(), url.port()),
        ("http", Some(80)) | ("https", Some(443))
    );
    match url.port() {
        None => bracket_ipv6(host.to_string()),
        Some(_) if strip_default_port => bracket_ipv6(host.to_string()),
        Some(port) => format!("{}:{}", bracket_ipv6(host.to_string()), port),
    }
}

fn bracket_ipv6(host: String) -> String {
    if host.contains(':') {
        format!("[{}]", host)
    } else {
        host
    }
}

async fn parse_response(response: reqwest::Response, duration_secs: f64) -> HttpResponse {
    let status = response.status().as_u16();

    let mut headers_raw = String::new();
    let mut headers_map = HashMap::new();
    for (key, value) in response.headers() {
        let v = value.to_str().unwrap_or_default();
        headers_raw.push_str(&format!("{}: {}\n", key.as_str(), v));
        headers_map.insert(key.as_str().to_lowercase(), v.to_string());
    }

    let body = read_body_limited(response).await;

    HttpResponse {
        status,
        headers_raw,
        body,
        headers_map,
        duration_secs,
    }
}

/// Default cap on HTTP response body bytes retained for matching, mirroring
/// Go nuclei's `MaxBodyRead` (pkg/protocols/http/request.go).
const MAX_BODY_READ: usize = 10 * 1024 * 1024;

/// Stream the response body in chunks, stopping once `MAX_BODY_READ` bytes are
/// buffered so oversized responses do not exhaust memory.
async fn read_body_limited(mut response: reqwest::Response) -> String {
    let mut body = String::new();
    let mut remaining = MAX_BODY_READ;
    while remaining > 0 {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if chunk.len() >= remaining {
                    body.push_str(&String::from_utf8_lossy(&chunk[..remaining]));
                    break;
                }
                body.push_str(&String::from_utf8_lossy(&chunk));
                remaining -= chunk.len();
            }
            _ => break,
        }
    }
    body
}

/// Parsed components of a raw HTTP request.
struct ParsedRawRequest {
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Option<String>,
}

/// Parse a raw HTTP request string into its components.
/// Handles the format used in Nuclei's `raw:` blocks.
fn parse_raw_request(raw: &str, target_url: &str) -> Result<ParsedRawRequest, String> {
    // Normalize line endings.
    let normalized = raw.replace("\r\n", "\n");

    // Split on double newline to separate headers from body.
    let (header_section, body) = if let Some(pos) = normalized.find("\n\n") {
        let h = &normalized[..pos];
        let b = normalized[pos + 2..].to_string();
        (h, if b.is_empty() { None } else { Some(b) })
    } else {
        (normalized.as_str(), None)
    };

    let mut lines = header_section.lines().filter(|l| !l.trim_start().starts_with('@'));

    // First line: METHOD PATH HTTP/1.1
    let request_line = lines.next().ok_or("Empty raw request")?;
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid request line: {}", request_line));
    }

    let method = parts[0].to_string();
    let path = parts[1];

    // Resolve the path against the target URL.
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        let base = target_url.trim_end_matches('/');
        if path.starts_with('/') {
            // Extract scheme + host(:port) from target URL.
            if let Ok(parsed) = url::Url::parse(target_url) {
                let host = parsed.host_str().unwrap_or("localhost");
                let authority = match parsed.port() {
                    Some(port) => format!("{}:{}", host, port),
                    None => host.to_string(),
                };
                format!("{}://{}{}", parsed.scheme(), authority, path)
            } else {
                format!("{}{}", base, path)
            }
        } else {
            format!("{}/{}", base, path)
        }
    };

    // Parse remaining lines as headers. A template-specified Host header is
    // preserved (Go nuclei keeps it and only fills it from the target URL when
    // absent) — reqwest honors an explicit Host header for vhost testing.
    let mut headers = HashMap::new();
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    Ok(ParsedRawRequest {
        method,
        url,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_policy_default_max_redirects() {
        let policy = RequestPolicy::new(RedirectFlow::FollowAll, 0, false);
        assert_eq!(policy.max_redirects, DEFAULT_MAX_REDIRECTS);
        let policy = RequestPolicy::new(RedirectFlow::FollowAll, 3, false);
        assert_eq!(policy.max_redirects, 3);
    }

    #[test]
    fn test_normalize_host_strips_default_ports() {
        let a = url::Url::parse("http://example.com:80/x").unwrap();
        let b = url::Url::parse("http://example.com/x").unwrap();
        assert_eq!(normalize_host(&a), normalize_host(&b));
        assert_eq!(normalize_host(&a), "example.com");

        let c = url::Url::parse("https://example.com:443/x").unwrap();
        assert_eq!(normalize_host(&c), "example.com");

        let d = url::Url::parse("http://example.com:8080/x").unwrap();
        assert_eq!(normalize_host(&d), "example.com:8080");
    }

    #[test]
    fn test_normalize_host_ipv6() {
        let bare = url::Url::parse("https://[::1]/x").unwrap();
        assert_eq!(normalize_host(&bare), "[::1]");
        let port = url::Url::parse("https://[::1]:8443/x").unwrap();
        assert_eq!(normalize_host(&port), "[::1]:8443");
    }

    #[test]
    fn test_parse_raw_request_get() {
        let raw = "GET /path HTTP/1.1\r\nHost: example.com\r\nX-A: b\r\n\r\n";
        let parsed = parse_raw_request(raw, "http://target-host.com").unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.url, "http://target-host.com/path");
        // The template-specified Host header is preserved (Go parity).
        assert_eq!(parsed.headers.get("Host").map(|s| s.as_str()), Some("example.com"));
        assert_eq!(parsed.headers.get("X-A").map(|s| s.as_str()), Some("b"));
        assert_eq!(parsed.body, None);
    }

    #[test]
    fn test_parse_raw_request_skips_annotations() {
        // `@`-prefixed lines are annotations and must be ignored (Go parity).
        let raw = "@Host: http://annotated.example.com\nGET /path HTTP/1.1\nHost: target.com\nX-A: b\n\n";
        let parsed = parse_raw_request(raw, "http://target-host.com").unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.url, "http://target-host.com/path");
        assert_eq!(parsed.headers.get("Host").map(|s| s.as_str()), Some("target.com"));
        assert_eq!(parsed.headers.get("X-A").map(|s| s.as_str()), Some("b"));
        assert!(!parsed.headers.contains_key("@Host") && !parsed.headers.contains_key("Host: http://annotated.example.com"));
    }

    #[test]
    fn test_parse_raw_request_post_with_body() {
        let raw = "POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/json\nContent-Length: 13\n\n{\"user\":\"abc\"}";
        let parsed = parse_raw_request(raw, "http://target.com").unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.url, "http://target.com/api/login");
        assert_eq!(
            parsed.headers.get("Content-Type").map(|s| s.as_str()),
            Some("application/json")
        );
        assert_eq!(
            parsed.headers.get("Content-Length").map(|s| s.as_str()),
            Some("13")
        );
        assert_eq!(parsed.body.as_deref(), Some("{\"user\":\"abc\"}"));
    }

    #[test]
    fn test_parse_raw_request_absolute_url() {
        let raw = "GET http://other.com/path HTTP/1.1\nHost: other.com\n\n";
        let parsed = parse_raw_request(raw, "http://target.com").unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.url, "http://other.com/path");
    }

    #[test]
    fn test_parse_raw_request_relative_path_no_leading_slash() {
        let raw = "GET foo HTTP/1.1\n\n";
        let parsed = parse_raw_request(raw, "http://target.com").unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.url, "http://target.com/foo");
    }

    #[test]
    fn test_parse_raw_request_invalid() {
        assert!(parse_raw_request("", "http://target.com").is_err());
        assert!(parse_raw_request("GET", "http://target.com").is_err());
    }

    #[test]
    fn test_parse_raw_request_port_preserved() {
        let raw = "GET /x HTTP/1.1\nHost: 127.0.0.1:8080\n\n";
        let parsed = parse_raw_request(raw, "http://127.0.0.1:8080").unwrap();
        assert_eq!(parsed.url, "http://127.0.0.1:8080/x");
    }
}
