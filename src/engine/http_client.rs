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

/// Configurable async HTTP client with connection pooling.
///
/// Mirrors nuclei's redirect semantics: requests do NOT follow redirects by
/// default; only requests belonging to blocks with `redirects: true` use the
/// redirect-following client. Failed requests are retried `retries` times.
pub struct HttpClient {
    client: reqwest::Client,
    client_redirect: reqwest::Client,
    retries: u32,
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration.
    pub fn new(
        timeout_secs: u64,
        max_redirects: usize,
        proxy_url: Option<&str>,
        custom_headers: &[(String, String)],
        retries: u32,
    ) -> Self {
        let build = |policy: Policy| {
            let mut builder = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .danger_accept_invalid_certs(true)
                .redirect(policy)
                .pool_max_idle_per_host(20)
                .pool_idle_timeout(Duration::from_secs(90))
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

            if let Some(proxy) = proxy_url {
                if let Ok(p) = reqwest::Proxy::all(proxy) {
                    builder = builder.proxy(p);
                }
            }

            if !custom_headers.is_empty() {
                let mut headers = HeaderMap::new();
                for (k, v) in custom_headers {
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
        };

        Self {
            client: build(Policy::none()),
            client_redirect: build(Policy::limited(max_redirects)),
            retries,
        }
    }

    /// Send an HTTP request without following redirects (nuclei default).
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &Option<String>,
    ) -> Result<HttpResponse, reqwest::Error> {
        self.execute(&self.client, method, url, headers, body).await
    }

    /// Send an HTTP request following redirects (blocks with `redirects: true`).
    pub async fn send_following(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &Option<String>,
    ) -> Result<HttpResponse, reqwest::Error> {
        self.execute(&self.client_redirect, method, url, headers, body)
            .await
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
        follow_redirects: bool,
    ) -> Result<HttpResponse, String> {
        let parsed = parse_raw_request(raw, target_url)?;
        let result = if follow_redirects {
            self.send_following(&parsed.method, &parsed.url, &parsed.headers, &parsed.body)
                .await
        } else {
            self.send(&parsed.method, &parsed.url, &parsed.headers, &parsed.body)
                .await
        };
        result.map_err(|e| e.to_string())
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

    let body = response.text().await.unwrap_or_default();

    HttpResponse {
        status,
        headers_raw,
        body,
        headers_map,
        duration_secs,
    }
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

    let mut lines = header_section.lines();

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

    // Parse remaining lines as headers.
    let mut headers = HashMap::new();
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            // Skip the Host header since reqwest sets it from the URL.
            if key.to_lowercase() != "host" {
                headers.insert(key, value);
            }
        }
    }

    Ok(ParsedRawRequest {
        method,
        url,
        headers,
        body,
    })
}
