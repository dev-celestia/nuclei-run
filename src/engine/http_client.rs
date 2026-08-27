use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
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
}

/// Configurable async HTTP client with connection pooling.
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration.
    pub fn new(
        timeout_secs: u64,
        max_redirects: usize,
        proxy_url: Option<&str>,
        custom_headers: &[(String, String)],
    ) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(max_redirects))
            .pool_max_idle_per_host(20)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        // Configure proxy if provided.
        if let Some(proxy) = proxy_url {
            if let Ok(p) = reqwest::Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
        }

        // Add custom default headers.
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

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        Self { client }
    }

    /// Create a simple client with just a timeout (for basic usage).
    #[allow(dead_code)]
    pub fn simple(timeout_secs: u64) -> Self {
        Self::new(timeout_secs, 10, None, &[])
    }

    /// Send an HTTP request and return the parsed response.
    pub async fn send(
        &self,
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

        let mut request = self.client.request(method, url);

        // Add per-request headers.
        for (k, v) in headers {
            request = request.header(k.as_str(), v.as_str());
        }

        // Add body if present.
        if let Some(body_content) = body {
            request = request.body(body_content.clone());
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        // Serialize headers to both raw string and map.
        let mut headers_raw = String::new();
        let mut headers_map = HashMap::new();
        for (key, value) in response.headers() {
            let v = value.to_str().unwrap_or_default();
            headers_raw.push_str(&format!("{}: {}\n", key.as_str(), v));
            headers_map.insert(key.as_str().to_lowercase(), v.to_string());
        }

        let body = response.text().await.unwrap_or_default();

        Ok(HttpResponse {
            status,
            headers_raw,
            body,
            headers_map,
        })
    }

    /// Parse a raw HTTP request string and send it.
    /// Raw format: METHOD PATH HTTP/1.1\r\nHeader: value\r\n\r\nBody
    pub async fn send_raw(
        &self,
        raw: &str,
        target_url: &str,
    ) -> Result<HttpResponse, String> {
        let parsed = parse_raw_request(raw, target_url)?;
        self.send(&parsed.method, &parsed.url, &parsed.headers, &parsed.body)
            .await
            .map_err(|e| e.to_string())
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
        let b = normalized[pos + 2..].trim().to_string();
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
            // Extract scheme + host from target URL.
            if let Ok(parsed) = url::Url::parse(target_url) {
                format!(
                    "{}://{}{}",
                    parsed.scheme(),
                    parsed.host_str().unwrap_or("localhost"),
                    path
                )
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
