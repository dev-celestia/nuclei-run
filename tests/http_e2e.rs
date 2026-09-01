use nuclei_run::engine::runner::{EngineRunner, ScanTask};
use nuclei_run::models::result::ScanFinding;
use nuclei_run::parser::yaml_loader;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let Ok(n) = stream.read(&mut buf).await else {
            break;
        };
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);

        if let Some(header_end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&data[..header_end]).to_lowercase();
            let content_length = headers
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if data.len() >= header_end + 4 + content_length {
                break;
            }
        }
        if data.len() > 1_048_576 {
            break;
        }
    }
    data
}

async fn run_template(
    engine: Arc<EngineRunner>,
    template_yaml: &str,
    target_url: &str,
) -> Vec<ScanFinding> {
    let dir = tempfile::tempdir().unwrap();
    let template_path = dir.path().join("template.yaml");
    std::fs::write(&template_path, template_yaml).unwrap();

    let loaded = yaml_loader::load_templates(
        &template_path.to_string_lossy(),
        &yaml_loader::TemplateFilter::default(),
    );
    assert_eq!(loaded.templates.len(), 1, "template must load successfully");
    let template = Arc::new(loaded.templates.into_iter().next().unwrap());

    let tasks = vec![ScanTask {
        target: target_url.to_string(),
        template,
    }];

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let collector = tokio::spawn(async move {
        let mut findings = Vec::new();
        while let Some(f) = rx.recv().await {
            findings.push(f);
        }
        findings
    });

    engine.run(tasks, tx).await;
    collector.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_redirect_disabled_by_default() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");

                if first_line.starts_with("GET /start") {
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        port
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with("GET /final") {
                    let body = "FINAL_PAGE";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        5,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // Template A: matcher on status 302 (redirect not followed) -> 1 finding
    let tmpl_a = r#"
id: test-redirect-disabled-status
info:
  name: Redirect Disabled Status
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/start"
    matchers:
      - type: status
        status:
          - 302
"#;
    let findings_a = run_template(Arc::clone(&engine), tmpl_a, &target).await;
    assert_eq!(findings_a.len(), 1);
    assert_eq!(findings_a[0].template_id, "test-redirect-disabled-status");

    // Template B: matcher on final body "FINAL_PAGE" -> 0 findings
    let tmpl_b = r#"
id: test-redirect-disabled-body
info:
  name: Redirect Disabled Body
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/start"
    matchers:
      - type: word
        words:
          - "FINAL_PAGE"
"#;
    let findings_b = run_template(Arc::clone(&engine), tmpl_b, &target).await;
    assert_eq!(findings_b.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_redirect_enabled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");

                if first_line.starts_with("GET /start") {
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        port
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with("GET /final") {
                    let body = "FINAL_PAGE";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        5,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    let tmpl = r#"
id: test-redirect-enabled
info:
  name: Redirect Enabled
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/start"
    redirects: true
    max-redirects: 5
    matchers:
      - type: word
        words:
          - "FINAL_PAGE"
"#;
    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "test-redirect-enabled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_duration_dsl_matcher() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let body = "slow response";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        10,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // Template with dsl: duration >= 1 -> 1 finding
    let tmpl_match = r#"
id: test-duration-match
info:
  name: Duration Match
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/slow"
    matchers:
      - type: dsl
        dsl:
          - "duration >= 1"
"#;
    let findings = run_template(Arc::clone(&engine), tmpl_match, &target).await;
    assert_eq!(findings.len(), 1);

    // Template with dsl: duration >= 5 -> 0 findings
    let tmpl_no_match = r#"
id: test-duration-no-match
info:
  name: Duration No Match
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/slow"
    matchers:
      - type: dsl
        dsl:
          - "duration >= 5"
"#;
    let findings_no = run_template(engine, tmpl_no_match, &target).await;
    assert_eq!(findings_no.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_randstr_pinned_across_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let recorded_headers = Arc::new(Mutex::new(Vec::new()));
    let recorded_clone = Arc::clone(&recorded_headers);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let recorded = Arc::clone(&recorded_clone);
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);

                let x_rand = req_str
                    .lines()
                    .find_map(|l| {
                        let lower = l.to_lowercase();
                        if lower.starts_with("x-rand:") {
                            Some(l[7..].trim().to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();

                recorded.lock().await.push(x_rand.clone());

                let body = format!("ECHO: {}", x_rand);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    let tmpl = r#"
id: test-randstr-pinned
info:
  name: Randstr Pinned
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/r1"
      - "{{BaseURL}}/r2"
    headers:
      X-Rand: "{{randstr}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "ECHO: {{randstr}}"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].template_id, "test-randstr-pinned");
    assert_eq!(findings[1].template_id, "test-randstr-pinned");

    let recorded = recorded_headers.lock().await;
    assert_eq!(recorded.len(), 2);
    assert!(!recorded[0].is_empty());
    assert_eq!(recorded[0], recorded[1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_template_variables() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("");

                let body = format!("PATH_WAS: {}", path);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    let tmpl = r#"
id: test-variables
info:
  name: Template Variables
  author: test
  severity: info
variables:
  probe: magicvalue123
http:
  - method: GET
    path:
      - "{{BaseURL}}/vars/{{probe}}"
    matchers:
      - type: word
        words:
          - "PATH_WAS: /vars/magicvalue123"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "test-variables");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_extractor_feed_forward() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");

                if first_line.starts_with("GET /token") {
                    let body = "token=SECRET987XYZ";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with("GET /echo") {
                    let x_token = req_str
                        .lines()
                        .find_map(|l| {
                            let lower = l.to_lowercase();
                            if lower.starts_with("x-token:") {
                                Some(l[8..].trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    let body = format!("TOKEN_ECHO: {}", x_token);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    let tmpl = r#"
id: test-extractor-feed-forward
info:
  name: Extractor Feed Forward
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/token"
    extractors:
      - type: regex
        name: token
        regex:
          - "token=([A-Z0-9]+)"
        group: 1
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/echo"
    headers:
      X-Token: "{{token}}"
    matchers:
      - type: word
        words:
          - "TOKEN_ECHO: SECRET987XYZ"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "test-extractor-feed-forward");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if count == 0 {
                    // Drop/shutdown connection immediately to trigger connection/read error in client
                    let _ = stream.shutdown().await;
                } else {
                    let _ = read_http_request(&mut stream).await;
                    let body = "RETRY_SUCCESS";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        3,
        None,
    ));

    let tmpl = r#"
id: test-retry
info:
  name: Retry Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/retry-endpoint"
    matchers:
      - type: word
        words:
          - "RETRY_SUCCESS"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "test-retry");
    assert!(attempts.load(Ordering::SeqCst) >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_variable_semantics() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");
                // Echo the request target (path + query) back in the body.
                let target_path = first_line.split_whitespace().nth(1).unwrap_or("");
                let body = target_path.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // Explicit-port target: Go nuclei exposes {{Hostname}} as host:port and
    // {{Host}} as the bare host. {{RootURL}} keeps the explicit port.
    let tmpl = r#"
id: test-variable-semantics
info:
  name: Variable Semantics
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe/H={{Hostname}}/O={{Host}}/P={{Port}}/S={{Scheme}}/R={{RootURL}}"
    matchers:
      - type: word
        condition: and
        words:
          - "H=127.0.0.1:__PORT__"
          - "O=127.0.0.1/"
          - "P=__PORT__/"
          - "S=http/"
          - "R=http://127.0.0.1:__PORT__"
"#
    .replace("__PORT__", &port.to_string());

    let findings = run_template(engine, &tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "variable interpolation must match Go nuclei semantics"
    );
    assert_eq!(findings[0].template_id, "test-variable-semantics");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_json_jq_extractor_output() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = r#"{"users":[{"id":"u1"},{"id":"u2"}]}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // `.users[].id` iterates the array; a dot-path extractor could not do this.
    let tmpl = r#"
id: test-json-jq-extractor
info:
  name: JSON JQ Extractor
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/users"
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: json
        json:
          - ".users[].id"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1);
    // HashMap iteration order is not stable; compare as a sorted set.
    let mut results = findings[0].extracted_results.clone();
    results.sort();
    assert_eq!(results, vec!["u1".to_string(), "u2".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xpath_html_attribute_feed_forward() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("");

                let body = if path.starts_with("/page") {
                    // Malformed HTML (no closing tags): only a lenient HTML
                    // parser handles this; a strict XML parser would reject it.
                    r#"<html><body><input name="csrf" value="SECRETX"><p>hi</p></body>"#.to_string()
                } else if let Some(tok) = path.strip_prefix("/submit/") {
                    format!("TOKEN_ECHO: {}", tok)
                } else {
                    "NOT FOUND".to_string()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // Extract the `value` attribute of an HTML input, then chain it into the
    // next request via {{csrf}}.
    let tmpl = r#"
id: test-xpath-html-attribute
info:
  name: XPath HTML Attribute
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/page"
    extractors:
      - type: xpath
        name: csrf
        attribute: value
        xpath:
          - "//input[@name='csrf']"
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/submit/{{csrf}}"
    matchers:
      - type: word
        words:
          - "TOKEN_ECHO: SECRETX"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "HTML XPath attribute extraction must feed forward"
    );
    assert_eq!(findings[0].template_id, "test-xpath-html-attribute");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_regex_multi_value_indexed_naming() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("");

                let body = if path.starts_with("/source") {
                    "prefix code=AAA middle code=BBB suffix".to_string()
                } else if let Some(v) = path.strip_prefix("/echo/") {
                    format!("ECHO: {}", v)
                } else {
                    "NOT FOUND".to_string()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // The extractor matches both AAA and BBB. Go names the first value `code`
    // and the second `code1`; request 2 uses {{code1}} to prove that indexed
    // naming reaches downstream request building.
    let tmpl = r#"
id: test-regex-indexed-naming
info:
  name: Regex Indexed Naming
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/source"
    extractors:
      - type: regex
        name: code
        group: 1
        regex:
          - "code=([A-Z]+)"
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/echo/{{code1}}"
    matchers:
      - type: word
        words:
          - "ECHO: BBB"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "multi-value regex extractor must expose indexed names (code1)"
    );
    assert_eq!(findings[0].template_id, "test-regex-indexed-naming");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_hex_word_encoding_matcher() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = "received PING from server";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // "50494e47" is hex for "PING". Go decodes hex-encoded words at compile
    // time, so the decoded pattern must match the body — the literal hex
    // string never appears in the response.
    let tmpl = r#"
id: test-hex-word-encoding
info:
  name: Hex Word Encoding
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: word
        encoding: hex
        words:
          - "50494e47"
"#;

    let findings = run_template(engine.clone(), tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "hex-encoded word must be decoded before matching"
    );
    assert_eq!(findings[0].template_id, "test-hex-word-encoding");

    // A hex word whose decoded bytes are absent must not match.
    let tmpl_miss = r#"
id: test-hex-word-encoding-miss
info:
  name: Hex Word Encoding Miss
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: word
        encoding: hex
        words:
          - "deadbeef"
"#;

    let findings = run_template(engine, tmpl_miss, &target).await;
    assert_eq!(findings.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_content_length_header_dsl() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = "hello";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // content_length is sourced from the Content-Length header when present
    // (header-vs-body divergence is covered by unit tests, since a real HTTP
    // client rejects truncated bodies).
    let tmpl = r#"
id: test-content-length-dsl
info:
  name: Content Length DSL
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: dsl
        dsl:
          - "content_length == 5 && status_code == 200"
"#;

    let findings = run_template(engine.clone(), tmpl, &target).await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "test-content-length-dsl");

    let tmpl_miss = r#"
id: test-content-length-dsl-miss
info:
  name: Content Length DSL Miss
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: dsl
        dsl:
          - "content_length == 6"
"#;

    let findings = run_template(engine, tmpl_miss, &target).await;
    assert_eq!(findings.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_header_cookie_variable_dsl_matcher() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = "plain page";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1\r\nSet-Cookie: session=abc123; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // Go exposes every response header (lowercased, `-`→`_`) and every
    // Set-Cookie name as a DSL variable. Neither value appears in the body,
    // so this only matches when the variable map is built correctly.
    let tmpl = r#"
id: test-header-cookie-dsl-vars
info:
  name: Header Cookie DSL Vars
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: dsl
        dsl:
          - "contains(x_powered_by, \"PHP\")"
          - "contains(session, \"abc123\")"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "header and cookie variables must be visible to DSL matchers"
    );
    assert_eq!(findings[0].template_id, "test-header-cookie-dsl-vars");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_dsl_extractor_feed_forward() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("");

                if let Some(v) = path.strip_prefix("/echo/") {
                    let body = format!("ECHO: {}", v);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    let body = r#"{"ok":true}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2,
        5,
        0,
        0,
        None,
        &[],
        false,
        false,
        30,
        0,
        None,
    ));

    // A DSL extractor evaluates against the response data map (Go
    // ExtractDSL): `content_type` resolves to the response header value and
    // feeds forward into the second request.
    let tmpl = r#"
id: test-dsl-extractor-feed-forward
info:
  name: DSL Extractor Feed Forward
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/api"
    extractors:
      - type: dsl
        name: ct
        dsl:
          - "content_type"
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/echo/{{ct}}"
    matchers:
      - type: word
        words:
          - "ECHO: application/json"
"#;

    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "DSL extractor must resolve response variables and feed forward"
    );
    assert_eq!(findings[0].template_id, "test-dsl-extractor-feed-forward");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cookie_jar_feed_forward() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes).to_lowercase();
                let first_line = req_str.lines().next().unwrap_or("").to_string();

                if first_line.starts_with("get /login") {
                    let body = "LOGIN-OK";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with("get /dash") {
                    let body = if req_str.contains("cookie: session=abc123") {
                        "COOKIE-OK"
                    } else {
                        "NO-COOKIE"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2, 5, 0, 10, None, &[], false, false, 30, 0, None,
    ));

    // Go default: cookie jar enabled — the Set-Cookie from /login is resent
    // on /dash within the same template execution.
    let tmpl_jar = r#"
id: test-cookie-jar-feed-forward
info:
  name: Cookie Jar Feed Forward
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/dash"
    matchers:
      - type: word
        words:
          - "COOKIE-OK"
"#;
    let findings = run_template(Arc::clone(&engine), tmpl_jar, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "cookies set by an earlier request must be replayed on later requests"
    );

    // disable-cookie: true disables the jar (Go DisableCookie) — the second
    // request must arrive without the session cookie.
    let tmpl_no_jar = r#"
id: test-disable-cookie
info:
  name: Disable Cookie
  author: test
  severity: info
http:
  - method: GET
    disable-cookie: true
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/dash"
    matchers:
      - type: word
        words:
          - "NO-COOKIE"
"#;
    let findings = run_template(engine, tmpl_no_jar, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "disable-cookie must prevent cookie reuse across requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_redirects_max_hops_enforced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");

                let resp = if first_line.starts_with("GET /hop1") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/hop2\r\nContent-Length: 9\r\nConnection: close\r\n\r\nhop1-body",
                        port
                    )
                } else if first_line.starts_with("GET /hop2") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/hop3\r\nContent-Length: 9\r\nConnection: close\r\n\r\nhop2-body",
                        port
                    )
                } else if first_line.starts_with("GET /hop3") {
                    let body = "CHAIN-END";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2, 5, 0, 10, None, &[], false, false, 30, 0, None,
    ));

    // max-redirects: 1 — follow exactly one hop, then return the intermediate
    // 302 response (Go checkMaxRedirects semantics).
    let tmpl_limited = r#"
id: test-redirect-max-limited
info:
  name: Redirect Max Limited
  author: test
  severity: info
http:
  - method: GET
    redirects: true
    max-redirects: 1
    path:
      - "{{BaseURL}}/hop1"
    matchers:
      - type: word
        words:
          - "hop2-body"
      - type: status
        status:
          - 302
"#;
    let findings = run_template(Arc::clone(&engine), tmpl_limited, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "max-redirects: 1 must stop after one hop with the 302 response"
    );

    // Sufficient cap — the full chain is followed to the final page.
    let tmpl_full = r#"
id: test-redirect-full-chain
info:
  name: Redirect Full Chain
  author: test
  severity: info
http:
  - method: GET
    redirects: true
    max-redirects: 5
    path:
      - "{{BaseURL}}/hop1"
    matchers:
      - type: word
        words:
          - "CHAIN-END"
"#;
    let findings = run_template(engine, tmpl_full, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "redirects: true with a sufficient cap must follow the whole chain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_host_redirects_same_host_followed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");

                let resp = if first_line.starts_with("GET /a") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        port
                    )
                } else if first_line.starts_with("GET /b") {
                    let body = "SAME-HOST-OK";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let engine = Arc::new(EngineRunner::new(
        2, 5, 0, 10, None, &[], false, false, 30, 0, None,
    ));

    let tmpl = r#"
id: test-host-redirects-same-host
info:
  name: Host Redirects Same Host
  author: test
  severity: info
http:
  - method: GET
    host-redirects: true
    max-redirects: 3
    path:
      - "{{BaseURL}}/a"
    matchers:
      - type: word
        words:
          - "SAME-HOST-OK"
"#;
    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "host-redirects must follow redirects that stay on the original host"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_host_redirects_cross_host_stopped() {
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_b = listener_b.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener_a.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = "REDIR-BODY";
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/dest\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    port_b,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener_b.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = "CROSS-HOST-OK";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port_a);
    let engine = Arc::new(EngineRunner::new(
        2, 5, 0, 10, None, &[], false, false, 30, 0, None,
    ));

    // host-redirects: different port = different normalized host (Go
    // normalizeHost), so the redirect must NOT be followed and the 302
    // response itself is returned.
    let tmpl_host = r#"
id: test-host-redirects-cross-host-stop
info:
  name: Host Redirects Cross Host Stop
  author: test
  severity: info
http:
  - method: GET
    host-redirects: true
    max-redirects: 3
    path:
      - "{{BaseURL}}/start"
    matchers:
      - type: word
        words:
          - "REDIR-BODY"
"#;
    let findings = run_template(Arc::clone(&engine), tmpl_host, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "host-redirects must stop at redirects pointing to another host"
    );

    // redirects: true follows the cross-host redirect.
    let tmpl_all = r#"
id: test-redirects-cross-host-follow
info:
  name: Redirects Cross Host Follow
  author: test
  severity: info
http:
  - method: GET
    redirects: true
    max-redirects: 3
    path:
      - "{{BaseURL}}/start"
    matchers:
      - type: word
        words:
          - "CROSS-HOST-OK"
"#;
    let findings = run_template(engine, tmpl_all, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "redirects: true must follow redirects to other hosts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_global_redirect_cli_flags() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let req_bytes = read_http_request(&mut stream).await;
                let req_str = String::from_utf8_lossy(&req_bytes);
                let first_line = req_str.lines().next().unwrap_or("");

                let resp = if first_line.starts_with("GET /gfinal") {
                    let body = "GLOBAL-OK";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else if first_line.starts_with("GET /g") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/gfinal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        port
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);

    // Template declares nothing about redirects; global -fr enables them.
    let tmpl = r#"
id: test-global-follow-redirects
info:
  name: Global Follow Redirects
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/g"
    matchers:
      - type: word
        words:
          - "GLOBAL-OK"
"#;
    let engine_follow = Arc::new(
        EngineRunner::new(2, 5, 0, 10, None, &[], false, false, 30, 0, None)
            .with_redirect_flags(true, false, false),
    );
    let findings = run_template(engine_follow, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "global follow-redirects (-fr) must enable redirect following"
    );

    // Global -dr disables redirects even if a template asks for them.
    let tmpl_ask = r#"
id: test-global-disable-redirects
info:
  name: Global Disable Redirects
  author: test
  severity: info
http:
  - method: GET
    redirects: true
    path:
      - "{{BaseURL}}/g"
    matchers:
      - type: status
        status:
          - 302
"#;
    let engine_disable = Arc::new(
        EngineRunner::new(2, 5, 0, 10, None, &[], false, false, 30, 0, None)
            .with_redirect_flags(true, false, true),
    );
    let findings = run_template(engine_disable, tmpl_ask, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "global disable-redirects (-dr) must override template redirects"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_self_contained_gating_and_execution() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let body = "SELFCONTAINED-OK";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let tmpl_top = format!(
        r#"
id: test-self-contained-top
info:
  name: Self Contained Top
  author: test
  severity: info
self-contained: true
http:
  - method: GET
    path:
      - "http://127.0.0.1:{}/probe"
    matchers:
      - type: word
        words:
          - "SELFCONTAINED-OK"
"#,
        port
    );
    let tmpl_block = format!(
        r#"
id: test-self-contained-block
info:
  name: Self Contained Block
  author: test
  severity: info
http:
  - method: GET
    self-contained: true
    path:
      - "http://127.0.0.1:{}/probe"
    matchers:
      - type: word
        words:
          - "SELFCONTAINED-OK"
"#,
        port
    );
    std::fs::write(dir.path().join("sc_top.yaml"), tmpl_top).unwrap();
    std::fs::write(dir.path().join("sc_block.yaml"), tmpl_block).unwrap();

    // Default: self-contained templates are excluded at load time (Go
    // capability gate, loadBlocking).
    let loaded = yaml_loader::load_templates(
        &dir.path().to_string_lossy(),
        &yaml_loader::TemplateFilter::default(),
    );
    assert_eq!(loaded.templates.len(), 0, "must be excluded without -esc");
    assert_eq!(loaded.skipped_self_contained, 2);

    // With -esc enabled they load and run without any target input.
    let filter = yaml_loader::TemplateFilter {
        enable_self_contained: true,
        ..Default::default()
    };
    let loaded = yaml_loader::load_templates(&dir.path().to_string_lossy(), &filter);
    assert_eq!(loaded.templates.len(), 2, "must load with -esc enabled");

    let engine = Arc::new(EngineRunner::new(
        2, 5, 0, 10, None, &[], false, false, 30, 0, None,
    ));
    let tasks: Vec<ScanTask> = loaded
        .templates
        .into_iter()
        .map(|t| ScanTask {
            target: String::new(),
            template: Arc::new(t),
        })
        .collect();

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let collector = tokio::spawn(async move {
        let mut findings = Vec::new();
        while let Some(f) = rx.recv().await {
            findings.push(f);
        }
        findings
    });
    engine.run(tasks, tx).await;
    let findings = collector.await.unwrap();

    assert_eq!(
        findings.len(),
        2,
        "self-contained templates must execute once with their own URL"
    );
    for f in &findings {
        assert!(
            f.matched_url.contains("/probe"),
            "finding must carry the template's own URL, got {}",
            f.matched_url
        );
    }
}
