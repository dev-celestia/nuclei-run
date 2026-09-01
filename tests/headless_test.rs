use nuclei_run::engine::headless_client::{locate_chrome, parse_duration, HeadlessClient};
use nuclei_run::engine::runner::{EngineRunner, ScanTask};
use nuclei_run::models::template::NucleiTemplate;
use nuclei_run::parser::yaml_loader;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_headless_template_parsing_all_actions() {
    let yaml = r#"
id: test-headless-full-actions
info:
  name: Headless Comprehensive Test
  author: dev-celestia
  severity: high

headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/login"
      - action: waitload
      - action: wait-for
        target: "input#username"
      - action: setheader
        key: "X-Custom-Auth"
        value: "SecretToken"
      - action: text
        by: "input#username"
        value: "admin"
      - action: type
        selector: "input#password"
        value: "P@ssw0rd123"
      - action: select
        target: "select#role"
        value: "Administrator"
      - action: click
        target: "button#submit-btn"
      - action: rightclick
        by: "div#context-menu-trigger"
      - action: keyboard
        key: "Enter"
      - action: sleep
        args:
          duration: "500ms"
      - action: screenshot
        to: "/tmp/screenshot.png"
      - action: extract
        name: token_extracted
        selector: "span#csrf-token"
        attribute: "innerText"
      - action: script
        name: document_title
        code: "document.title"
    matchers:
      - type: word
        words:
          - "Dashboard"
      - type: word
        part: document_title
        words:
          - "Admin Portal"
"#;

    let tmpl: Result<NucleiTemplate, _> = serde_yaml::from_str(yaml);
    assert!(
        tmpl.is_ok(),
        "Failed to parse headless YAML: {:?}",
        tmpl.err()
    );
    let tmpl = tmpl.unwrap();
    assert_eq!(tmpl.id, "test-headless-full-actions");
    assert_eq!(tmpl.headless.len(), 1);

    let steps = &tmpl.headless[0].steps;
    assert_eq!(steps.len(), 14);

    assert_eq!(steps[0].action, "navigate");
    assert_eq!(
        steps[0].args.get("url"),
        Some(&"{{BaseURL}}/login".to_string())
    );

    assert_eq!(steps[1].action, "waitload");

    assert_eq!(steps[2].action, "wait-for");
    assert_eq!(steps[2].target.as_deref(), Some("input#username"));

    assert_eq!(steps[3].action, "setheader");
    assert_eq!(steps[3].key.as_deref(), Some("X-Custom-Auth"));
    assert_eq!(steps[3].value.as_deref(), Some("SecretToken"));

    assert_eq!(steps[4].action, "text");
    assert_eq!(steps[4].target.as_deref(), Some("input#username"));
    assert_eq!(steps[4].value.as_deref(), Some("admin"));

    assert_eq!(steps[5].action, "type");
    assert_eq!(steps[5].target.as_deref(), Some("input#password"));

    assert_eq!(steps[6].action, "select");
    assert_eq!(steps[6].target.as_deref(), Some("select#role"));

    assert_eq!(steps[7].action, "click");
    assert_eq!(steps[7].target.as_deref(), Some("button#submit-btn"));

    assert_eq!(steps[8].action, "rightclick");
    assert_eq!(steps[8].target.as_deref(), Some("div#context-menu-trigger"));

    assert_eq!(steps[9].action, "keyboard");

    assert_eq!(steps[10].action, "sleep");
    assert_eq!(steps[10].args.get("duration"), Some(&"500ms".to_string()));

    assert_eq!(steps[11].action, "screenshot");

    assert_eq!(steps[12].action, "extract");
    assert_eq!(steps[12].name.as_deref(), Some("token_extracted"));
    assert_eq!(steps[12].attribute.as_deref(), Some("innerText"));

    assert_eq!(steps[13].action, "script");
    assert_eq!(steps[13].name.as_deref(), Some("document_title"));
    assert_eq!(steps[13].code.as_deref(), Some("document.title"));
}

#[test]
fn test_duration_parser_variants() {
    assert_eq!(parse_duration("100ms"), Duration::from_millis(100));
    assert_eq!(parse_duration("250ms"), Duration::from_millis(250));
    assert_eq!(parse_duration("1s"), Duration::from_secs(1));
    assert_eq!(parse_duration("2.5s"), Duration::from_millis(2500));
    assert_eq!(parse_duration("5"), Duration::from_secs(5));
    assert_eq!(parse_duration("200"), Duration::from_millis(200));
}

#[tokio::test]
async fn test_headless_live_execution_if_chrome_available() {
    if locate_chrome().is_none() {
        eprintln!("[SKIP] Chrome/Chromium executable not found on host, skipping live CDP test");
        return;
    }

    let yaml = r#"
id: test-headless-live
info:
  name: Live Headless Test
  author: dev-celestia
  severity: info

headless:
  - steps:
      - action: script
        name: math_eval
        code: "2 + 2"
      - action: script
        name: user_agent
        code: "navigator.userAgent"
      - action: sleep
        args:
          duration: "50ms"
"#;

    let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
    let vars = HashMap::new();
    let result = HeadlessClient::execute(&tmpl.headless[0], "https://example.com", &vars).await;

    assert!(
        result.is_ok(),
        "Live headless execution failed: {:?}",
        result.err()
    );
    let resp = result.unwrap();
    assert_eq!(resp.data.get("math_eval").map(|s| s.as_str()), Some("4"));
    assert!(resp.data.get("user_agent").is_some());
    assert!(!resp.dom_content.is_empty());
}

#[tokio::test]
async fn test_headless_live_navigation_metadata_and_headers() {
    if locate_chrome().is_none() {
        eprintln!("[SKIP] Chrome executable not found, skipping live CDP metadata test");
        return;
    }

    let yaml = r#"
id: test-headless-nav-metadata
info:
  name: Live Headless Navigation Metadata Test
  author: dev-celestia
  severity: info

headless:
  - steps:
      - action: setheader
        key: "X-Nuclei-Test"
        value: "HeadlessLiveCheck"
      - action: navigate
        args:
          url: "https://example.com"
      - action: waitload
"#;

    let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
    let vars = HashMap::new();
    let result = HeadlessClient::execute(&tmpl.headless[0], "https://example.com", &vars).await;

    assert!(
        result.is_ok(),
        "Live navigation metadata test failed: {:?}",
        result.err()
    );
    let resp = result.unwrap();
    assert_eq!(resp.status, 200);
    assert!(!resp.headers.is_empty());
    assert!(resp.dom_content.contains("Example Domain") || resp.dom_content.contains("example"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_headless_form_flow_via_engine() {
    if locate_chrome().is_none() {
        eprintln!("[SKIP] Chrome/Chromium executable not found, skipping headless form flow test");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let html = r#"<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
  <input id="username" type="text" />
  <button id="submit" onclick="document.getElementById('result').innerText = document.getElementById('username').value + '-OK'">Submit</button>
  <div id="result"></div>
  <span id="csrf">CSRFTOKEN</span>
</body>
</html>"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);

    let yaml = r#"
id: test-headless-form-flow
info:
  name: Headless Form Flow Test
  author: test
  severity: high

headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/"
      - action: waitload
      - action: text
        target: "input#username"
        value: "admin"
      - action: click
        target: "button#submit"
      - action: script
        name: result
        code: "document.getElementById('result').innerText"
      - action: extract
        name: csrf
        selector: "span#csrf"
        attribute: "innerText"
    matchers-condition: and
    matchers:
      - type: word
        part: result
        words:
          - "admin-OK"
      - type: word
        part: csrf
        words:
          - "CSRFTOKEN"
"#;

    let dir = tempfile::tempdir().unwrap();
    let template_path = dir.path().join("headless_template.yaml");
    std::fs::write(&template_path, yaml).unwrap();

    let loaded = yaml_loader::load_templates(
        &template_path.to_string_lossy(),
        &yaml_loader::TemplateFilter::default(),
    );
    assert_eq!(loaded.templates.len(), 1);
    let template = Arc::new(loaded.templates.into_iter().next().unwrap());

    let engine = Arc::new(EngineRunner::new(
        1,
        10,
        0,
        0,
        None,
        &[],
        false,
        true,
        30,
        0,
        None,
    ));

    let tasks = vec![ScanTask { target, template }];

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

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "test-headless-form-flow");
    assert_eq!(findings[0].protocol, "headless");
}
