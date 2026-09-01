use nuclei_run::engine::runner::{EngineRunner, ScanTask};
use nuclei_run::engine::workflow::WorkflowTemplateRegistry;
use nuclei_run::parser::yaml_loader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

/// Load a template into an Arc.
fn load_template(path: &std::path::Path) -> Arc<nuclei_run::models::template::NucleiTemplate> {
    let loaded = yaml_loader::load_templates(
        &path.to_string_lossy(),
        &yaml_loader::TemplateFilter::default(),
    );
    assert_eq!(loaded.templates.len(), 1, "template must load: {}", path.display());
    Arc::new(loaded.templates.into_iter().next().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_workflow_gates_subtemplate_on_extractor() {
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
                let body = if first_line.starts_with("GET /parent") {
                    "value is SECRET-abcd"
                } else if first_line.starts_with("GET /child") {
                    "CHILD_OK"
                } else {
                    "not found"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);

    let dir = tempfile::tempdir().unwrap();
    let parent_path = dir.path().join("parent.yaml");
    let child_path = dir.path().join("child.yaml");
    let workflow_path = dir.path().join("workflow.yaml");

    std::fs::write(
        &parent_path,
        r#"
id: wf-parent
info:
  name: Parent
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/parent"
    matchers:
      - type: word
        words:
          - "SECRET"
    extractors:
      - type: regex
        name: token
        regex:
          - "SECRET-([a-z]+)"
        group: 1
"#,
    )
    .unwrap();

    std::fs::write(
        &child_path,
        r#"
id: wf-child
info:
  name: Child
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/child"
    matchers:
      - type: word
        words:
          - "CHILD_OK"
"#,
    )
    .unwrap();

    std::fs::write(
        &workflow_path,
        r#"
id: wf-workflow
info:
  name: Workflow Gating
  author: test
  severity: info
workflows:
  - template: parent.yaml
    matchers:
      - name: token
        subtemplates:
          - template: child.yaml
"#,
    )
    .unwrap();

    // The registry is built from all non-workflow templates (parent + child).
    let parent = load_template(&parent_path);
    let child = load_template(&child_path);

    let engine = Arc::new(
        EngineRunner::new(2, 10, 0, 0, None, &[], false, false, 30, 0, None)
            .with_workflow_registry(Arc::new(WorkflowTemplateRegistry::new(vec![
                parent,
                child,
            ]))),
    );

    // The ScanTask uses the workflow template.
    let workflow = load_template(&workflow_path);
    assert!(
        !workflow.workflows.is_empty(),
        "workflow template must parse its workflows block"
    );

    let tasks = vec![ScanTask {
        target,
        template: workflow,
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
    let findings = collector.await.unwrap();

    // Parent matched AND extracted `token`, so the gated child subtemplate ran.
    let ids: Vec<&str> = findings.iter().map(|f| f.template_id.as_str()).collect();
    assert!(
        ids.contains(&"wf-child"),
        "extractor `token` should gate child subtemplate; got findings: {:?}",
        ids
    );
    assert!(
        findings.iter().any(|f| f.template_id == "wf-child"
            && f.matched_url.ends_with("/child")),
        "child finding should target /child; got {:?}",
        findings.iter().map(|f| f.matched_url.clone()).collect::<Vec<_>>()
    );
    assert_eq!(findings.len(), 2, "expected parent + child findings");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_workflow_skips_child_when_parent_does_not_extract() {
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
                let body = if first_line.starts_with("GET /parent") {
                    "no token here"
                } else if first_line.starts_with("GET /child") {
                    "CHILD_OK"
                } else {
                    "not found"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let target = format!("http://127.0.0.1:{}", port);
    let dir = tempfile::tempdir().unwrap();
    let parent_path = dir.path().join("parent.yaml");
    let child_path = dir.path().join("child.yaml");

    std::fs::write(
        &parent_path,
        r#"
id: wf-parent
info:
  name: Parent
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/parent"
    matchers:
      - type: word
        words:
          - "SECRET"
    extractors:
      - type: regex
        name: token
        regex:
          - "SECRET-([a-z]+)"
        group: 1
"#,
    )
    .unwrap();
    std::fs::write(
        &child_path,
        r#"
id: wf-child
info:
  name: Child
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/child"
    matchers:
      - type: word
        words:
          - "CHILD_OK"
"#,
    )
    .unwrap();

    let engine = Arc::new(
        EngineRunner::new(2, 10, 0, 0, None, &[], false, false, 30, 0, None)
            .with_workflow_registry(Arc::new(WorkflowTemplateRegistry::new(vec![
                load_template(&parent_path),
                load_template(&child_path),
            ]))),
    );

    let mut workflow_yaml = std::fs::read_to_string(dir.path().join("workflow.yaml")).unwrap_or_default();
    if workflow_yaml.is_empty() {
        workflow_yaml = r#"
id: wf-workflow
info:
  name: Workflow Gating
  author: test
  severity: info
workflows:
  - template: parent.yaml
    matchers:
      - name: token
        subtemplates:
          - template: child.yaml
"#
        .to_string();
        std::fs::write(dir.path().join("workflow.yaml"), &workflow_yaml).unwrap();
    }
    let workflow = load_template(&dir.path().join("workflow.yaml"));

    let tasks = vec![ScanTask {
        target,
        template: workflow,
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
    let findings = collector.await.unwrap();

    // Parent DID match ("SECRET" matcher is a no-op here — the body has no
    // SECRET either). The parent finds nothing, so no token extract, so the
    // child must NOT run.
    let ids: Vec<&str> = findings.iter().map(|f| f.template_id.as_str()).collect();
    assert!(
        !ids.contains(&"wf-child"),
        "child must not run when parent produced no token extract; got {:?}",
        ids
    );
    assert_eq!(findings.len(), 0, "no findings expected: {:?}", ids);
}
