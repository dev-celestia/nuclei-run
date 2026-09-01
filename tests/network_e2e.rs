use nuclei_run::engine::runner::{EngineRunner, ScanTask};
use nuclei_run::models::result::ScanFinding;
use nuclei_run::parser::yaml_loader;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
async fn test_network_duration_dsl_matcher() {
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
                // Delayed reply: makes `duration` measurable in DSL matchers.
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let _ = stream.write_all(b"PONG").await;
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

    // Both matchers must hold: the DSL duration check AND the response body.
    // matchers-condition: and ensures a broken (always-zero) duration cannot
    // hide behind the word matcher.
    let tmpl_match = r#"
id: test-network-duration-match
info:
  name: Network Duration Match
  author: test
  severity: info
network:
  - inputs:
      - data: "PING\r\n"
        read: 1024
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "duration >= 1"
      - type: word
        words:
          - "PONG"
"#;
    let findings = run_template(Arc::clone(&engine), tmpl_match, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "network protocol must report real duration to DSL matchers"
    );
    assert_eq!(findings[0].template_id, "test-network-duration-match");

    // Template with dsl: duration >= 5 -> 0 findings
    let tmpl_no_match = r#"
id: test-network-duration-no-match
info:
  name: Network Duration No Match
  author: test
  severity: info
network:
  - inputs:
      - data: "PING\r\n"
        read: 1024
    matchers:
      - type: dsl
        dsl:
          - "duration >= 5"
"#;
    let findings_no = run_template(engine, tmpl_no_match, &target).await;
    assert_eq!(findings_no.len(), 0);
}
