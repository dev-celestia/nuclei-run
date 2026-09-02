use nuclei_run::engine::runner::{EngineRunner, ScanTask};
use nuclei_run::models::result::ScanFinding;
use nuclei_run::parser::yaml_loader;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::Once;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

static PROVIDER: Once = Once::new();

fn install_provider() {
    // tokio-rustls defaults enable aws-lc-rs while this crate enables ring;
    // rustls refuses to auto-select between the two, so pin the ring provider.
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

const CHAIN_PEM: &str = "tests/fixtures/ssl/server-chain.pem";
const LEAF_PEM: &str = "tests/fixtures/ssl/server-cert.pem";
const KEY_PEM: &str = "tests/fixtures/ssl/server-key.pem";

async fn run_template(
    engine: Arc<EngineRunner>,
    template_yaml: &str,
    target: &str,
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
        target: target.to_string(),
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

fn leaf_sha256() -> String {
    let pem = std::fs::read(LEAF_PEM).unwrap();
    let der = CertificateDer::pem_slice_iter(&pem)
        .next()
        .unwrap()
        .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(der.as_ref());
    hex::encode(hasher.finalize())
}

async fn ssl_server() -> (Arc<EngineRunner>, String) {
    install_provider();
    let chain_pem = std::fs::read(CHAIN_PEM).unwrap();
    let key_pem = std::fs::read(KEY_PEM).unwrap();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&chain_pem)
        .map(|r| r.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&key_pem).unwrap();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // Drive the server handshake to completion; dropping closes it.
                let _ = acceptor.accept(stream).await;
            });
        }
    });

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
    (engine, format!("127.0.0.1:{}", port))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ssl_parity_variables_match() {
    let (engine, target) = ssl_server().await;

    let tmpl = r#"
id: test-ssl-parity-vars
info:
  name: SSL Parity Variables
  author: test
  severity: info
ssl:
  - matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "contains(subject_org, 'Server Org')"
      - type: dsl
        dsl:
          - "contains(emails, 'test@example.com')"
      - type: word
        part: tls_connection
        words:
          - "rustls"
      - type: word
        part: type
        words:
          - "ssl"
      - type: regex
        part: duration
        regex:
          - "[0-9]"
      - type: dsl
        dsl:
          - "contains(issuer_dn, 'Intermediate CA')"
"#;
    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(
        findings.len(),
        1,
        "all parity variables must be exposed and match"
    );
    assert_eq!(findings[0].template_id, "test-ssl-parity-vars");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ssl_certificate_pem_and_fingerprint_json() {
    let (engine, target) = ssl_server().await;
    let expected_sha256 = leaf_sha256();

    let tmpl = r#"
id: test-ssl-cert
info:
  name: SSL Certificate
  author: test
  severity: info
ssl:
  - extractors:
      - type: json
        name: sha256
        json:
          - ".fingerprint_hash.sha256"
    matchers:
      - type: word
        part: certificate
        words:
          - "BEGIN CERTIFICATE"
"#;
    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1, "certificate PEM matcher must match");
    assert_eq!(
        findings[0].extracted_results,
        vec![expected_sha256],
        "response JSON fingerprint must equal the leaf sha256"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ssl_chain_json_excludes_leaf() {
    let (engine, target) = ssl_server().await;

    let tmpl = r#"
id: test-ssl-chain
info:
  name: SSL Chain
  author: test
  severity: info
ssl:
  - extractors:
      - type: json
        name: chain_subject_cn
        json:
          - ".chain[0].subject_cn"
      - type: json
        name: chain_issuer_cn
        json:
          - ".chain[0].issuer_cn"
    matchers:
      - type: dsl
        dsl:
          - "contains(issuer_dn, 'Intermediate CA')"
"#;
    let findings = run_template(engine, tmpl, &target).await;
    assert_eq!(findings.len(), 1, "leaf issuer DN must match");
    let extracted = findings[0].extracted_results.clone();
    // chain[0] is the intermediate (leaf is flattened, never repeated in chain).
    assert!(
        extracted.contains(&"Intermediate CA".to_string()),
        "{extracted:?}"
    );
    assert!(extracted.contains(&"Root CA".to_string()), "{extracted:?}");
    assert!(
        !extracted.contains(&"localhost".to_string()),
        "{extracted:?}"
    );
}
