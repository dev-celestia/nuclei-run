//! End-to-end Interactsh OOB test with a mock interactsh server and a mock
//! target. Verifies the full pipeline: registration → URL substitution →
//! request → pending correlation → polling → RSA/AES decryption → matcher
//! evaluation → finding emission.

use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use ctr::cipher::{KeyIvInit, StreamCipher};
use nuclei_run::engine::interactsh::InteractshClient;
use nuclei_run::engine::runner::{EngineRunner, ScanTask};
use nuclei_run::parser::yaml_loader;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct MockState {
    /// Base64 PKCS#1 PEM public key received from the client's registration.
    client_pubkey: Mutex<Option<String>>,
    /// Correlation subdomain captured from the target trigger request.
    interaction_id: Mutex<Option<String>>,
    /// Whether the encrypted interaction was already delivered via /poll.
    delivered: AtomicBool,
}

const TEMPLATE: &str = r#"
id: oob-e2e-check
info:
  name: OOB End-to-End Check
  author: test
  severity: info
http:
  - raw:
      - |
        GET /trigger?u={{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_interactsh_end_to_end() {
    let state = Arc::new(MockState::default());

    // --- Mock interactsh server -------------------------------------------
    let oast_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let oast_port = oast_listener.local_addr().unwrap().port();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = oast_listener.accept().await else {
                    break;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_oast_request(stream, state).await;
                });
            }
        });
    }

    // --- Mock target: captures the generated interactsh URL ---------------
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target_listener.local_addr().unwrap().port();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = target_listener.accept().await else {
                    break;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_target_request(stream, state).await;
                });
            }
        });
    }

    // --- Load the OOB template --------------------------------------------
    let dir = tempfile::tempdir().unwrap();
    let template_path = dir.path().join("oob-e2e.yaml");
    std::fs::write(&template_path, TEMPLATE).unwrap();
    let loaded = yaml_loader::load_templates(
        &template_path.to_string_lossy(),
        &yaml_loader::TemplateFilter::default(),
    );
    assert_eq!(loaded.templates.len(), 1, "template must load");
    let template = Arc::new(loaded.templates.into_iter().next().unwrap());

    // --- Run the engine against the mock target ---------------------------
    let client = InteractshClient::new(
        Some(&format!("http://127.0.0.1:{}", oast_port)),
        None,
    )
    .expect("client creation");

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
        Some(client),
    ));

    let tasks = vec![ScanTask {
        target: format!("http://127.0.0.1:{}", target_port),
        template: Arc::clone(&template),
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

    assert_eq!(
        findings.len(),
        1,
        "expected exactly one OOB-driven finding, got: {:?}",
        findings
    );
    assert_eq!(findings[0].template_id, "oob-e2e-check");
    assert_eq!(findings[0].protocol, "http");
    assert!(state.delivered.load(Ordering::Relaxed));
}

// ---------------------------------------------------------------------------
// Mock server handlers
// ---------------------------------------------------------------------------

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

        if let Some(header_end) = find_subsequence(&data, b"\r\n\r\n") {
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

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

async fn respond_json(stream: &mut tokio::net::TcpStream, body: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Mock target: capture the `u=<subdomain>.<host>` value from the request line.
async fn handle_target_request(mut stream: tokio::net::TcpStream, state: Arc<MockState>) {
    let data = read_http_request(&mut stream).await;
    let text = String::from_utf8_lossy(&data);
    if let Some(first_line) = text.lines().next() {
        // e.g. "GET /trigger?u=abc123.127.0.0.1 HTTP/1.1"
        if let Some(u_start) = first_line.find("u=") {
            let rest = &first_line[u_start + 2..];
            let value = rest.split(&[' ', '&'][..]).next().unwrap_or("");
            let subdomain = value.split('.').next().unwrap_or("").to_string();
            if !subdomain.is_empty() {
                *state.interaction_id.lock().unwrap() = Some(subdomain);
            }
        }
    }
    let body = "trigger received";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Mock interactsh server: register / poll / deregister endpoints.
async fn handle_oast_request(mut stream: tokio::net::TcpStream, state: Arc<MockState>) {
    let data = read_http_request(&mut stream).await;
    let text = String::from_utf8_lossy(&data).to_string();
    let first_line = text.lines().next().unwrap_or("").to_string();

    if first_line.starts_with("POST /register") {
        let body = split_body(&text);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(key) = v.get("public-key").and_then(|k| k.as_str()) {
                *state.client_pubkey.lock().unwrap() = Some(key.to_string());
            }
        }
        respond_json(&mut stream, r#"{"message":"registration successful"}"#).await;
    } else if first_line.starts_with("GET /poll") {
        match build_poll_response(&state) {
            Some(body) => respond_json(&mut stream, &body).await,
            None => respond_json(&mut stream, r#"{"data":[]}"#).await,
        }
    } else if first_line.starts_with("POST /deregister") {
        respond_json(&mut stream, r#"{"message":"deregistration successful"}"#).await;
    } else {
        respond_json(&mut stream, "{}").await;
    }
}

fn split_body(text: &str) -> &str {
    text.find("\r\n\r\n")
        .map(|p| &text[p + 4..])
        .unwrap_or("")
}

/// Build an encrypted poll response carrying one HTTP interaction for the
/// captured correlation subdomain (exactly like the real server would).
fn build_poll_response(state: &MockState) -> Option<String> {
    let id = state.interaction_id.lock().unwrap().clone()?;
    if state.delivered.swap(true, Ordering::Relaxed) {
        return None;
    }

    let pem_b64 = state.client_pubkey.lock().unwrap().clone()?;
    let pem = String::from_utf8(general_purpose::STANDARD.decode(pem_b64).ok()?).ok()?;
    let pubkey = RsaPublicKey::from_pkcs1_pem(&pem).ok()?;

    let interaction = serde_json::json!({
        "protocol": "http",
        "unique-id": id,
        "full-id": format!("{}.mockhost", id),
        "raw-request": "GET / HTTP/1.1\r\nHost: mockhost\r\n\r\n",
        "raw-response": "HTTP/1.1 200 OK\r\n\r\noob",
        "remote-address": "127.0.0.1",
    });
    let plain = serde_json::to_vec(&interaction).ok()?;

    // Encrypt the AES key with the client's RSA public key (OAEP SHA-256).
    let aes_key: [u8; 32] = rand::random();
    let mut rng = rand::rngs::OsRng;
    let encrypted_key = pubkey
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key)
        .ok()?;

    // AES-256-CTR with a prefixed 16-byte IV.
    let iv: [u8; 16] = rand::random();
    let mut cipher_text = plain;
    type Aes256Ctr = ctr::Ctr128BE<Aes256>;
    Aes256Ctr::new_from_slices(&aes_key, &iv)
        .ok()?
        .apply_keystream(&mut cipher_text);
    let mut blob = iv.to_vec();
    blob.extend_from_slice(&cipher_text);

    Some(format!(
        r#"{{"data":["{}"],"aes_key":"{}"}}"#,
        general_purpose::STANDARD.encode(&blob),
        general_purpose::STANDARD.encode(&encrypted_key)
    ))
}
