//! Live Interactsh OOB client implementing the projectdiscovery/interactsh
//! wire protocol (reference: interactsh v1.3.x `pkg/client`).
//!
//! - Registration: `POST /register` with a base64 PKCS#1 "RSA PUBLIC KEY" PEM,
//!   a random secret key and correlation ID. Re-registered periodically as
//!   keepalive (the server evicts sessions).
//! - URL generation: `<correlation-id><nonce>.<server-host>` where the nonce is
//!   13 z-base-32 characters (nuclei correlates on the full first DNS label).
//! - Polling: `GET /poll?id=<correlation-id>&secret=<secret-key>` every 5s;
//!   each `data` entry is base64 → AES-CTR decrypted with the AES key recovered
//!   via RSA-OAEP-SHA256 decryption of `aes_key`.
//! - Correlation: `Interaction.unique-id` equals the first label of the
//!   generated URL; pending request contexts are keyed by that label.

use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};
use crate::models::result::ScanFinding;
use crate::models::template::{TemplateExtractor, TemplateMatcher};
use base64::{engine::general_purpose, Engine as _};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::Rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, RwLock};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Default public Interactsh servers (mirrors the Go client default list).
const DEFAULT_SERVERS: &[&str] = &[
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
];

const CORRELATION_ID_LEN: usize = 20;
const NONCE_LEN: usize = 13;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// An out-of-band interaction event recorded by the Interactsh server.
/// `full_id`, `q_type`, `smtp_from` and `remote_address` are kept for wire
/// completeness (nuclei surfaces them in debug output).
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub struct Interaction {
    #[serde(rename = "protocol", default)]
    pub protocol: String,
    #[serde(rename = "unique-id", default)]
    pub unique_id: String,
    #[serde(rename = "full-id", default)]
    pub full_id: String,
    #[serde(rename = "q-type", default)]
    pub q_type: String,
    #[serde(rename = "raw-request", default)]
    pub raw_request: String,
    #[serde(rename = "raw-response", default)]
    pub raw_response: String,
    #[serde(rename = "smtp-from", default)]
    pub smtp_from: String,
    #[serde(rename = "remote-address", default)]
    pub remote_address: String,
}

#[derive(serde::Deserialize)]
struct PollResponse {
    #[serde(default)]
    data: Vec<String>,
    #[serde(default, rename = "aes_key")]
    aes_key: String,
}

#[derive(serde::Serialize)]
struct RegisterRequest<'a> {
    #[serde(rename = "public-key")]
    public_key: &'a str,
    #[serde(rename = "secret-key")]
    secret_key: &'a str,
    #[serde(rename = "correlation-id")]
    correlation_id: &'a str,
}

/// Everything needed to evaluate a block's matchers and emit a finding when an
/// interaction arrives for a generated correlation URL.
pub struct PendingRequest {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub tags: Option<String>,
    pub matched_url: String,
    /// Saved HTTP response context (status/headers/body) of the request that
    /// carried the interactsh URL — interactsh matchers may combine OOB parts
    /// with response parts.
    pub status: u16,
    pub headers: String,
    pub body: String,
    pub matchers_condition: String,
    pub matchers: Vec<TemplateMatcher>,
    pub extractors: Vec<TemplateExtractor>,
}

struct CorrelationState {
    /// First DNS label of generated URL → pending request contexts.
    requests: HashMap<String, Vec<Arc<PendingRequest>>>,
    /// Interactions that arrived before their request was registered.
    early_interactions: HashMap<String, Vec<Interaction>>,
}

/// Live Interactsh session: registration, URL generation, polling, decryption.
pub struct InteractshClient {
    server_url: String,
    hostname: String,
    token: Option<String>,
    correlation_id: String,
    secret_key: String,
    private_key: RsaPrivateKey,
    public_key_b64: String,
    http: reqwest::Client,
    aes_key: RwLock<Option<Vec<u8>>>,
    state: RwLock<CorrelationState>,
    last_registered: RwLock<Instant>,
    /// Failures are retried with backoff; before this instant, registration
    /// attempts short-circuit so unreachable servers don't stall the scan.
    next_retry: RwLock<Instant>,
    generated: AtomicBool,
}

impl InteractshClient {
    /// Create a new client. `server` may be a bare domain or a full URL; when
    /// absent, a random public Interactsh server is used.
    pub fn new(server: Option<&str>, token: Option<&str>) -> Result<Arc<Self>, String> {
        let (server_url, hostname) = match server {
            Some(s) => Self::normalize_server(s)?,
            None => {
                let host =
                    DEFAULT_SERVERS[rand::thread_rng().gen_range(0..DEFAULT_SERVERS.len())];
                (format!("https://{}", host), host.to_string())
            }
        };

        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| e.to_string())?;
        let public_key = rsa::RsaPublicKey::from(&private_key);

        // Interactsh expects base64(PEM) where the PEM block is PKCS#1
        // "RSA PUBLIC KEY".
        let pem = public_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|e| e.to_string())?;
        let public_key_b64 = general_purpose::STANDARD.encode(pem.as_bytes());

        let correlation_id = random_string(CORRELATION_ID_LEN);
        let secret_key = random_string(CORRELATION_ID_LEN);

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("nuclei-run/0.1")
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Arc::new(Self {
            server_url,
            hostname,
            token: token.map(|t| t.to_string()),
            correlation_id,
            secret_key,
            private_key,
            public_key_b64,
            http,
            aes_key: RwLock::new(None),
            state: RwLock::new(CorrelationState {
                requests: HashMap::new(),
                early_interactions: HashMap::new(),
            }),
            last_registered: RwLock::new(Instant::now() - KEEPALIVE_INTERVAL),
            next_retry: RwLock::new(Instant::now()),
            generated: AtomicBool::new(false),
        }))
    }

    /// The interactsh server domain used in correlation URLs.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Register (or re-register as keepalive) with the server. Failures set a
    /// backoff window so unreachable servers don't stall the scan.
    pub async fn register(&self) -> Result<(), String> {
        let req = RegisterRequest {
            public_key: &self.public_key_b64,
            secret_key: &self.secret_key,
            correlation_id: &self.correlation_id,
        };

        let mut request = self
            .http
            .post(format!("{}/register", self.server_url))
            .json(&req);
        if let Some(token) = &self.token {
            request = request.header("Authorization", token.clone());
        }

        let result: Result<(), String> = async {
            let response = request.send().await.map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("registration failed: HTTP {}", response.status()));
            }
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                *self.last_registered.write().await = Instant::now();
                Ok(())
            }
            Err(e) => {
                *self.next_retry.write().await = Instant::now() + Duration::from_secs(60);
                Err(e)
            }
        }
    }

    /// Ensure the session is registered (initial registration or keepalive).
    async fn ensure_registered(&self) -> Result<(), String> {
        let needs_refresh = {
            let last = *self.last_registered.read().await;
            last.elapsed() >= KEEPALIVE_INTERVAL
        };
        if !needs_refresh {
            return Ok(());
        }

        // Backoff: after a failure, don't hammer an unreachable server.
        if Instant::now() < *self.next_retry.read().await {
            return Err("interactsh registration in backoff".to_string());
        }

        self.register().await
    }

    /// Generate a new correlation URL (initializing the session lazily).
    pub async fn generate_url(&self) -> Result<String, String> {
        self.ensure_registered().await?;
        self.generated.store(true, Ordering::Relaxed);
        Ok(format!(
            "{}{}.{}",
            self.correlation_id,
            zbase32_nonce(NONCE_LEN),
            self.hostname
        ))
    }

    /// Whether any correlation URL was generated during this scan.
    pub fn generated_any(&self) -> bool {
        self.generated.load(Ordering::Relaxed)
    }

    /// Correlation key for a generated URL: the full first DNS label.
    pub fn correlation_key(url: &str) -> &str {
        url.split('.').next().unwrap_or("")
    }

    /// Store a pending request for a generated URL. If interactions already
    /// arrived for this label, return them for immediate processing (mirrors
    /// nuclei's early-interaction handling).
    pub async fn add_request(
        &self,
        url: &str,
        pending: Arc<PendingRequest>,
    ) -> Vec<Interaction> {
        let key = Self::correlation_key(url).to_string();
        let mut state = self.state.write().await;
        if let Some(early) = state.early_interactions.remove(&key) {
            return early;
        }
        state.requests.entry(key).or_default().push(pending);
        Vec::new()
    }

    /// Deregister from the server.
    pub async fn deregister(&self) {
        let body = serde_json::json!({
            "correlation-id": self.correlation_id,
            "secret-key": self.secret_key,
        });
        let mut request = self
            .http
            .post(format!("{}/deregister", self.server_url))
            .json(&body);
        if let Some(token) = &self.token {
            request = request.header("Authorization", token.clone());
        }
        let _ = request.send().await;
    }

    /// Poll once: decrypt and correlate all pending interactions.
    async fn poll_once(&self) -> Vec<(Interaction, Vec<Arc<PendingRequest>>)> {
        let url = format!(
            "{}/poll?id={}&secret={}",
            self.server_url, self.correlation_id, self.secret_key
        );
        let mut request = self.http.get(&url);
        if let Some(token) = &self.token {
            request = request.header("Authorization", token.clone());
        }

        let Ok(response) = request.send().await else {
            return Vec::new();
        };
        let Ok(poll) = response.json::<PollResponse>().await else {
            return Vec::new();
        };
        if poll.data.is_empty() {
            return Vec::new();
        }

        // Recover the AES session key (encrypted with our RSA public key).
        if !poll.aes_key.is_empty() {
            if let Ok(key) = self.decrypt_aes_key(&poll.aes_key) {
                *self.aes_key.write().await = Some(key);
            }
        }
        let aes_key = match self.aes_key.read().await.clone() {
            Some(key) => key,
            None => return Vec::new(),
        };

        let mut matched = Vec::new();
        let mut state = self.state.write().await;
        for blob in &poll.data {
            let Ok(plain) = decrypt_message(&aes_key, blob) else {
                continue;
            };
            let Ok(interaction) = serde_json::from_slice::<Interaction>(&plain) else {
                continue;
            };

            match state.requests.remove(&interaction.unique_id) {
                Some(pendings) => matched.push((interaction, pendings)),
                None => {
                    state
                        .early_interactions
                        .entry(interaction.unique_id.clone())
                        .or_default()
                        .push(interaction);
                }
            }
        }
        matched
    }

    /// Background poller: emits findings via `finding_tx` as interactions
    /// correlate with pending requests. Stops when `stop_rx` flips to true.
    pub async fn poll_loop(
        self: Arc<Self>,
        finding_tx: mpsc::Sender<ScanFinding>,
        mut stop_rx: watch::Receiver<bool>,
        poll_interval_secs: u64,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
            }

            let _ = self.ensure_registered().await;
            for (interaction, pendings) in self.poll_once().await {
                for pending in pendings {
                    if let Some(finding) = evaluate_interaction(&pending, &interaction) {
                        let _ = finding_tx.send(finding).await;
                    }
                }
            }
        }
    }

    fn decrypt_aes_key(&self, encrypted_b64: &str) -> Result<Vec<u8>, String> {
        let encrypted = general_purpose::STANDARD
            .decode(encrypted_b64)
            .map_err(|e| e.to_string())?;
        let padding = Oaep::new::<Sha256>();
        self.private_key
            .decrypt(padding, &encrypted)
            .map_err(|e| e.to_string())
    }

    fn normalize_server(server: &str) -> Result<(String, String), String> {
        let explicit_http = server.starts_with("http://");
        let with_scheme = if server.starts_with("http://") || server.starts_with("https://") {
            server.to_string()
        } else {
            format!("https://{}", server)
        };
        let parsed = url::Url::parse(&with_scheme)
            .map_err(|_| format!("invalid interactsh server: {}", server))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("invalid interactsh server: {}", server))?
            .to_string();
        let authority = match parsed.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.clone(),
        };
        let scheme = if explicit_http { "http" } else { "https" };
        Ok((format!("{}://{}", scheme, authority), host))
    }
}

/// Evaluate a pending request's matchers against an arrived interaction and
/// produce a finding when they match. Interactsh parts are populated from the
/// interaction; response parts from the saved HTTP response context.
pub fn evaluate_interaction(
    pending: &PendingRequest,
    interaction: &Interaction,
) -> Option<ScanFinding> {
    let eval = EvaluatedResponse {
        status: pending.status,
        headers: &pending.headers,
        body: &pending.body,
        interactsh_protocol: Some(&interaction.protocol),
        interactsh_request: Some(&interaction.raw_request),
        interactsh_response: Some(&interaction.raw_response),
        named_parts: None,
    };

    if !MatcherEngine::evaluate_all(&pending.matchers, &pending.matchers_condition, &eval) {
        return None;
    }

    Some(ScanFinding {
        template_id: pending.template_id.clone(),
        template_name: pending.template_name.clone(),
        severity: pending.severity.clone(),
        matched_url: pending.matched_url.clone(),
        matched_at: chrono::Utc::now().to_rfc3339(),
        extracted_results: extract_interactsh_output(&pending.extractors, &eval, interaction),
        protocol: "http".to_string(),
        matcher_name: None,
        tags: pending.tags.clone(),
    })
}

/// Run non-internal extractors over the interaction parts. Supports regex and
/// simple word extraction over interactsh_protocol/request/response and the
/// saved response body/headers.
fn extract_interactsh_output(
    extractors: &[TemplateExtractor],
    eval: &EvaluatedResponse,
    interaction: &Interaction,
) -> Vec<String> {
    let mut results = Vec::new();

    for ext in extractors {
        if ext.internal {
            continue;
        }
        let part = ext.part.as_deref().unwrap_or("interactsh_request");
        let content = match part {
            "interactsh_protocol" => interaction.protocol.as_str(),
            "interactsh_request" => interaction.raw_request.as_str(),
            "interactsh_response" => interaction.raw_response.as_str(),
            "header" | "all_headers" => eval.headers,
            "body" => eval.body,
            _ => eval.body,
        };

        match ext.extractor_type.as_str() {
            "regex" => {
                for pattern in &ext.regex {
                    let Ok(re) = regex::Regex::new(pattern) else {
                        continue;
                    };
                    if let Some(caps) = re.captures(content) {
                        let group = ext.regex_group.unwrap_or(0);
                        if let Some(m) = caps.get(group).or_else(|| caps.get(0)) {
                            results.push(m.as_str().to_string());
                        }
                    }
                }
            }
            "kval" => {
                for key in &ext.kval {
                    for line in content.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case(key.trim()) {
                                results.push(v.trim().to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    results
}

/// Decrypt one poll `data` entry: base64 → AES-CTR with prefixed 16-byte IV.
fn decrypt_message(key: &[u8], secure_message: &str) -> Result<Vec<u8>, String> {
    let mut cipher_text = general_purpose::STANDARD
        .decode(secure_message)
        .map_err(|e| e.to_string())?;
    if cipher_text.len() < 16 {
        return Err("ciphertext shorter than IV".to_string());
    }

    let iv: [u8; 16] = cipher_text[..16].try_into().unwrap();
    let mut out = cipher_text.split_off(16);

    match key.len() {
        32 => {
            let mut stream = Aes256Ctr::new_from_slices(key, &iv).map_err(|e| e.to_string())?;
            stream.apply_keystream(&mut out);
        }
        16 => {
            let mut stream = Aes128Ctr::new_from_slices(key, &iv).map_err(|e| e.to_string())?;
            stream.apply_keystream(&mut out);
        }
        n => return Err(format!("unsupported AES key length: {}", n)),
    }
    Ok(out)
}

/// Random lowercase-alphanumeric string (correlation ID / secret key).
fn random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// z-base-32 encoded random nonce for correlation URLs.
fn zbase32_nonce(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ZBASE32_ALPHABET[rng.gen_range(0..32)] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_generation_format() {
        let correlation_id = "abcdefghij1234567890";
        let nonce = zbase32_nonce(NONCE_LEN);
        let url = format!("{}{}.{}", correlation_id, nonce, "oast.pro");
        assert!(url.ends_with(".oast.pro"));
        assert!(url.starts_with(correlation_id));
        assert_eq!(
            InteractshClient::correlation_key(&url),
            format!("{}{}", correlation_id, nonce)
        );
    }

    #[test]
    fn test_correlation_key() {
        assert_eq!(
            InteractshClient::correlation_key("abc123xyz.oast.pro"),
            "abc123xyz"
        );
    }

    #[test]
    fn test_decrypt_message_roundtrip() {
        use ctr::cipher::{KeyIvInit, StreamCipher};

        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext = b"hello interactsh";

        let mut buf = plaintext.to_vec();
        let mut stream = Aes256Ctr::new_from_slices(&key, &iv).unwrap();
        stream.apply_keystream(&mut buf);

        let mut cipher_text = iv.to_vec();
        cipher_text.extend_from_slice(&buf);
        let b64 = general_purpose::STANDARD.encode(&cipher_text);

        let decrypted = decrypt_message(&key, &b64).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_normalize_server() {
        assert_eq!(
            InteractshClient::normalize_server("https://oast.pro").unwrap(),
            ("https://oast.pro".to_string(), "oast.pro".to_string())
        );
        assert_eq!(
            InteractshClient::normalize_server("oast.live").unwrap(),
            ("https://oast.live".to_string(), "oast.live".to_string())
        );
        assert_eq!(
            InteractshClient::normalize_server("http://localhost:8080").unwrap(),
            ("http://localhost:8080".to_string(), "localhost".to_string())
        );
    }
}
