use crate::engine::dsl::TemplateDsl;
use crate::engine::variables::VariableResolver;
use crate::models::template::{NetworkBlock, NetworkInput};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct NoVerifyCert;

impl rustls::client::danger::ServerCertVerifier for NoVerifyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Network protocol execution response.
///
/// Field semantics mirror Go nuclei's `responseToDSLMap`
/// (`pkg/protocols/network/operators.go`): `data` is the final read chunk
/// (the default match part), `raw` is the full accumulated transaction.
#[derive(Debug, Clone)]
pub struct NetworkResponse {
    /// Original target input (Go `host` variable).
    pub host: String,
    /// Actual dialed host:port (Go `matched`).
    pub address: String,
    /// Everything written to the connection (Go `request` variable).
    pub request: String,
    /// Final read after all input steps (Go `data`, default match part).
    pub data: String,
    /// All read data combined (Go `raw`).
    pub raw: String,
    /// Named input buffers in read order (`name:` on inputs).
    pub named: Vec<(String, String)>,
    /// Dialed peer IP (Go `ip` variable).
    pub ip: String,
}

impl NetworkResponse {
    /// Go-parity variable map for matchers/extractors.
    pub fn variables(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("data".to_string(), self.data.clone());
        vars.insert("raw".to_string(), self.raw.clone());
        vars.insert("request".to_string(), self.request.clone());
        vars.insert("host".to_string(), self.host.clone());
        vars.insert("matched".to_string(), self.address.clone());
        if !self.ip.is_empty() {
            vars.insert("ip".to_string(), self.ip.clone());
        }
        for (name, value) in &self.named {
            vars.insert(name.clone(), value.clone());
        }
        vars
    }
}

pub struct NetworkClient;

impl NetworkClient {
    /// Execute a network block against a target. `extra_vars` carries
    /// template-level and previously extracted values used to interpolate
    /// addresses and input data (Go renders both through the variable scope).
    pub async fn execute(
        block: &NetworkBlock,
        target: &str,
        extra_vars: &HashMap<String, String>,
        timeout_secs: u64,
    ) -> Result<NetworkResponse, String> {
        let timeout = Duration::from_secs(timeout_secs.max(1));

        // Determine destination host & port. Block hosts are interpolated
        // first (Go: replacer.Replace(address, variables)); {{Hostname}} and
        // friends resolve against the target.
        let host_source = if !block.host.is_empty() {
            interpolate(&block.host[0], target, extra_vars)
        } else {
            target.to_string()
        };
        let (host, port) = parse_host_port(&host_source, block.port.as_deref());

        let addr = format!("{}:{}", host, port);

        let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("Connection timeout to {}", addr))?
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
        let ip = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();

        let mut sent_bytes: Vec<u8> = Vec::new();
        let mut all_reads: Vec<u8> = Vec::new();
        let mut named: Vec<(String, String)> = Vec::new();
        let mut step_vars: HashMap<String, String> = extra_vars.clone();

        // Go always performs a final read after the input steps
        // (`bufferSize` = read-size or 1024, or all available when
        // `read-all` is set); its content is the `data` part.
        let final_chunk;
        if block.tls {
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifyCert))
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));
            let server_name = ServerName::try_from(host.as_str())
                .unwrap_or_else(|_| ServerName::try_from("localhost").unwrap())
                .to_owned();

            let mut tls_stream =
                tokio::time::timeout(timeout, connector.connect(server_name, stream))
                    .await
                    .map_err(|_| format!("TLS handshake timeout to {}", addr))?
                    .map_err(|e| format!("TLS handshake error with {}: {}", addr, e))?;

            Self::run_conversation(
                &mut tls_stream,
                &block.inputs,
                &mut sent_bytes,
                &mut all_reads,
                &mut named,
                &mut step_vars,
                target,
                timeout,
            )
            .await?;

            final_chunk = Self::final_read(&mut tls_stream, block, timeout).await;
        } else {
            let mut stream = stream;
            Self::run_conversation(
                &mut stream,
                &block.inputs,
                &mut sent_bytes,
                &mut all_reads,
                &mut named,
                &mut step_vars,
                target,
                timeout,
            )
            .await?;

            final_chunk = Self::final_read(&mut stream, block, timeout).await;
        }

        let data = String::from_utf8_lossy(&final_chunk).to_string();
        all_reads.extend_from_slice(&final_chunk);
        let raw = String::from_utf8_lossy(&all_reads).to_string();

        Ok(NetworkResponse {
            host: target.to_string(),
            address: addr,
            request: String::from_utf8_lossy(&sent_bytes).to_string(),
            data,
            raw,
            named,
            ip,
        })
    }

    async fn run_conversation<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        stream: &mut S,
        inputs: &[NetworkInput],
        sent_bytes: &mut Vec<u8>,
        all_reads: &mut Vec<u8>,
        named: &mut Vec<(String, String)>,
        step_vars: &mut HashMap<String, String>,
        target: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        if inputs.is_empty() {
            return Ok(());
        }

        for input in inputs {
            // Input data is rendered against the variable scope (named
            // buffers from previous steps included, as in Go).
            let rendered = match &input.data {
                Some(data) => interpolate(data, target, step_vars),
                None => String::new(),
            };
            if !rendered.is_empty() {
                let bytes_to_send = if input.input_type.as_deref() == Some("hex") {
                    hex::decode(rendered.replace(' ', ""))
                        .unwrap_or_else(|_| rendered.as_bytes().to_vec())
                } else {
                    rendered.as_bytes().to_vec()
                };

                tokio::time::timeout(timeout, stream.write_all(&bytes_to_send))
                    .await
                    .map_err(|_| "Write timeout".to_string())?
                    .map_err(|e| format!("Write error: {}", e))?;
                let _ = stream.flush().await;
                sent_bytes.extend_from_slice(&bytes_to_send);
            }

            if let Some(read_len) = input.read {
                let buffer = Self::read_chunk(stream, read_len.max(1), timeout).await;
                let buffer_str = String::from_utf8_lossy(&buffer).to_string();
                all_reads.extend_from_slice(&buffer);
                if let Some(name) = input.name.as_deref() {
                    if !name.is_empty() {
                        named.push((name.to_string(), buffer_str.clone()));
                        step_vars.insert(name.to_string(), buffer_str);
                    }
                }
            }
        }

        Ok(())
    }

    async fn read_chunk<S: AsyncReadExt + Unpin>(
        stream: &mut S,
        len: usize,
        timeout: Duration,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => buf.truncate(n),
            _ => buf.clear(),
        }
        buf
    }

    /// Final read after the input steps. When `read-all` is set, keeps reading
    /// until EOF, error, or the timeout expires; otherwise reads a single
    /// fixed-size chunk (Go `read-size`, default 1024).
    async fn final_read<S: AsyncReadExt + Unpin>(
        stream: &mut S,
        block: &NetworkBlock,
        timeout: Duration,
    ) -> Vec<u8> {
        if block.read_all {
            let mut all = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => all.extend_from_slice(&buf[..n]),
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
            all
        } else {
            let final_size = block.read_size.unwrap_or(1024).max(1);
            Self::read_chunk(stream, final_size, timeout).await
        }
    }
}

/// Interpolate a network protocol field: URL-derived variables resolve first
/// (when the target is a URL), then the supplied variable map covers
/// {{Hostname}}-style placeholders for bare host:port targets.
fn interpolate(input: &str, target: &str, vars: &HashMap<String, String>) -> String {
    let mut merged = vars.clone();
    if !merged.contains_key("Hostname") {
        let resolved = VariableResolver::resolve("{{Hostname}}", target);
        if !resolved.contains("{{") {
            merged.insert("Hostname".to_string(), resolved);
        }
    }
    TemplateDsl::interpolate(input, target, &merged)
}

fn parse_host_port(host_str: &str, default_port: Option<&str>) -> (String, u16) {
    let clean = host_str
        .trim_start_matches("tcp://")
        .trim_start_matches("udp://")
        .trim_start_matches("tls://")
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    if let Some(idx) = clean.rfind(':') {
        let host = clean[..idx].to_string();
        let port = clean[idx + 1..].parse::<u16>().unwrap_or(80);
        (host, port)
    } else {
        let port = default_port.and_then(|p| p.parse().ok()).unwrap_or(80);
        (clean.to_string(), port)
    }
}
