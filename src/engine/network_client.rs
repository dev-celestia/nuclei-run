use crate::models::template::{NetworkBlock, NetworkInput};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Network protocol execution response.
#[derive(Debug, Clone)]
pub struct NetworkResponse {
    pub host: String,
    #[allow(dead_code)]
    pub raw: String,
    pub body: String,
    #[allow(dead_code)]
    pub duration_ms: u64,
}

pub struct NetworkClient;

impl NetworkClient {
    /// Execute a network block against a target.
    pub async fn execute(
        block: &NetworkBlock,
        target: &str,
        timeout_secs: u64,
    ) -> Result<NetworkResponse, String> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs.max(1));

        // Determine destination host & port
        let (host, port) = if !block.host.is_empty() {
            parse_host_port(&block.host[0], block.port.as_deref())
        } else {
            parse_host_port(target, block.port.as_deref())
        };

        let addr = format!("{}:{}", host, port);

        let mut received_bytes = Vec::new();

        if block.tls {
            // TLS over TCP
            let root_cert_store = rustls::RootCertStore::empty();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));
            let server_name = ServerName::try_from(host.as_str())
                .unwrap_or_else(|_| ServerName::try_from("localhost").unwrap())
                .to_owned();

            let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                .await
                .map_err(|_| format!("Connection timeout to {}", addr))?
                .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

            let mut tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, stream))
                .await
                .map_err(|_| format!("TLS handshake timeout to {}", addr))?
                .map_err(|e| format!("TLS handshake error with {}: {}", addr, e))?;

            // Execute input steps
            Self::interleave_io(&mut tls_stream, &block.inputs, block.read_size, &mut received_bytes, timeout).await?;
        } else {
            // Raw TCP Stream
            let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                .await
                .map_err(|_| format!("Connection timeout to {}", addr))?
                .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

            Self::interleave_io(&mut stream, &block.inputs, block.read_size, &mut received_bytes, timeout).await?;
        }

        let body = String::from_utf8_lossy(&received_bytes).to_string();
        let raw = body.clone();
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(NetworkResponse {
            host: addr,
            raw,
            body,
            duration_ms,
        })
    }

    async fn interleave_io<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        stream: &mut S,
        inputs: &[NetworkInput],
        read_size: Option<usize>,
        output_buffer: &mut Vec<u8>,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut buf = vec![0u8; 4096];

        if inputs.is_empty() {
            // If no inputs specified, read available banner
            let read_limit = read_size.unwrap_or(4096);
            buf.resize(read_limit, 0);
            if let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                if n > 0 {
                    output_buffer.extend_from_slice(&buf[..n]);
                }
            }
            return Ok(());
        }

        for input in inputs {
            if let Some(ref data) = input.data {
                let bytes_to_send = if input.input_type.as_deref() == Some("hex") {
                    hex::decode(data.replace(' ', "")).unwrap_or_else(|_| data.as_bytes().to_vec())
                } else {
                    data.as_bytes().to_vec()
                };

                let _ = tokio::time::timeout(timeout, stream.write_all(&bytes_to_send))
                    .await
                    .map_err(|_| "Write timeout".to_string())?
                    .map_err(|e| format!("Write error: {}", e))?;
                let _ = stream.flush().await;
            }

            if let Some(read_len) = input.read {
                let mut read_buf = vec![0u8; read_len.max(1)];
                if let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut read_buf)).await {
                    if n > 0 {
                        output_buffer.extend_from_slice(&read_buf[..n]);
                    }
                }
            }
        }

        Ok(())
    }
}

fn parse_host_port(host_str: &str, default_port: Option<&str>) -> (String, u16) {
    let clean = host_str
        .trim_start_matches("tcp://")
        .trim_start_matches("udp://")
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
