use crate::models::template::WhoisBlock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct WhoisResponse {
    pub query: String,
    pub raw: String,
}

pub struct WhoisClient;

impl WhoisClient {
    pub async fn execute(
        block: &WhoisBlock,
        target: &str,
        timeout_secs: u64,
    ) -> Result<WhoisResponse, String> {
        let query = block
            .query
            .as_deref()
            .unwrap_or(target)
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .split(':')
            .next()
            .unwrap_or(target);

        let whois_server = block.server.as_deref().unwrap_or("whois.iana.org");
        let server_addr = format!("{}:43", whois_server);
        let timeout = Duration::from_secs(timeout_secs.max(1));

        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| format!("WHOIS timeout to {}", server_addr))?
            .map_err(|e| format!("WHOIS connect error to {}: {}", server_addr, e))?;

        let query_bytes = format!("{}\r\n", query);
        stream.write_all(query_bytes.as_bytes()).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut response_bytes = Vec::new();
        let _ = tokio::time::timeout(timeout, stream.read_to_end(&mut response_bytes)).await;

        let raw = String::from_utf8_lossy(&response_bytes).to_string();
        Ok(WhoisResponse {
            query: query.to_string(),
            raw,
        })
    }
}
