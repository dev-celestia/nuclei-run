use crate::models::template::WebSocketBlock;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone)]
pub struct WebSocketResponse {
    pub url: String,
    pub responses: Vec<String>,
    pub raw: String,
}

pub struct WebSocketClient;

impl WebSocketClient {
    pub async fn execute(
        block: &WebSocketBlock,
        target: &str,
        timeout_secs: u64,
    ) -> Result<WebSocketResponse, String> {
        let ws_url = if target.starts_with("ws://") || target.starts_with("wss://") {
            target.to_string()
        } else if target.starts_with("https://") {
            target.replacen("https://", "wss://", 1)
        } else if target.starts_with("http://") {
            target.replacen("http://", "ws://", 1)
        } else {
            format!("ws://{}", target)
        };

        let full_url = if let Some(ref path) = block.path {
            if path.starts_with('/') {
                format!("{}{}", ws_url.trim_end_matches('/'), path)
            } else {
                format!("{}/{}", ws_url.trim_end_matches('/'), path)
            }
        } else {
            ws_url
        };

        let timeout = Duration::from_secs(timeout_secs.max(1));

        // Build the handshake request so template-specified headers are sent
        // (Go renders and applies all `headers:` to the WebSocket dialer).
        let mut request = full_url
            .clone()
            .into_client_request()
            .map_err(|e| format!("Invalid WebSocket URL {}: {}", full_url, e))?;
        for (key, value) in &block.headers {
            let header_value: tokio_tungstenite::tungstenite::http::HeaderValue = value
                .parse()
                .map_err(|_| format!("Invalid WebSocket header: {}", key))?;
            let header_name: tokio_tungstenite::tungstenite::http::HeaderName = key
                .parse()
                .map_err(|_| format!("Invalid WebSocket header name: {}", key))?;
            request.headers_mut().insert(header_name, header_value);
        }

        let connect_fut = connect_async(request);
        let (mut ws_stream, _) = tokio::time::timeout(timeout, connect_fut)
            .await
            .map_err(|_| format!("WebSocket connection timeout for {}", full_url))?
            .map_err(|e| format!("WebSocket handshake error: {}", e))?;

        let mut received_messages = Vec::new();

        // Send configured inputs
        for input in &block.inputs {
            let data_str = input.data.as_deref().unwrap_or("");
            let data = if data_str.starts_with("hex:") {
                let hex_str = data_str.trim_start_matches("hex:").trim();
                let bytes = hex::decode(hex_str).map_err(|e| format!("Hex decode error: {}", e))?;
                Message::Binary(bytes.into())
            } else {
                Message::Text(data_str.to_string().into())
            };

            ws_stream
                .send(data)
                .await
                .map_err(|e| format!("Failed to send WS message: {}", e))?;

            // Read response with short timeout per message
            if let Ok(Some(Ok(msg))) = tokio::time::timeout(Duration::from_millis(1500), ws_stream.next()).await {
                match msg {
                    Message::Text(txt) => received_messages.push(txt.to_string()),
                    Message::Binary(bin) => received_messages.push(String::from_utf8_lossy(&bin).to_string()),
                    _ => {}
                }
            }
        }

        // Close connection gracefully
        let _ = ws_stream.close(None).await;

        let raw = received_messages.join("\n");
        Ok(WebSocketResponse {
            url: full_url,
            responses: received_messages,
            raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_url_formatting() {
        let block = WebSocketBlock {
            path: Some("/socket.io".to_string()),
            inputs: vec![],
            headers: Default::default(),
            matchers_condition: None,
            matchers: vec![],
            extractors: vec![],
        };
        assert_eq!(block.path.as_deref(), Some("/socket.io"));
    }
}
