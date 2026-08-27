use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// An out-of-band interaction event recorded by the Interactsh server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionEvent {
    pub protocol: String,
    pub unique_id: String,
    pub raw_request: String,
    pub raw_response: String,
    pub remote_address: String,
    pub timestamp: String,
}

/// Interactsh OOB correlation engine.
#[derive(Clone)]
pub struct InteractshClient {
    server_url: String,
    session_id: String,
    correlation_cache: Arc<RwLock<HashMap<String, Vec<InteractionEvent>>>>,
}

impl InteractshClient {
    pub fn new(server_url: Option<&str>) -> Self {
        let rand_session: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        Self {
            server_url: server_url.unwrap_or("oast.pro").to_string(),
            session_id: rand_session.to_lowercase(),
            correlation_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate dynamic correlation URL for template injection (e.g. `c7s9812a.oast.pro`).
    pub fn generate_url(&self) -> String {
        let nonce: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        format!("{}.{}.{}", nonce.to_lowercase(), self.session_id, self.server_url)
    }

    /// Check if an interaction occurred for a given correlation ID.
    pub async fn poll_interactions(&self, correlation_id: &str) -> Vec<InteractionEvent> {
        let cache = self.correlation_cache.read().await;
        cache.get(correlation_id).cloned().unwrap_or_default()
    }

    /// Record an interaction into cache.
    pub async fn record_interaction(&self, event: InteractionEvent) {
        let mut cache = self.correlation_cache.write().await;
        cache.entry(event.unique_id.clone()).or_default().push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interactsh_url_generation() {
        let client = InteractshClient::new(Some("oast.pro"));
        let url = client.generate_url();
        assert!(url.ends_with(".oast.pro"));
        assert!(url.contains(&client.session_id));
    }
}
