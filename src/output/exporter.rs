use crate::models::result::ScanFinding;
use reqwest::Client;
use std::time::Duration;

/// Exporter destinations for automated findings ingestion.
#[derive(Debug, Clone)]
pub enum ExporterTarget {
    Elasticsearch { url: String, index: String },
    SplunkHec { url: String, token: String },
    Webhook { url: String },
}

pub struct RemoteExporter {
    client: Client,
}

impl RemoteExporter {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Export a finding to a remote SIEM or Webhook receiver.
    pub async fn export(&self, finding: &ScanFinding, target: &ExporterTarget) -> Result<(), String> {
        let payload = serde_json::to_string(finding).map_err(|e| e.to_string())?;

        match target {
            ExporterTarget::Elasticsearch { url, index } => {
                let endpoint = format!("{}/{}/_doc", url.trim_end_matches('/'), index);
                let res = self.client.post(&endpoint)
                    .header("Content-Type", "application/json")
                    .body(payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !res.status().is_success() {
                    return Err(format!("Elasticsearch error status: {}", res.status()));
                }
            }
            ExporterTarget::SplunkHec { url, token } => {
                let endpoint = format!("{}/services/collector/event", url.trim_end_matches('/'));
                let splunk_payload = serde_json::json!({
                    "event": finding,
                    "sourcetype": "nuclei:finding"
                });
                let res = self.client.post(&endpoint)
                    .header("Authorization", format!("Splunk {}", token))
                    .json(&splunk_payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !res.status().is_success() {
                    return Err(format!("Splunk error status: {}", res.status()));
                }
            }
            ExporterTarget::Webhook { url } => {
                let res = self.client.post(url)
                    .header("Content-Type", "application/json")
                    .body(payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !res.status().is_success() {
                    return Err(format!("Webhook error status: {}", res.status()));
                }
            }
        }

        Ok(())
    }
}
