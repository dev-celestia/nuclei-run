use crate::models::template::{TemplateExtractor, TemplateMatcher};
use std::collections::HashMap;
use std::sync::Arc;

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
pub struct PollResponse {
    #[serde(default)]
    pub data: Vec<String>,
    #[serde(default, rename = "aes_key")]
    pub aes_key: String,
}

#[derive(serde::Serialize)]
pub struct RegisterRequest<'a> {
    #[serde(rename = "public-key")]
    pub public_key: &'a str,
    #[serde(rename = "secret-key")]
    pub secret_key: &'a str,
    #[serde(rename = "correlation-id")]
    pub correlation_id: &'a str,
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

pub struct CorrelationState {
    /// First DNS label of generated URL → pending request contexts.
    pub requests: HashMap<String, Vec<Arc<PendingRequest>>>,
    /// Interactions that arrived before their request was registered.
    pub early_interactions: HashMap<String, Vec<Interaction>>,
}
