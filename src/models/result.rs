use serde::{Deserialize, Serialize};

/// A single vulnerability finding emitted by the scan engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    /// Template ID (e.g., "CVE-2023-12345").
    pub template_id: String,

    /// Human-readable template name.
    pub template_name: String,

    /// Severity level as string (info, low, medium, high, critical).
    pub severity: String,

    /// The URL that matched.
    pub matched_url: String,

    /// ISO 8601 timestamp of when the finding was discovered.
    pub matched_at: String,

    /// Values extracted by extractors.
    #[serde(default)]
    pub extracted_results: Vec<String>,

    /// Protocol type (http, dns, etc.).
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// The matcher name that triggered the finding (if named).
    #[serde(default)]
    pub matcher_name: Option<String>,

    /// Template tags for categorization.
    #[serde(default)]
    pub tags: Option<String>,
}

fn default_protocol() -> String {
    "http".to_string()
}

/// Aggregated scan summary displayed at completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total HTTP requests sent.
    pub total_requests: usize,

    /// Total vulnerability findings.
    pub total_findings: usize,

    /// Findings broken down by severity.
    pub findings_by_severity: std::collections::HashMap<String, usize>,

    /// Total templates loaded.
    pub templates_loaded: usize,

    /// Total targets scanned.
    pub targets_scanned: usize,

    /// Wall-clock elapsed time in milliseconds.
    pub elapsed_millis: u128,

    /// Average requests per second.
    pub rps: f64,
}
