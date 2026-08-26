use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Top-level Nuclei Template Schema
// ---------------------------------------------------------------------------

/// Root template structure compatible with Nuclei v2/v3 YAML specifications.
/// Handles both modern `http:` and legacy `requests:` keys via serde alias.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiTemplate {
    pub id: String,
    pub info: TemplateInfo,

    /// HTTP request blocks. Supports both `http:` (modern) and `requests:` (legacy).
    #[serde(default, alias = "requests")]
    pub http: Vec<HttpBlock>,

    /// Flow control expression (Nuclei v3+). Skipped if present but not yet supported.
    #[serde(default)]
    pub flow: Option<String>,

    /// Template-level variables for substitution.
    #[serde(default)]
    pub variables: HashMap<String, serde_yaml::Value>,
}

// ---------------------------------------------------------------------------
// Template Metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,

    #[serde(default)]
    pub author: FlexibleStringList,

    /// Severity as a string for tolerant parsing, normalized via `Severity` enum.
    #[serde(default = "default_severity_str")]
    pub severity: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub reference: Option<FlexibleStringList>,

    #[serde(default)]
    pub tags: Option<String>,

    #[serde(default)]
    pub metadata: Option<HashMap<String, serde_yaml::Value>>,

    /// Classification block (CVSSv3, CWE, etc.) — stored but not evaluated.
    #[serde(default)]
    pub classification: Option<HashMap<String, serde_yaml::Value>>,

    /// Remediation guidance.
    #[serde(default)]
    pub remediation: Option<String>,
}

fn default_severity_str() -> String {
    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// Flexible String / List Field
// ---------------------------------------------------------------------------

/// Handles YAML fields that can be a single string or an array of strings.
/// Covers `author`, `reference`, and similar fields across community templates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlexibleStringList {
    Single(String),
    List(Vec<String>),
}

impl Default for FlexibleStringList {
    fn default() -> Self {
        FlexibleStringList::Single(String::new())
    }
}

impl FlexibleStringList {
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            FlexibleStringList::Single(s) => {
                if s.is_empty() {
                    vec![]
                } else {
                    s.split(',').map(|s| s.trim().to_string()).collect()
                }
            }
            FlexibleStringList::List(v) => v.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Severity Enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    /// Parse a severity string tolerantly (case-insensitive).
    pub fn from_str_tolerant(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Unknown,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
            Severity::Unknown => "unknown",
        };
        write!(f, "{}", label)
    }
}

// ---------------------------------------------------------------------------
// HTTP Request Block
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlock {
    /// HTTP method (GET, POST, etc.). Optional for raw requests.
    #[serde(default)]
    pub method: Option<String>,

    /// Standard path-based requests with variable placeholders.
    #[serde(default)]
    pub path: Vec<String>,

    /// Raw HTTP packet requests (for smuggling, CRLF injection, etc.).
    #[serde(default)]
    pub raw: Vec<String>,

    /// Custom HTTP headers to send with the request.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request body content.
    #[serde(default)]
    pub body: Option<String>,

    /// Logical condition between matchers: "and" or "or".
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// List of matchers to evaluate against the response.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// List of extractors to pull data from the response.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,

    /// Stop processing subsequent paths after the first match.
    #[serde(default, rename = "stop-at-first-match")]
    pub stop_at_first_match: bool,

    /// Maximum number of redirects to follow for this request block.
    #[serde(default, rename = "max-redirects")]
    pub max_redirects: Option<usize>,

    /// Whether to follow redirects (default: true in most templates).
    #[serde(default)]
    pub redirects: Option<bool>,

    /// Cookie reuse across requests within this block.
    #[serde(default, rename = "cookie-reuse")]
    pub cookie_reuse: Option<bool>,
}

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMatcher {
    /// Matcher type: "word", "regex", "status", "binary", "dsl".
    #[serde(rename = "type")]
    pub matcher_type: String,

    /// Response part to match against: "body", "header", "all_headers", "response", "status".
    #[serde(default)]
    pub part: Option<String>,

    /// Word patterns for substring matching.
    #[serde(default)]
    pub words: Vec<String>,

    /// Regex patterns for pattern matching.
    #[serde(default)]
    pub regex: Vec<String>,

    /// HTTP status codes to match.
    #[serde(default)]
    pub status: Vec<u16>,

    /// DSL expressions for complex logical matching.
    #[serde(default)]
    pub dsl: Vec<String>,

    /// Binary hex patterns for byte-sequence matching.
    #[serde(default)]
    pub binary: Vec<String>,

    /// Logical condition within this matcher's patterns: "and" or "or".
    #[serde(default)]
    pub condition: Option<String>,

    /// Negate the match result.
    #[serde(default)]
    pub negative: bool,

    /// Case-insensitive matching for word/regex.
    #[serde(default, rename = "case-insensitive")]
    pub case_insensitive: bool,

    /// Encoding to apply before matching.
    #[serde(default)]
    pub encoding: Option<String>,

    /// Name identifier for internal reference.
    #[serde(default)]
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Extractor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateExtractor {
    /// Extractor type: "regex", "kval", "json", "xpath", "dsl".
    #[serde(rename = "type")]
    pub extractor_type: String,

    /// Name of the extracted variable (used in chaining).
    pub name: Option<String>,

    /// Response part to extract from: "body", "header", "all_headers", "response".
    #[serde(default)]
    pub part: Option<String>,

    /// Regex patterns for extraction.
    #[serde(default)]
    pub regex: Vec<String>,

    /// Regex capture group index (default: 0 = full match).
    #[serde(default, rename = "group")]
    pub regex_group: Option<usize>,

    /// Key-value extraction from headers/cookies.
    #[serde(default)]
    pub kval: Vec<String>,

    /// JSON path expressions.
    #[serde(default)]
    pub json: Vec<String>,

    /// When true, extracted value is stored for chaining but not outputted.
    #[serde(default, rename = "internal")]
    pub internal: bool,
}
