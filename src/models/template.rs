use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Top-level Nuclei Template Schema
// ---------------------------------------------------------------------------

/// Root template structure compatible with Nuclei v2/v3 YAML specifications.
/// Handles modern `http:`, legacy `requests:`, `dns:`, `network:`/`tcp:`, `ssl:`,
/// `whois:`, `file:`, `code:`, `fuzzing:`, and `flow:`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiTemplate {
    pub id: String,
    pub info: TemplateInfo,

    /// HTTP request blocks. Supports both `http:` (modern) and `requests:` (legacy).
    #[serde(default, alias = "requests")]
    pub http: Vec<HttpBlock>,

    /// DNS request blocks.
    #[serde(default)]
    pub dns: Vec<DnsBlock>,

    /// Network / TCP / UDP socket blocks.
    #[serde(default, alias = "tcp")]
    pub network: Vec<NetworkBlock>,

    /// SSL / TLS inspection blocks.
    #[serde(default)]
    pub ssl: Vec<SslBlock>,

    /// WHOIS query blocks.
    #[serde(default)]
    pub whois: Vec<WhoisBlock>,

    /// Local file inspection blocks.
    #[serde(default)]
    pub file: Vec<FileBlock>,

    /// Code execution blocks.
    #[serde(default)]
    pub code: Vec<CodeBlock>,

    /// WebSocket protocol blocks.
    #[serde(default, alias = "ws")]
    pub websocket: Vec<WebSocketBlock>,

    /// Headless browser blocks.
    #[serde(default)]
    pub headless: Vec<HeadlessBlock>,

    /// JavaScript execution blocks.
    #[serde(default, alias = "js")]
    pub javascript: Vec<JavaScriptBlock>,

    /// Parameter fuzzing blocks.
    #[serde(default)]
    pub fuzzing: Vec<FuzzingBlock>,

    /// Flow control expression (Nuclei v3+).
    #[serde(default)]
    pub flow: Option<String>,

    /// Cryptographic template signature (Ed25519/ECDSA).
    #[serde(default, rename = "digest")]
    pub signature: Option<String>,

    /// Self-contained template (doesn't require target input).
    #[serde(default, rename = "self-contained")]
    pub self_contained: bool,

    /// Template-level variables for substitution.
    #[serde(default)]
    pub variables: HashMap<String, serde_yaml::Value>,

    /// Template-level constants for substitution.
    #[serde(default)]
    pub constants: HashMap<String, serde_yaml::Value>,
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
    #[allow(dead_code)]
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

    /// Whether to follow only redirects to the same host (`host-redirects`).
    #[serde(default, rename = "host-redirects")]
    pub host_redirects: Option<bool>,

    /// Disable cookie reuse (cookie jar) for this request block.
    #[serde(default, rename = "disable-cookie")]
    pub disable_cookie: Option<bool>,

    /// Block-level self-contained marker (request runs without target input).
    #[serde(default, rename = "self-contained")]
    pub self_contained: bool,

    /// Cookie reuse across requests within this block. Deprecated upstream:
    /// cookie reuse is now the default; `disable-cookie` is the switch.
    #[serde(default, rename = "cookie-reuse")]
    pub cookie_reuse: Option<bool>,

    /// Race condition testing.
    #[serde(default)]
    pub race: bool,

    /// Number of concurrent requests for race condition.
    #[serde(default, rename = "race_number")]
    pub race_number: Option<usize>,
}

// ---------------------------------------------------------------------------
// DNS Protocol Block (`dns:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBlock {
    /// Domain name to query (e.g. `{{FQDN}}`).
    #[serde(default)]
    pub name: Option<String>,

    /// DNS record query type: A, AAAA, CNAME, NS, TXT, MX, PTR, SOA, SRV, CAA, AXFR.
    #[serde(default, rename = "type")]
    pub query_type: Option<String>,

    /// Custom recursive resolvers (e.g. `["1.1.1.1:53", "8.8.8.8:53"]`).
    #[serde(default)]
    pub resolvers: Vec<String>,

    /// Trace / recursion. Go defaults to recursion desired = true when the
    /// field is absent; `recursion: false` disables it.
    #[serde(default)]
    pub recursion: Option<bool>,

    /// Number of retries on timeout.
    #[serde(default)]
    pub retries: Option<usize>,

    /// Matchers condition ("and" or "or").
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers for DNS responses.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors for DNS responses.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// Network / TCP Protocol Block (`network:` / `tcp:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlock {
    /// Host to connect to (e.g. `{{Hostname}}:8080` or `tcp://{{Host}}:{{Port}}`).
    #[serde(default)]
    pub host: Vec<String>,

    /// Port list.
    #[serde(default)]
    pub port: Option<String>,

    /// TLS over TCP socket.
    #[serde(default)]
    pub tls: bool,

    /// Conversation input steps.
    #[serde(default)]
    pub inputs: Vec<NetworkInput>,

    /// Expected read size in bytes.
    #[serde(default, rename = "read-size")]
    pub read_size: Option<usize>,

    /// Matchers condition ("and" or "or").
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInput {
    /// Optional name: the read buffer becomes a variable under this name
    /// (Go nuclei named input support).
    #[serde(default)]
    pub name: Option<String>,

    /// Data string to send.
    #[serde(default)]
    pub data: Option<String>,

    /// Input type: "hex" or "text".
    #[serde(default, rename = "type")]
    pub input_type: Option<String>,

    /// Number of bytes to read after sending.
    #[serde(default)]
    pub read: Option<usize>,
}

// ---------------------------------------------------------------------------
// SSL / TLS Protocol Block (`ssl:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslBlock {
    /// Address to inspect (e.g. `{{Host}}:{{Port}}`).
    #[serde(default)]
    pub address: Option<String>,

    /// Minimum TLS version.
    #[serde(default, rename = "min-version")]
    pub min_version: Option<String>,

    /// Maximum TLS version.
    #[serde(default, rename = "max-version")]
    pub max_version: Option<String>,

    /// Cipher suites to test.
    #[serde(default, rename = "cipher-suites")]
    pub cipher_suites: Vec<String>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// WHOIS Protocol Block (`whois:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisBlock {
    /// Query domain/IP.
    #[serde(default)]
    pub query: Option<String>,

    /// Custom WHOIS server.
    #[serde(default)]
    pub server: Option<String>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// Local File Protocol Block (`file:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBlock {
    /// File paths or globs to scan.
    #[serde(default)]
    pub extensions: Vec<String>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// Code Execution Protocol Block (`code:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlock {
    /// Engine / Interpreter: "sh", "bash", "python3", "powershell", "cmd".
    /// Templates use both `engine: python` and `engine: [python]` forms.
    #[serde(default, rename = "engine", deserialize_with = "string_or_seq")]
    pub engine: Vec<String>,

    /// Source code / script content.
    #[serde(default)]
    pub source: Option<String>,

    /// Arguments to pass to script.
    #[serde(default)]
    pub args: Vec<String>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

/// Accept either a scalar string or a sequence of strings, returning a Vec.
/// Nuclei templates use both forms for fields like `engine:`.
fn string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => Ok(vec![s]),
        OneOrMany::Many(v) => Ok(v),
    }
}

// ---------------------------------------------------------------------------
// WebSocket Protocol Block (`websocket:` / `ws:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketBlock {
    /// WebSocket path or relative URL.
    #[serde(default)]
    pub path: Option<String>,

    /// Inputs / messages to send over WebSocket.
    #[serde(default)]
    pub inputs: Vec<NetworkInput>,

    /// Custom headers for WebSocket handshake.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Matchers condition: "and" | "or".
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// Headless Browser Protocol Block (`headless:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessBlock {
    /// Steps / actions to execute in headless browser.
    #[serde(default)]
    pub steps: Vec<HeadlessStep>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessStep {
    /// Action: "navigate", "click", "type", "text", "wait-for", "waitload", "script", "screenshot", "setheader", "extract", "keyboard", "select", "sleep".
    #[serde(default, rename = "action")]
    pub action: String,

    /// Name of this step's result (a named matcher part, e.g. `name: extract`).
    #[serde(default)]
    pub name: Option<String>,

    /// Target URL or CSS selector.
    #[serde(default, alias = "by", alias = "selector")]
    pub target: Option<String>,

    /// Script source for action: "script".
    #[serde(default, rename = "code", alias = "script", alias = "source")]
    pub code: Option<String>,

    /// Key/Value pairs for form typing or headers.
    #[serde(default)]
    pub key: Option<String>,

    #[serde(default)]
    pub value: Option<String>,

    /// Custom headers for action: "setheader".
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Attribute name to extract for action: "extract" (e.g. "href", "src", "value").
    #[serde(default)]
    pub attribute: Option<String>,

    /// Extra arguments (nuclei defines these as a string map,
    /// e.g. `args: {url: "..."}` for the navigate action).
    #[serde(default)]
    pub args: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// JavaScript Execution Protocol Block (`javascript:` / `js:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptBlock {
    /// JavaScript code / script content.
    #[serde(default, alias = "source")]
    pub code: Option<String>,

    /// Pre-condition expression; when falsy, the block is skipped.
    #[serde(default, rename = "pre-condition")]
    pub pre_condition: Option<String>,

    /// Arguments injected into the JS runtime as globals.
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// Parameter Fuzzing Block (`fuzzing:`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingBlock {
    /// Target components to fuzz: "query", "headers", "cookie", "body", "path".
    #[serde(default)]
    pub part: Option<String>,

    /// Attack type: "sniper", "pitchfork", "clusterbomb".
    #[serde(default, rename = "type")]
    pub attack_type: Option<String>,

    /// Injection mode: "replace", "prefix", "postfix", "infix".
    #[serde(default)]
    pub mode: Option<String>,

    /// Keys / parameter names to fuzz.
    #[serde(default)]
    pub keys: Vec<String>,

    /// Payloads list or map.
    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,

    /// Matchers condition.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,

    /// Matchers.
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,

    /// Extractors.
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
}

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMatcher {
    /// Matcher type: "word", "regex", "status", "binary", "dsl", "size", "xpath", "time".
    #[serde(rename = "type")]
    pub matcher_type: String,

    /// Response part to match against: "body", "header", "all_headers", "response", "status", "raw", "interactsh_protocol", "interactsh_request", "interactsh_response".
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

    /// Size in bytes to match.
    #[serde(default)]
    pub size: Vec<usize>,

    /// XPath expressions for XML / HTML matching.
    #[serde(default)]
    pub xpath: Vec<String>,

    /// Response time in seconds/ms.
    #[serde(default)]
    pub time: Vec<u64>,

    /// Logical condition within this matcher's patterns: "and" or "or".
    #[serde(default)]
    pub condition: Option<String>,

    /// Negate the match result.
    #[serde(default)]
    pub negative: bool,

    /// Case-insensitive matching for word/regex.
    #[serde(default, rename = "case-insensitive")]
    pub case_insensitive: bool,

    /// Encoding to apply before matching (e.g. "hex").
    #[serde(default)]
    pub encoding: Option<String>,

    /// Name identifier for internal reference.
    #[serde(default)]
    pub name: Option<String>,

    /// When true, matcher is evaluated for internal flow control / prerequisites
    /// and does not emit a finding on its own.
    #[serde(default, rename = "internal")]
    pub internal: bool,
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

    /// XPath expressions.
    #[serde(default)]
    pub xpath: Vec<String>,

    /// HTML attribute to extract for XPath (e.g. "href", "value").
    #[serde(default)]
    pub attribute: Option<String>,

    /// DSL expressions for extraction.
    #[serde(default)]
    pub dsl: Vec<String>,

    /// When true, extracted value is stored for chaining but not outputted.
    #[serde(default, rename = "internal")]
    pub internal: bool,
}
