/// Runtime configuration derived from CLI arguments.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScanConfig {
    /// Target URLs to scan.
    pub targets: Vec<String>,

    /// Paths to template files or directories.
    pub template_paths: Vec<String>,

    /// Filter: only run templates with these severity levels.
    pub severity_filter: Vec<String>,

    /// Filter: only run templates with these tags.
    pub tag_filter: Vec<String>,

    /// Filter: only run templates with these IDs.
    pub id_filter: Vec<String>,

    /// Number of concurrent workers.
    pub concurrency: usize,

    /// Maximum requests per second (0 = unlimited).
    pub rate_limit_rps: u32,

    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,

    /// Number of retries on failure.
    pub retries: u32,

    /// Maximum redirects to follow.
    pub max_redirects: usize,

    /// Global `-fr`: follow redirects for all http templates.
    pub follow_redirects: bool,

    /// Global `-fhr`: follow only same-host redirects.
    pub follow_host_redirects: bool,

    /// Global `-dr`: disable redirect following entirely.
    pub disable_redirects: bool,

    /// `-esc`: allow loading/executing self-contained templates.
    pub enable_self_contained: bool,

    /// HTTP/SOCKS5 proxy URL.
    pub proxy: Option<String>,

    /// Custom headers to include in all requests.
    pub custom_headers: Vec<(String, String)>,

    /// Output file path (for JSONL/SARIF).
    pub output_path: Option<String>,

    /// Markdown export path.
    pub markdown_export: Option<String>,

    /// Enable code protocol execution.
    pub enable_code_templates: bool,

    /// Enable headless browser protocol execution.
    pub headless: bool,

    /// Uncover OSINT search query.
    pub uncover: bool,
    pub uncover_query: Option<String>,
    pub uncover_engine: Option<String>,

    /// Custom Interactsh server.
    pub interactsh_server: Option<String>,

    /// Maximum consecutive host errors before dropping host (0 = disabled).
    pub max_host_errors: usize,

    /// Detect potential honeypot hosts based on match concentration.
    pub honeypot_detect: bool,

    /// Distinct template IDs required to flag a honeypot host.
    pub honeypot_threshold: usize,

    /// Suppress output for flagged honeypot hosts.
    pub suppress_honeypot: bool,

    /// Cryptographically sign templates with generated/provided key.
    pub sign_templates: bool,

    /// Refuse executing unsigned templates.
    pub disable_unsigned_templates: bool,

    /// Path to the Ed25519 signing key (hex) for signing/verification.
    pub signing_key_path: Option<String>,

    /// Elasticsearch export destination (base URL).
    pub export_elasticsearch: Option<String>,

    /// Elasticsearch index name.
    pub es_index: String,

    /// Splunk HEC export destination (base URL).
    pub export_splunk: Option<String>,

    /// Splunk HEC token.
    pub splunk_token: Option<String>,

    /// Webhook export destination (JSON POST).
    pub export_webhook: Option<String>,

    /// Issue tracker kind: github, gitlab, jira, linear.
    pub tracker: Option<String>,

    /// Tracker project identifier.
    pub tracker_project: Option<String>,

    /// Tracker host URL (Jira host or self-hosted GitLab).
    pub tracker_url: Option<String>,

    /// Deduplicate identical HTTP requests across templates.
    pub cluster_requests: bool,

    /// Enable JSONL output format.
    pub jsonl: bool,

    /// Enable SARIF output format.
    pub sarif: bool,

    /// Silent mode: suppress banner, progress, and summary.
    pub silent: bool,

    /// Force re-download of remote templates (bypass cache).
    pub update_templates: bool,
}
