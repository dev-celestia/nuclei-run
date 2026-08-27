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

    /// HTTP/SOCKS5 proxy URL.
    pub proxy: Option<String>,

    /// Custom headers to include in all requests.
    pub custom_headers: Vec<(String, String)>,

    /// Output file path (for JSONL/SARIF).
    pub output_path: Option<String>,

    /// Enable JSONL output format.
    pub jsonl: bool,

    /// Enable SARIF output format.
    pub sarif: bool,

    /// Silent mode: suppress banner, progress, and summary.
    pub silent: bool,

    /// Force re-download of remote templates (bypass cache).
    pub update_templates: bool,
}
