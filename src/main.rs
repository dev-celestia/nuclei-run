mod config;
mod models;
mod parser;
mod engine;
mod output;
mod ui_bridge;

use clap::Parser;
use config::ScanConfig;
use engine::runner::{EngineRunner, ScanTask};
use models::result::ScanSummary;
use output::jsonl::JsonlWriter;
use output::sarif::SarifReporter;
use parser::yaml_loader::{self, TemplateFilter};
use std::collections::HashMap;
use std::sync::Arc;

/// nuclei-run: High-performance Nuclei-compatible vulnerability scanner
#[derive(Parser, Debug)]
#[command(name = "nuclei-run", version, about = "High-performance Nuclei-compatible vulnerability scanner")]
struct Cli {
    /// Target URL to scan
    #[arg(short = 'u', long = "url")]
    url: Option<String>,

    /// File containing list of target URLs (one per line)
    #[arg(short = 'l', long = "list")]
    list: Option<String>,

    /// Path to template file or directory
    #[arg(short = 't', long = "templates", required = true)]
    templates: Vec<String>,

    /// Filter by severity (comma-separated: info,low,medium,high,critical)
    #[arg(long = "severity", short = 's', value_delimiter = ',')]
    severity: Option<Vec<String>>,

    /// Filter by template tags (comma-separated)
    #[arg(long = "tags", value_delimiter = ',')]
    tags: Option<Vec<String>>,

    /// Filter by template IDs (comma-separated)
    #[arg(long = "id", value_delimiter = ',')]
    id: Option<Vec<String>>,

    /// Number of concurrent workers
    #[arg(short = 'c', long = "concurrency", default_value = "25")]
    concurrency: usize,

    /// Maximum requests per second (0 = unlimited)
    #[arg(long = "rate-limit", short = 'r', default_value = "150")]
    rate_limit: u32,

    /// HTTP request timeout in seconds
    #[arg(long = "timeout", default_value = "10")]
    timeout: u64,

    /// Number of retries on failure
    #[arg(long = "retries", default_value = "1")]
    retries: u32,

    /// Maximum redirects to follow
    #[arg(long = "max-redirects", alias = "mr", default_value = "10")]
    max_redirects: usize,

    /// Enable following redirects for http templates
    #[arg(long = "follow-redirects", alias = "fr")]
    follow_redirects: bool,

    /// Follow redirects on the same host only
    #[arg(long = "follow-host-redirects", alias = "fhr")]
    follow_host_redirects: bool,

    /// Disable redirects for http templates (overrides template settings)
    #[arg(long = "disable-redirects", alias = "dr")]
    disable_redirects: bool,

    /// Enable loading self-contained templates
    #[arg(long = "enable-self-contained", alias = "esc")]
    enable_self_contained: bool,

    /// HTTP/SOCKS5 proxy URL
    #[arg(long = "proxy")]
    proxy: Option<String>,

    /// Custom headers (format: "Key: Value", repeatable)
    #[arg(short = 'H', long = "header")]
    header: Option<Vec<String>>,

    /// Output file path
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Export scan results to Markdown report file
    #[arg(short = 'm', long = "markdown-export")]
    pub markdown_export: Option<String>,

    /// Enable local code execution protocol templates
    #[arg(long = "enable-code-templates")]
    pub enable_code_templates: bool,

    /// Enable headless browser protocol execution (requires Chrome/Chromium)
    #[arg(long = "headless")]
    pub headless: bool,

    /// Discover targets via Uncover OSINT engines
    #[arg(long = "uncover", alias = "uc")]
    pub uncover: bool,

    /// Uncover search query
    #[arg(long = "uncover-query", short = 'q', alias = "uq")]
    pub uncover_query: Option<String>,

    /// Uncover search engine (shodan, censys, fofa, zoomeye, netlas, quake, hunter)
    #[arg(long = "uncover-engine", short = 'e', alias = "ue")]
    pub uncover_engine: Option<String>,

    /// Custom Interactsh server address
    #[arg(long = "interactsh-server", alias = "iserver")]
    pub interactsh_server: Option<String>,

    /// Maximum consecutive host errors before dropping host (circuit breaker)
    #[arg(long = "max-host-error", alias = "mhe", default_value = "30")]
    pub max_host_errors: usize,

    /// Detect potential honeypot hosts based on match concentration
    #[arg(long = "honeypot-detect", alias = "hpd")]
    pub honeypot_detect: bool,

    /// Distinct template IDs required to flag a honeypot host
    #[arg(long = "honeypot-threshold", alias = "hpt", default_value = "15")]
    pub honeypot_threshold: usize,

    /// Suppress output for flagged honeypot hosts
    #[arg(long = "suppress-honeypot", alias = "shp")]
    pub suppress_honeypot: bool,

    /// Cryptographically sign templates in place with Ed25519
    #[arg(long = "sign")]
    pub sign: bool,

    /// Refuse executing unsigned templates
    #[arg(long = "disable-unsigned-templates", alias = "duts")]
    pub disable_unsigned_templates: bool,

    /// Path to the Ed25519 signing key (hex); used by --sign and signature verification
    #[arg(long = "signing-key")]
    pub signing_key: Option<String>,

    /// Export findings to Elasticsearch (base URL)
    #[arg(long = "export-elasticsearch")]
    pub export_elasticsearch: Option<String>,

    /// Elasticsearch index name (default: nuclei-run)
    #[arg(long = "es-index", default_value = "nuclei-run")]
    pub es_index: String,

    /// Export findings to Splunk HEC (base URL)
    #[arg(long = "export-splunk")]
    pub export_splunk: Option<String>,

    /// Splunk HEC authentication token
    #[arg(long = "splunk-token")]
    pub splunk_token: Option<String>,

    /// Export findings to a webhook URL (JSON POST)
    #[arg(long = "export-webhook")]
    pub export_webhook: Option<String>,

    /// Create issues for findings: github, gitlab, jira, linear (tokens via env: GITHUB_TOKEN, GITLAB_TOKEN, JIRA_EMAIL + JIRA_API_TOKEN, LINEAR_API_KEY)
    #[arg(long = "tracker")]
    pub tracker: Option<String>,

    /// Tracker project: GitHub repo (org/repo), GitLab project ID, Jira project key, or Linear team ID
    #[arg(long = "tracker-project")]
    pub tracker_project: Option<String>,

    /// Tracker host URL: Jira instance host or self-hosted GitLab base URL
    #[arg(long = "tracker-url")]
    pub tracker_url: Option<String>,

    /// Deduplicate identical HTTP requests across templates
    #[arg(long = "cluster-requests")]
    pub cluster_requests: bool,

    /// Enable JSON Lines output
    #[arg(long = "jsonl")]
    pub jsonl: bool,

    /// Enable SARIF v2.1.0 output
    #[arg(long = "sarif")]
    pub sarif: bool,

    /// Silent mode: suppress banner and progress
    #[arg(long = "silent")]
    pub silent: bool,

    /// Force re-download of remote templates (bypass cache)
    #[arg(long = "update-templates", short = 'U')]
    pub update_templates: bool,
}

/// Translate nuclei-style single-dash multi-character flags into long flags
/// (clap only supports single-character shorts).
fn translate_legacy_flag(arg: &str) -> String {
    let (flag, suffix) = match arg.split_once('=') {
        Some((f, s)) => (f, Some(s)),
        None => (arg, None),
    };
    let mapped = match flag {
        "-uc" => "--uncover",
        "-uq" => "--uncover-query",
        "-ue" => "--uncover-engine",
        "-mhe" => "--max-host-error",
        "-duts" => "--disable-unsigned-templates",
        _ => return arg.to_string(),
    };
    match suffix {
        Some(s) => format!("{}={}", mapped, s),
        None => mapped.to_string(),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().map(|a| translate_legacy_flag(&a)).collect();
    let cli = Cli::parse_from(args);

    // Build scan configuration from CLI args.
    let scan_config = build_config(&cli);

    // Print banner unless silent.
    if !scan_config.silent {
        output::stdout::print_banner();
    }


    // Handle template signing mode if requested
    if scan_config.sign_templates {
        let key_path = scan_config.signing_key_path.as_ref().map(std::path::PathBuf::from);
        let (signing_key, key_file) =
            match engine::crypto_signer::TemplateSigner::load_or_create(key_path.as_deref()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[ERR] Signing key error: {}", e);
                    std::process::exit(1);
                }
            };
        eprintln!("[INF] Using signing key: {}", key_file.display());

        let mut signed = 0usize;
        for t_path in &scan_config.template_paths {
            let p = std::path::Path::new(t_path);
            if p.is_file() {
                match engine::crypto_signer::TemplateSigner::sign_file(p, &signing_key) {
                    Ok(()) => signed += 1,
                    Err(e) => eprintln!("[WRN] Failed to sign {}: {}", t_path, e),
                }
            } else if p.is_dir() {
                for entry in walkdir::WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
                    let fp = entry.path();
                    let is_yaml = fp
                        .extension()
                        .map_or(false, |x| x == "yaml" || x == "yml");
                    if is_yaml
                        && engine::crypto_signer::TemplateSigner::sign_file(fp, &signing_key)
                            .is_ok()
                    {
                        signed += 1;
                    }
                }
            }
        }
        eprintln!("[INF] Signed {} templates", signed);
        return;
    }

    // Resolve target URLs.
    let mut targets = resolve_targets(&cli);

    // OSINT target discovery (uncover).
    if scan_config.uncover {
        let Some(query) = scan_config.uncover_query.clone() else {
            eprintln!("[ERR] -uc requires a query via -uq <query>");
            std::process::exit(1);
        };
        let engine = scan_config
            .uncover_engine
            .clone()
            .unwrap_or_else(|| "shodan".to_string());
        let opts = engine::uncover::UncoverOptions {
            engine,
            query,
            limit: 100,
        };
        match engine::uncover::UncoverClient::query(&opts).await {
            Ok(discovered) => {
                eprintln!("[INF] Uncover discovered {} targets", discovered.len());
                targets.extend(discovered.into_iter().map(|t| normalize_url(&t)));
            }
            Err(e) => {
                eprintln!("[ERR] Uncover query failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    if targets.is_empty() {
        eprintln!("{}", "[ERR] No targets specified. Use -u <url>, -l <file>, or -uc OSINT discovery");
        std::process::exit(1);
    }

    // Load templates.
    let signature_policy = if scan_config.disable_unsigned_templates {
        let key_path = scan_config
            .signing_key_path
            .as_ref()
            .map(std::path::PathBuf::from)
            .or_else(|| {
                let default = engine::crypto_signer::TemplateSigner::default_key_path();
                default.exists().then_some(default)
            });
        match key_path.and_then(|p| {
            engine::crypto_signer::TemplateSigner::load_verifying_key(&p).ok()
        }) {
            Some(key) => yaml_loader::SignaturePolicy::Verify(key),
            None => yaml_loader::SignaturePolicy::RequireDigest,
        }
    } else {
        yaml_loader::SignaturePolicy::AllowAll
    };

    let filter = TemplateFilter {
        severities: scan_config.severity_filter.clone(),
        tags: scan_config.tag_filter.clone(),
        ids: scan_config.id_filter.clone(),
        signature_policy,
        enable_self_contained: scan_config.enable_self_contained,
    };

    // Resolve template paths (download remote URLs if needed).
    let mut resolved_handles = Vec::new();
    let mut resolved_paths = Vec::new();

    for path in &scan_config.template_paths {
        match parser::template_resolver::resolve_template_path(path, scan_config.update_templates).await {
            Ok(resolved) => {
                resolved_paths.push(resolved.local_path.clone());
                resolved_handles.push(resolved);
            }
            Err(e) => {
                eprintln!("[ERR] Failed to resolve template path '{}': {}", path, e);
            }
        }
    }

    let mut all_templates = Vec::new();
    let mut total_scanned = 0;
    let mut total_unsupported = 0;
    let mut total_errors = 0;
    let mut total_filtered = 0;
    let mut total_self_contained_excluded = 0;

    for path in &resolved_paths {
        let result = yaml_loader::load_templates(&path.to_string_lossy(), &filter);
        total_scanned += result.total_files_scanned;
        total_unsupported += result.skipped_unsupported;
        total_errors += result.skipped_parse_errors;
        total_filtered += result.skipped_filtered;
        total_self_contained_excluded += result.skipped_self_contained;
        all_templates.extend(result.templates);
    }

    if total_self_contained_excluded > 0 && !scan_config.silent {
        eprintln!(
            "[INF] Excluded {} self-contained template[s] (disabled as default), use -esc option to run self-contained templates.",
            total_self_contained_excluded
        );
    }

    if all_templates.is_empty() {
        eprintln!(
            "{} No templates loaded (scanned {} files)",
            "[ERR]",
            total_scanned,
        );
        std::process::exit(1);
    }

    if !scan_config.silent {
        output::stdout::print_load_summary(
            all_templates.len(),
            total_unsupported,
            total_errors,
            total_filtered,
        );
        output::stdout::print_target_summary(targets.len());
    }

    // Build scan tasks: each (target, template) pair.
    let templates_arc: Vec<Arc<models::template::NucleiTemplate>> =
        all_templates.into_iter().map(Arc::new).collect();

    // Compute request clusters (mutual exclusion with per-template tasks).
    let clustered_tasks: Vec<engine::clustering::ClusteredTask> =
        if scan_config.cluster_requests {
            let clusters =
                engine::clustering::RequestClusterer::cluster(&targets, &templates_arc);
            if !scan_config.silent {
                eprintln!(
                    "[INF] Clustered into {} distinct HTTP requests across {} templates",
                    clusters.len(),
                    templates_arc.len()
                );
            }
            clusters
        } else {
            Vec::new()
        };

    // Initialize the Interactsh OOB client when any template needs it.
    let interactsh_client = if templates_need_interactsh(&templates_arc) {
        match engine::interactsh::InteractshClient::new(
            scan_config.interactsh_server.as_deref(),
            None,
        ) {
            Ok(client) => {
                if !scan_config.silent {
                    eprintln!(
                        "[INF] Using Interactsh Server: {}",
                        client.hostname()
                    );
                }
                Some(client)
            }
            Err(e) => {
                eprintln!("[WRN] Could not initialize Interactsh client: {} (OOB disabled)", e);
                None
            }
        }
    } else {
        None
    };

    // Build per-template tasks only when clustering is NOT active.
    let tasks: Vec<ScanTask> = if scan_config.cluster_requests {
        Vec::new()
    } else {
        let mut t = Vec::new();
        for template in &templates_arc {
            if yaml_loader::requires_self_contained(template) {
                t.push(ScanTask {
                    target: String::new(),
                    template: Arc::clone(template),
                });
            } else {
                for target in &targets {
                    t.push(ScanTask {
                        target: target.clone(),
                        template: Arc::clone(template),
                    });
                }
            }
        }
        t
    };

    // Create engine runner.
    let engine = Arc::new(
        EngineRunner::new(
            scan_config.concurrency,
            scan_config.timeout_secs,
            scan_config.rate_limit_rps,
            scan_config.max_redirects,
            scan_config.proxy.as_deref(),
            &scan_config.custom_headers,
            scan_config.enable_code_templates,
            scan_config.headless,
            scan_config.max_host_errors,
            scan_config.retries,
            interactsh_client,
        )
        .with_redirect_flags(
            scan_config.follow_redirects,
            scan_config.follow_host_redirects,
            scan_config.disable_redirects,
        )
        .with_workflow_registry(Arc::new(
            engine::workflow::WorkflowTemplateRegistry::new(templates_arc.clone()),
        )),
    );

    // Set up finding channel.
    let (finding_tx, mut finding_rx) = tokio::sync::mpsc::channel(1000);

    // Graceful cancellation on Ctrl-C.
    let cancel_engine = Arc::clone(&engine);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\n[INF] Interrupt received, stopping scan gracefully...");
            cancel_engine.cancel();
        }
    });

    // Start the scan.
    let start_time = std::time::Instant::now();
    let engine_clone = Arc::clone(&engine);

    let scan_handle = tokio::spawn(async move {
        if !clustered_tasks.is_empty() {
            engine_clone.run_clustered(clustered_tasks, finding_tx).await;
        } else {
            engine_clone.run(tasks, finding_tx).await;
        }
    });

    // Collect and output findings as they arrive.
    let mut all_findings = Vec::new();
    let mut jsonl_writer = if scan_config.jsonl {
        let writer = if let Some(ref path) = scan_config.output_path {
            JsonlWriter::to_file(path).ok()
        } else {
            Some(JsonlWriter::to_stdout())
        };
        writer
    } else {
        None
    };

    let mut severity_counts: HashMap<String, usize> = HashMap::new();

    // Configure remote exporters and issue tracker from CLI options.
    let mut exporter_targets: Vec<output::exporter::ExporterTarget> = Vec::new();
    if let Some(ref url) = scan_config.export_elasticsearch {
        exporter_targets.push(output::exporter::ExporterTarget::Elasticsearch {
            url: url.clone(),
            index: scan_config.es_index.clone(),
        });
    }
    if let Some(ref url) = scan_config.export_splunk {
        exporter_targets.push(output::exporter::ExporterTarget::SplunkHec {
            url: url.clone(),
            token: scan_config.splunk_token.clone().unwrap_or_default(),
        });
    }
    if let Some(ref url) = scan_config.export_webhook {
        exporter_targets.push(output::exporter::ExporterTarget::Webhook { url: url.clone() });
    }
    let exporter = if exporter_targets.is_empty() {
        None
    } else {
        Some(output::exporter::RemoteExporter::new())
    };

    let tracker_target = build_tracker_target(&scan_config);
    let issue_tracker = if tracker_target.is_some() {
        Some(output::issue_tracker::IssueTrackerClient::new())
    } else {
        None
    };

    // Honeypot detection (opt-in).
    let mut honeypot_detector = if scan_config.honeypot_detect {
        Some(engine::honeypot::Detector::new(scan_config.honeypot_threshold))
    } else {
        None
    };

    while let Some(finding) = finding_rx.recv().await {
        // Honeypot detection / suppression: record the match, warn when a host
        // crosses the threshold, and drop results for flagged hosts when
        // --suppress-honeypot is set.
        if let Some(ref mut detector) = honeypot_detector {
            if detector.record_match(&finding.matched_url, &finding.template_id) {
                eprintln!(
                    "[WRN] Potential honeypot detected: {} (matched {} distinct templates)",
                    engine::honeypot::Detector::normalize_host_key(&finding.matched_url),
                    detector.threshold()
                );
            }
            if scan_config.suppress_honeypot && detector.is_flagged(&finding.matched_url) {
                continue;
            }
        }

        // Print to stdout (unless writing JSONL to stdout in non-silent mode).
        if !scan_config.silent && !(scan_config.jsonl && scan_config.output_path.is_none()) {
            output::stdout::print_finding(&finding);
        }

        // Write JSONL if enabled.
        if let Some(ref mut writer) = jsonl_writer {
            let _ = writer.write_finding(&finding);
        }

        // Export to remote SIEM / webhook destinations.
        if let Some(ref exporter) = exporter {
            for target in &exporter_targets {
                if let Err(e) = exporter.export(&finding, target).await {
                    eprintln!("[WRN] Export failed: {}", e);
                }
            }
        }

        // Create an issue in the configured tracker.
        if let (Some(ref tracker), Some(ref target)) = (&issue_tracker, &tracker_target) {
            if let Err(e) = tracker.create_issue(&finding, target).await {
                eprintln!("[WRN] Issue tracker failed: {}", e);
            }
        }

        // Track severity counts.
        *severity_counts
            .entry(finding.severity.clone())
            .or_insert(0) += 1;

        all_findings.push(finding);
    }

    // Wait for engine to complete.
    let _ = scan_handle.await;
    let elapsed = start_time.elapsed();

    // Flush JSONL writer.
    if let Some(ref mut writer) = jsonl_writer {
        let _ = writer.flush();
    }

    // Write SARIF report if enabled.
    if scan_config.sarif {
        let sarif_path = scan_config
            .output_path
            .as_deref()
            .unwrap_or("results.sarif.json");
        if let Err(e) = SarifReporter::write_report(&all_findings, sarif_path) {
            eprintln!("[ERR] Failed to write SARIF report: {}", e);
        } else if !scan_config.silent {
            eprintln!("[INF] SARIF report written to {}", sarif_path);
        }
    }

    // Summary calculation
    let total_requests = engine.request_count();
    let elapsed_millis = elapsed.as_millis();
    let rps = if elapsed.as_secs_f64() > 0.0 {
        total_requests as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let summary = ScanSummary {
        total_requests,
        total_findings: all_findings.len(),
        findings_by_severity: severity_counts,
        templates_loaded: templates_arc.len(),
        targets_scanned: targets.len(),
        elapsed_millis,
        rps,
    };

    // Write Markdown report if requested.
    if let Some(ref md_path) = scan_config.markdown_export {
        if let Err(e) = output::markdown::MarkdownReporter::write_report(&all_findings, Some(&summary), md_path) {
            eprintln!("[ERR] Failed to write Markdown report to {}: {}", md_path, e);
        } else if !scan_config.silent {
            eprintln!("[INF] Markdown report written to {}", md_path);
        }
    }

    if !scan_config.silent {
        if let Some(ref detector) = honeypot_detector {
            eprintln!("[INF] {}", detector.summary());
        }
        output::stdout::print_summary(&summary);
    }

    // Exit with non-zero code if critical/high findings were discovered.
    if all_findings.iter().any(|f| {
        f.severity == "critical" || f.severity == "high"
    }) {
        std::process::exit(1);
    }
}

/// Build ScanConfig from CLI arguments.
fn build_config(cli: &Cli) -> ScanConfig {
    let custom_headers = cli
        .header
        .as_ref()
        .map(|headers| {
            headers
                .iter()
                .filter_map(|h| {
                    let parts: Vec<&str> = h.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    ScanConfig {
        targets: vec![], // Resolved separately.
        template_paths: cli.templates.clone(),
        severity_filter: cli.severity.clone().unwrap_or_default(),
        tag_filter: cli.tags.clone().unwrap_or_default(),
        id_filter: cli.id.clone().unwrap_or_default(),
        concurrency: cli.concurrency,
        rate_limit_rps: cli.rate_limit,
        timeout_secs: cli.timeout,
        retries: cli.retries,
        max_redirects: cli.max_redirects,
        follow_redirects: cli.follow_redirects,
        follow_host_redirects: cli.follow_host_redirects,
        disable_redirects: cli.disable_redirects,
        enable_self_contained: cli.enable_self_contained,
        proxy: cli.proxy.clone(),
        custom_headers,
        output_path: cli.output.clone(),
        markdown_export: cli.markdown_export.clone(),
        enable_code_templates: cli.enable_code_templates,
        headless: cli.headless,
        uncover: cli.uncover,
        uncover_query: cli.uncover_query.clone(),
        uncover_engine: cli.uncover_engine.clone(),
        interactsh_server: cli.interactsh_server.clone(),
        max_host_errors: cli.max_host_errors,
        honeypot_detect: cli.honeypot_detect,
        honeypot_threshold: cli.honeypot_threshold,
        suppress_honeypot: cli.suppress_honeypot,
        sign_templates: cli.sign,
        disable_unsigned_templates: cli.disable_unsigned_templates,
        signing_key_path: cli.signing_key.clone(),
        export_elasticsearch: cli.export_elasticsearch.clone(),
        es_index: cli.es_index.clone(),
        export_splunk: cli.export_splunk.clone(),
        splunk_token: cli.splunk_token.clone(),
        export_webhook: cli.export_webhook.clone(),
        tracker: cli.tracker.clone(),
        tracker_project: cli.tracker_project.clone(),
        tracker_url: cli.tracker_url.clone(),
        cluster_requests: cli.cluster_requests,
        jsonl: cli.jsonl,
        sarif: cli.sarif,
        silent: cli.silent,
        update_templates: cli.update_templates,
    }
}

/// Resolve target URLs from -u and -l arguments.
fn resolve_targets(cli: &Cli) -> Vec<String> {
    let mut targets = Vec::new();

    // Single URL.
    if let Some(ref url) = cli.url {
        targets.push(normalize_url(url));
    }

    // URL list file.
    if let Some(ref list_path) = cli.list {
        match std::fs::read_to_string(list_path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        targets.push(normalize_url(trimmed));
                    }
                }
            }
            Err(e) => {
                eprintln!("[ERR] Failed to read target list {}: {}", list_path, e);
            }
        }
    }

    // Also read from stdin if no targets provided via args.
    if targets.is_empty() && cli.url.is_none() && cli.list.is_none() {
        // Check if stdin has data (non-interactive).
        if atty_is_not_terminal() {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                if let Ok(line) = line {
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        targets.push(normalize_url(&trimmed));
                    }
                }
            }
        }
    }

    targets
}

/// Ensure URL has a scheme prefix.
fn normalize_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    }
}

/// Build the issue tracker destination from CLI options and env tokens.
fn build_tracker_target(config: &ScanConfig) -> Option<output::issue_tracker::IssueTrackerTarget> {
    use output::issue_tracker::IssueTrackerTarget;

    let kind = config.tracker.as_deref()?.to_lowercase();
    let project = config.tracker_project.clone().unwrap_or_default();
    if project.is_empty() {
        eprintln!("[WRN] --tracker requires --tracker-project; issue creation disabled");
        return None;
    }

    fn missing(name: &str) {
        eprintln!("[WRN] Tracker disabled: {} environment variable not set", name);
    }

    match kind.as_str() {
        "github" => match std::env::var("GITHUB_TOKEN") {
            Ok(token) => Some(IssueTrackerTarget::GitHub { repo: project, token }),
            Err(_) => {
                missing("GITHUB_TOKEN");
                None
            }
        },
        "gitlab" => match std::env::var("GITLAB_TOKEN") {
            Ok(token) => Some(IssueTrackerTarget::GitLab {
                project_id: project,
                token,
                base_url: config.tracker_url.clone(),
            }),
            Err(_) => {
                missing("GITLAB_TOKEN");
                None
            }
        },
        "jira" => {
            let Some(host) = config.tracker_url.clone() else {
                eprintln!("[WRN] Tracker disabled: jira requires --tracker-url (instance host)");
                return None;
            };
            match (std::env::var("JIRA_EMAIL"), std::env::var("JIRA_API_TOKEN")) {
                (Ok(user_email), Ok(api_token)) => Some(IssueTrackerTarget::Jira {
                    host,
                    project_key: project,
                    user_email,
                    api_token,
                }),
                _ => {
                    missing("JIRA_EMAIL / JIRA_API_TOKEN");
                    None
                }
            }
        }
        "linear" => match std::env::var("LINEAR_API_KEY") {
            Ok(api_key) => Some(IssueTrackerTarget::Linear { team_id: project, api_key }),
            Err(_) => {
                missing("LINEAR_API_KEY");
                None
            }
        },
        other => {
            eprintln!("[WRN] Unknown tracker '{}'; issue creation disabled", other);
            None
        }
    }
}

/// Simple check if stdin is not a terminal (for pipe detection).
fn atty_is_not_terminal() -> bool {
    // Use a simple heuristic: try to detect if we're connected to a pipe.
    !std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// Returns true when any loaded template uses `{{interactsh-url}}` markers and
/// therefore needs the OOB correlation client.
fn templates_need_interactsh(templates: &[Arc<models::template::NucleiTemplate>]) -> bool {
    const MARKER: &str = "{{interactsh-url}}";
    templates.iter().any(|t| {
        t.http.iter().any(|b| {
            b.raw.iter().any(|r| r.contains(MARKER))
                || b.path.iter().any(|p| p.contains(MARKER))
                || b.body.as_deref().map_or(false, |body| body.contains(MARKER))
                || b.headers.values().any(|v| v.contains(MARKER))
        })
    })
}
