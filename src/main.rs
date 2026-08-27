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
    #[arg(long = "max-redirects", default_value = "10")]
    max_redirects: usize,

    /// HTTP/SOCKS5 proxy URL
    #[arg(long = "proxy")]
    proxy: Option<String>,

    /// Custom headers (format: "Key: Value", repeatable)
    #[arg(short = 'H', long = "header")]
    header: Option<Vec<String>>,

    /// Output file path
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Enable JSON Lines output
    #[arg(long = "jsonl")]
    jsonl: bool,

    /// Enable SARIF v2.1.0 output
    #[arg(long = "sarif")]
    sarif: bool,

    /// Silent mode: suppress banner and progress
    #[arg(long = "silent")]
    silent: bool,

    /// Force re-download of remote templates (bypass cache)
    #[arg(long = "update-templates", short = 'U')]
    update_templates: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Build scan configuration from CLI args.
    let scan_config = build_config(&cli);

    // Print banner unless silent.
    if !scan_config.silent {
        output::stdout::print_banner();
    }

    // Resolve target URLs.
    let targets = resolve_targets(&cli);
    if targets.is_empty() {
        eprintln!("{}", "[ERR] No targets specified. Use -u <url> or -l <file>");
        std::process::exit(1);
    }

    // Load templates.
    let filter = TemplateFilter {
        severities: scan_config.severity_filter.clone(),
        tags: scan_config.tag_filter.clone(),
        ids: scan_config.id_filter.clone(),
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

    for path in &resolved_paths {
        let result = yaml_loader::load_templates(&path.to_string_lossy(), &filter);
        total_scanned += result.total_files_scanned;
        total_unsupported += result.skipped_unsupported;
        total_errors += result.skipped_parse_errors;
        total_filtered += result.skipped_filtered;
        all_templates.extend(result.templates);
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

    let mut tasks = Vec::new();
    for target in &targets {
        for template in &templates_arc {
            tasks.push(ScanTask {
                target: target.clone(),
                template: Arc::clone(template),
            });
        }
    }

    // Create engine runner.
    let engine = Arc::new(EngineRunner::new(
        scan_config.concurrency,
        scan_config.timeout_secs,
        scan_config.rate_limit_rps,
        scan_config.max_redirects,
        scan_config.proxy.as_deref(),
        &scan_config.custom_headers,
    ));

    // Set up finding channel.
    let (finding_tx, mut finding_rx) = tokio::sync::mpsc::channel(1000);

    // Start the scan.
    let start_time = std::time::Instant::now();
    let engine_clone = Arc::clone(&engine);

    let scan_handle = tokio::spawn(async move {
        engine_clone.run(tasks, finding_tx).await;
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

    while let Some(finding) = finding_rx.recv().await {
        // Print to stdout (unless writing JSONL to stdout in non-silent mode).
        if !scan_config.silent && !(scan_config.jsonl && scan_config.output_path.is_none()) {
            output::stdout::print_finding(&finding);
        }

        // Write JSONL if enabled.
        if let Some(ref mut writer) = jsonl_writer {
            let _ = writer.write_finding(&finding);
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

    // Print summary.
    let total_requests = engine.request_count();
    let elapsed_millis = elapsed.as_millis();
    let rps = if elapsed.as_secs_f64() > 0.0 {
        total_requests as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    if !scan_config.silent {
        let summary = ScanSummary {
            total_requests,
            total_findings: all_findings.len(),
            findings_by_severity: severity_counts,
            templates_loaded: templates_arc.len(),
            targets_scanned: targets.len(),
            elapsed_millis,
            rps,
        };
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
        proxy: cli.proxy.clone(),
        custom_headers,
        output_path: cli.output.clone(),
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

/// Simple check if stdin is not a terminal (for pipe detection).
fn atty_is_not_terminal() -> bool {
    // Use a simple heuristic: try to detect if we're connected to a pipe.
    !std::io::IsTerminal::is_terminal(&std::io::stdin())
}
