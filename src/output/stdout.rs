use crate::models::result::{ScanFinding, ScanSummary};
use colored::Colorize;

/// Print a single finding to stdout with color-coded severity.
///
/// Format: [template-id] [http] [severity] matched-url [extracted-data]
pub fn print_finding(finding: &ScanFinding) {
    let severity_colored = colorize_severity(&finding.severity);
    let extracted = if finding.extracted_results.is_empty() {
        String::new()
    } else {
        format!(" [{}]", finding.extracted_results.join(", "))
    };

    println!(
        "[{}] [{}] [{}] {}{}",
        finding.template_id.bold(),
        finding.protocol.dimmed(),
        severity_colored,
        finding.matched_url.cyan(),
        extracted.yellow(),
    );
}

/// Print the scan banner at startup.
pub fn print_banner() {
    let banner = r#"
                    __     _                             
   ____  __  ______/ /__  (_)     _______  ______        
  / __ \/ / / / __/ / _ \/ /_____/ ___/ / / / __ \       
 / / / / /_/ / /_/ /  __/ /_____/ /  / /_/ / / / /       
/_/ /_/\__,_/\__/_/\___/_/     /_/   \__,_/_/ /_/        
                                                         
    "#;

    println!("{}", banner.bright_cyan());
    println!(
        "  {} {} | {}",
        "nuclei-run".bold().bright_white(),
        env!("CARGO_PKG_VERSION").dimmed(),
        "High-Performance Vulnerability Scanner".dimmed()
    );
    println!();
}

/// Print template loading summary.
pub fn print_load_summary(
    loaded: usize,
    skipped_unsupported: usize,
    skipped_errors: usize,
    skipped_filtered: usize,
) {
    println!(
        "{} Loaded {} templates ({} unsupported, {} errors, {} filtered out)",
        "[INF]".bright_blue(),
        loaded.to_string().bold().bright_green(),
        skipped_unsupported,
        skipped_errors,
        skipped_filtered,
    );
}

/// Print target loading summary.
pub fn print_target_summary(count: usize) {
    println!(
        "{} Targeting {} hosts",
        "[INF]".bright_blue(),
        count.to_string().bold().bright_green(),
    );
}

/// Print the scan completion summary table.
pub fn print_summary(summary: &ScanSummary) {
    println!();
    println!("{}", "─".repeat(60).dimmed());
    println!(
        "  {} {}",
        "Scan Summary".bold().bright_white(),
        format!("({}ms elapsed)", summary.elapsed_millis).dimmed(),
    );
    println!("{}", "─".repeat(60).dimmed());

    println!(
        "  {} {} | {} {} | {} {:.1}",
        "Requests:".dimmed(),
        summary.total_requests.to_string().bold(),
        "Findings:".dimmed(),
        summary.total_findings.to_string().bold().bright_red(),
        "RPS:".dimmed(),
        summary.rps,
    );

    if !summary.findings_by_severity.is_empty() {
        let mut parts = Vec::new();
        for sev in &["critical", "high", "medium", "low", "info"] {
            if let Some(&count) = summary.findings_by_severity.get(*sev) {
                if count > 0 {
                    parts.push(format!("{}: {}", colorize_severity(sev), count));
                }
            }
        }
        if !parts.is_empty() {
            println!("  {} {}", "Breakdown:".dimmed(), parts.join(" | "));
        }
    }

    println!("{}", "─".repeat(60).dimmed());
}

/// Apply color to severity label.
fn colorize_severity(severity: &str) -> colored::ColoredString {
    match severity.to_lowercase().as_str() {
        "critical" => severity.bold().bright_red(),
        "high" => severity.bold().red(),
        "medium" => severity.bold().yellow(),
        "low" => severity.bold().blue(),
        "info" => severity.bold().cyan(),
        _ => severity.dimmed(),
    }
}
