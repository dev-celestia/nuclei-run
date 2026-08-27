use crate::models::template::{NucleiTemplate, Severity};
use serde_yaml;
use std::path::Path;
use walkdir::WalkDir;

/// Filter criteria for selecting templates during loading.
#[derive(Debug, Clone, Default)]
pub struct TemplateFilter {
    /// Filter by severity levels (e.g., ["high", "critical"]).
    pub severities: Vec<String>,
    /// Filter by template tags (e.g., ["cve", "rce"]).
    pub tags: Vec<String>,
    /// Filter by specific template IDs.
    pub ids: Vec<String>,
}

/// Result of loading templates from disk.
pub struct LoadResult {
    pub templates: Vec<NucleiTemplate>,
    pub total_files_scanned: usize,
    pub skipped_unsupported: usize,
    pub skipped_parse_errors: usize,
    pub skipped_filtered: usize,
}

/// Load templates from a single file or directory (recursive).
/// Gracefully skips templates that use unsupported protocols or fail parsing.
pub fn load_templates(path: &str, filter: &TemplateFilter) -> LoadResult {
    let p = Path::new(path);
    let mut result = LoadResult {
        templates: Vec::new(),
        total_files_scanned: 0,
        skipped_unsupported: 0,
        skipped_parse_errors: 0,
        skipped_filtered: 0,
    };

    if p.is_file() {
        result.total_files_scanned = 1;
        match load_single_template(p, filter) {
            TemplateLoadOutcome::Loaded(t) => result.templates.push(t),
            TemplateLoadOutcome::Filtered => result.skipped_filtered += 1,
            TemplateLoadOutcome::Unsupported => result.skipped_unsupported += 1,
            TemplateLoadOutcome::ParseError(e) => {
                eprintln!("[WRN] Failed to parse {}: {}", path, e);
                result.skipped_parse_errors += 1;
            }
        }
    } else if p.is_dir() {
        for entry in WalkDir::new(p)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_path = entry.path();
            if !is_yaml_file(file_path) {
                continue;
            }
            result.total_files_scanned += 1;

            match load_single_template(file_path, filter) {
                TemplateLoadOutcome::Loaded(t) => result.templates.push(t),
                TemplateLoadOutcome::Filtered => result.skipped_filtered += 1,
                TemplateLoadOutcome::Unsupported => result.skipped_unsupported += 1,
                TemplateLoadOutcome::ParseError(e) => {
                    eprintln!(
                        "[WRN] Failed to parse {}: {}",
                        file_path.display(),
                        e
                    );
                    result.skipped_parse_errors += 1;
                }
            }
        }
    } else {
        eprintln!("[ERR] Path does not exist: {}", path);
    }

    result
}

enum TemplateLoadOutcome {
    Loaded(NucleiTemplate),
    Filtered,
    Unsupported,
    ParseError(String),
}

/// Load and validate a single YAML template file.
fn load_single_template(path: &Path, filter: &TemplateFilter) -> TemplateLoadOutcome {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return TemplateLoadOutcome::ParseError(e.to_string()),
    };

    let template: NucleiTemplate = match serde_yaml::from_str(&content) {
        Ok(t) => t,
        Err(e) => return TemplateLoadOutcome::ParseError(e.to_string()),
    };

    // Ensure template has at least one executable block
    let has_executable_blocks = !template.http.is_empty()
        || !template.dns.is_empty()
        || !template.network.is_empty()
        || !template.ssl.is_empty()
        || !template.whois.is_empty()
        || !template.file.is_empty()
        || !template.code.is_empty()
        || !template.websocket.is_empty()
        || !template.headless.is_empty()
        || !template.javascript.is_empty()
        || !template.fuzzing.is_empty()
        || template.flow.is_some();

    if !has_executable_blocks {
        return TemplateLoadOutcome::Unsupported;
    }

    // Apply filters.
    if !passes_filter(&template, filter) {
        return TemplateLoadOutcome::Filtered;
    }

    TemplateLoadOutcome::Loaded(template)
}

/// Check if template passes all active filters.
fn passes_filter(template: &NucleiTemplate, filter: &TemplateFilter) -> bool {
    // Severity filter
    if !filter.severities.is_empty() {
        let sev = Severity::from_str_tolerant(&template.info.severity);
        let sev_str = sev.to_string();
        if !filter.severities.iter().any(|s| s.eq_ignore_ascii_case(&sev_str)) {
            return false;
        }
    }

    // ID filter
    if !filter.ids.is_empty() && !filter.ids.iter().any(|id| id.eq_ignore_ascii_case(&template.id)) {
        return false;
    }

    // Tag filter
    if !filter.tags.is_empty() {
        if let Some(ref tags_str) = template.info.tags {
            let template_tags: Vec<&str> = tags_str.split(',').map(|t| t.trim()).collect();
            if !filter.tags.iter().any(|ft| {
                template_tags.iter().any(|tt| tt.eq_ignore_ascii_case(ft))
            }) {
                return false;
            }
        } else {
            return false; // Template has no tags but filter requires tags.
        }
    }

    true
}

/// Check if a file path has a YAML extension.
fn is_yaml_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext == "yaml" || ext == "yml")
        .unwrap_or(false)
}
