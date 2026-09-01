pub mod filter;
pub mod loader;

#[allow(unused_imports)]
pub use filter::{passes_filter, SignaturePolicy, TemplateFilter};
#[allow(unused_imports)]
pub use loader::{is_yaml_file, load_single_template, requires_self_contained, TemplateLoadOutcome};

use crate::models::template::NucleiTemplate;
use std::path::Path;
use walkdir::WalkDir;

/// Result of loading templates from disk.
pub struct LoadResult {
    pub templates: Vec<NucleiTemplate>,
    pub total_files_scanned: usize,
    pub skipped_unsupported: usize,
    pub skipped_parse_errors: usize,
    pub skipped_filtered: usize,
    /// Self-contained templates excluded by the `-esc` capability gate.
    pub skipped_self_contained: usize,
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
        skipped_self_contained: 0,
    };

    if p.is_file() {
        result.total_files_scanned = 1;
        match load_single_template(p, filter) {
            TemplateLoadOutcome::Loaded(t) => result.templates.push(t),
            TemplateLoadOutcome::Filtered => result.skipped_filtered += 1,
            TemplateLoadOutcome::Unsupported => result.skipped_unsupported += 1,
            TemplateLoadOutcome::SelfContainedExcluded => result.skipped_self_contained += 1,
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
                TemplateLoadOutcome::SelfContainedExcluded => result.skipped_self_contained += 1,
                TemplateLoadOutcome::ParseError(e) => {
                    eprintln!("[WRN] Failed to parse {}: {}", file_path.display(), e);
                    result.skipped_parse_errors += 1;
                }
            }
        }
    } else {
        eprintln!("[ERR] Path does not exist: {}", path);
    }

    result
}
