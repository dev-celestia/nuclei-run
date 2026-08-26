use crate::models::result::ScanFinding;
use serde_json::json;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Generate an OASIS SARIF v2.1.0 report from scan findings.
pub struct SarifReporter;

impl SarifReporter {
    /// Write findings as a SARIF v2.1.0 JSON document to the given file path.
    pub fn write_report(findings: &[ScanFinding], output_path: &str) -> io::Result<()> {
        let sarif = Self::build_sarif(findings);
        let json_str = serde_json::to_string_pretty(&sarif)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut file = File::create(Path::new(output_path))?;
        file.write_all(json_str.as_bytes())?;
        file.flush()
    }

    /// Build the SARIF JSON structure.
    pub fn build_sarif(findings: &[ScanFinding]) -> serde_json::Value {
        // Collect unique rules (template IDs).
        let mut rules = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for finding in findings {
            if seen_rules.insert(finding.template_id.clone()) {
                rules.push(json!({
                    "id": finding.template_id,
                    "name": finding.template_name,
                    "shortDescription": {
                        "text": finding.template_name
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(&finding.severity)
                    },
                    "properties": {
                        "tags": finding.tags.as_deref().unwrap_or("").split(',')
                            .map(|t| t.trim())
                            .filter(|t| !t.is_empty())
                            .collect::<Vec<&str>>()
                    }
                }));
            }
        }

        // Build results array.
        let results: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                let mut result = json!({
                    "ruleId": f.template_id,
                    "level": severity_to_sarif_level(&f.severity),
                    "message": {
                        "text": format!(
                            "{} detected at {}",
                            f.template_name, f.matched_url
                        )
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.matched_url
                            }
                        }
                    }]
                });

                // Add extracted snippets if available.
                if !f.extracted_results.is_empty() {
                    result["properties"] = json!({
                        "extracted_data": f.extracted_results
                    });
                }

                result
            })
            .collect();

        json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "nuclei-rs",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/nuclei-rs",
                        "rules": rules
                    }
                },
                "results": results
            }]
        })
    }
}

/// Map nuclei severity to SARIF level.
fn severity_to_sarif_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "none",
    }
}
