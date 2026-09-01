use crate::engine::crypto_signer::TemplateSigner;
use crate::models::template::NucleiTemplate;
use crate::parser::yaml_loader::filter::{passes_filter, SignaturePolicy, TemplateFilter};
use std::path::Path;

pub enum TemplateLoadOutcome {
    Loaded(NucleiTemplate),
    Filtered,
    Unsupported,
    SelfContainedExcluded,
    ParseError(String),
}

/// Self-contained capability check mirroring Go's `requiresSelfContained`
/// (pkg/templates/capability.go): the top-level flag or any http request
/// block flag. Go's network/headless blocks carry `yaml:"-"` on their
/// SelfContained field, so YAML templates can never set those.
pub fn requires_self_contained(template: &NucleiTemplate) -> bool {
    template.self_contained || template.http.iter().any(|b| b.self_contained)
}

/// Load and validate a single YAML template file.
pub fn load_single_template(path: &Path, filter: &TemplateFilter) -> TemplateLoadOutcome {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return TemplateLoadOutcome::ParseError(e.to_string()),
    };

    // Signature enforcement (--disable-unsigned-templates).
    match &filter.signature_policy {
        SignaturePolicy::AllowAll => {}
        SignaturePolicy::RequireDigest => {
            if TemplateSigner::extract_digest_hex(&content).is_none() {
                return TemplateLoadOutcome::Filtered;
            }
        }
        SignaturePolicy::Verify(key) => {
            let signed = TemplateSigner::extract_digest_hex(&content)
                .map(|digest| TemplateSigner::verify_content(&content, key, &digest))
                .unwrap_or(false);
            if !signed {
                return TemplateLoadOutcome::Filtered;
            }
        }
    }

    let mut template: NucleiTemplate = match serde_yaml::from_str(&content) {
        Ok(t) => t,
        Err(e) => return TemplateLoadOutcome::ParseError(e.to_string()),
    };
    template.source_path = path.to_string_lossy().into_owned().into();

    // Capability gate: self-contained templates are excluded unless `-esc`
    // is set (Go: capability.go `CapabilitySelfContained`, loadBlocking).
    if requires_self_contained(&template) && !filter.enable_self_contained {
        return TemplateLoadOutcome::SelfContainedExcluded;
    }

    // Ensure template has at least one executable block (or is a workflow).
    let has_executable_blocks = !template.http.is_empty()
        || !template.dns.is_empty()
        || !template.network.is_empty()
        || !template.ssl.is_empty()
        || !template.whois.is_empty()
        || !template.file.is_empty()
        || !template.code.is_empty()
        || !template.websocket.is_empty()
        || !template.javascript.is_empty()
        || !template.headless.is_empty()
        || !template.fuzzing.is_empty()
        || !template.workflows.is_empty()
        || template.flow.is_some();

    if !has_executable_blocks {
        return TemplateLoadOutcome::Unsupported;
    }

    // Flow templates whose script uses syntax beyond the supported boolean
    // subset (loops, functions, iterate/set, etc.) cannot be executed safely:
    // running their blocks without the gating logic produces false positives,
    // so they are skipped as unsupported.
    if let Some(ref flow) = template.flow {
        if crate::engine::flow::parse_flow(flow).is_none() {
            return TemplateLoadOutcome::Unsupported;
        }
    }

    // Apply filters.
    if !passes_filter(&template, filter) {
        return TemplateLoadOutcome::Filtered;
    }

    TemplateLoadOutcome::Loaded(template)
}

/// Check if a file path has a YAML extension.
pub fn is_yaml_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext == "yaml" || ext == "yml")
        .unwrap_or(false)
}
