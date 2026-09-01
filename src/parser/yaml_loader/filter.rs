use crate::models::template::{NucleiTemplate, Severity};

/// Template signature enforcement mode for `--disable-unsigned-templates`.
#[derive(Debug, Clone, Default)]
pub enum SignaturePolicy {
    /// No signature enforcement (default).
    #[default]
    AllowAll,
    /// Require a `# digest:` line to be present.
    RequireDigest,
    /// Require a `# digest:` line and verify it against this key.
    Verify(ed25519_dalek::VerifyingKey),
}

/// Filter criteria for selecting templates during loading.
#[derive(Debug, Clone, Default)]
pub struct TemplateFilter {
    /// Filter by severity levels (e.g., ["high", "critical"]).
    pub severities: Vec<String>,
    /// Filter by template tags (e.g., ["cve", "rce"]).
    pub tags: Vec<String>,
    /// Filter by specific template IDs.
    pub ids: Vec<String>,
    /// Signature enforcement policy.
    pub signature_policy: SignaturePolicy,
    /// Allow self-contained templates (`-esc` / `--enable-self-contained`).
    /// Go nuclei excludes them at load time unless this capability is enabled.
    pub enable_self_contained: bool,
}

/// Check if template passes all active filters.
pub fn passes_filter(template: &NucleiTemplate, filter: &TemplateFilter) -> bool {
    // Severity filter
    if !filter.severities.is_empty() {
        let sev = Severity::from_str_tolerant(&template.info.severity);
        let sev_str = sev.to_string();
        if !filter
            .severities
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&sev_str))
        {
            return false;
        }
    }

    // ID filter
    if !filter.ids.is_empty()
        && !filter
            .ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(&template.id))
    {
        return false;
    }

    // Tag filter
    if !filter.tags.is_empty() {
        if let Some(ref tags_str) = template.info.tags {
            let template_tags: Vec<&str> = tags_str.split(',').map(|t| t.trim()).collect();
            if !filter
                .tags
                .iter()
                .any(|ft| template_tags.iter().any(|tt| tt.eq_ignore_ascii_case(ft)))
            {
                return false;
            }
        } else {
            return false; // Template has no tags but filter requires tags.
        }
    }

    true
}
