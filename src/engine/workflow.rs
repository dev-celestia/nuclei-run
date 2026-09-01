use crate::models::template::{NucleiTemplate, WorkflowStep};
use std::path::Path;
use std::sync::Arc;

/// Resolves the step templates referenced by a workflow `WorkflowStep`.
///
/// This mirrors Go's `WorkflowLoader` (`pkg/model/workflow_loader.go`) which
/// resolves step `template:` paths or `tags:` selectors into concrete,
/// already-loaded templates. In this implementation steps resolve against the
/// full set of templates loaded for the scan (keyed by tag and by source path)
/// rather than re-loading files at execution time.
pub struct WorkflowTemplateRegistry {
    templates: Vec<Arc<NucleiTemplate>>,
}

impl WorkflowTemplateRegistry {
    pub fn new(templates: Vec<Arc<NucleiTemplate>>) -> Self {
        Self { templates }
    }

    /// Resolve a workflow step to the concrete templates it references.
    ///
    /// - When `tags` is set, every loaded template whose `info.tags`
    ///   intersects any requested tag is selected (Go `GetTemplatePathsByTags`).
    /// - Otherwise `template` is matched by source-path suffix/basename
    ///   (Go `GetTemplatePaths` with loose matching).
    pub fn resolve_step(&self, step: &WorkflowStep) -> Vec<Arc<NucleiTemplate>> {
        let tag_sel = step.tag_list();
        if !tag_sel.is_empty() {
            return self
                .templates
                .iter()
                .filter(|t| {
                    t.info.tags.as_deref().is_some_and(|tags| {
                        tags.split(',')
                            .map(|x| x.trim())
                            .any(|tt| tag_sel.iter().any(|w| w.eq_ignore_ascii_case(tt)))
                    })
                })
                .cloned()
                .collect();
        }

        if let Some(path) = &step.template {
            let needle = normalize_path(path);
            let needle_base = Path::new(path)
                .file_name()
                .map(|b| b.to_string_lossy().into_owned())
                .unwrap_or_default();
            return self
                .templates
                .iter()
                .filter(|t| {
                    let Some(sp) = t.source_path.as_deref() else {
                        return false;
                    };
                    let sp = normalize_path(sp);
                    sp.ends_with(&needle)
                        || {
                            !needle_base.is_empty()
                                && Path::new(&sp)
                                    .file_name()
                                    .map(|b| b.to_string_lossy().into_owned())
                                    == Some(needle_base.clone())
                        }
                })
                .cloned()
                .collect();
        }

        Vec::new()
    }
}

/// Normalize a path for suffix matching: forward slashes, trimmed separators.
fn normalize_path(p: &str) -> String {
    p.replace('\\', "/")
        .trim_end_matches('/')
        .to_string()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::template::TemplateInfo;

    fn template(id: &str, tags: &str, path: Option<&str>) -> Arc<NucleiTemplate> {
        let info = TemplateInfo {
            name: id.to_string(),
            author: crate::models::template::FlexibleStringList::Single("test".into()),
            severity: "info".to_string(),
            description: None,
            reference: None,
            tags: tags.to_string().into(),
            metadata: None,
            classification: None,
            remediation: None,
        };
        Arc::new(NucleiTemplate {
            id: id.to_string(),
            info,
            http: vec![],
            dns: vec![],
            network: vec![],
            ssl: vec![],
            whois: vec![],
            file: vec![],
            code: vec![],
            websocket: vec![],
            headless: vec![],
            javascript: vec![],
            fuzzing: vec![],
            flow: None,
            signature: None,
            self_contained: false,
            variables: Default::default(),
            constants: Default::default(),
            workflows: vec![],
            source_path: path.map(|s| s.to_string()),
        })
    }

    #[test]
    fn test_resolve_by_tags() {
        let registry = WorkflowTemplateRegistry::new(vec![
            template("a", "cve,rce", Some("/t/a.yaml")),
            template("b", "misc", Some("/t/b.yaml")),
        ]);
        let step = WorkflowStep {
            tags: crate::models::template::FlexibleStringList::List(vec!["rce".into()]),
            ..Default::default()
        };
        let resolved = registry.resolve_step(&step);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "a");
    }

    #[test]
    fn test_resolve_by_path() {
        let registry = WorkflowTemplateRegistry::new(vec![
            template("a", "", Some("/templates/http/example.yaml")),
        ]);
        let step = WorkflowStep {
            template: Some("http/example.yaml".into()),
            ..Default::default()
        };
        let resolved = registry.resolve_step(&step);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "a");
    }

    #[test]
    fn test_resolve_empty() {
        let registry = WorkflowTemplateRegistry::new(vec![template("a", "", Some("/t/a.yaml"))]);
        let step = WorkflowStep::default();
        assert!(registry.resolve_step(&step).is_empty());
    }

    #[test]
    fn test_matcher_condition_and_or() {
        let mut m = crate::models::template::WorkflowMatcher::default();
        assert!(!m.is_and());
        m.condition = Some("and".into());
        assert!(m.is_and());
    }
}
