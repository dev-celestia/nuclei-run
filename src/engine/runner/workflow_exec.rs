use crate::engine::runner::{EngineRunner, RunCapture};
use crate::engine::workflow::WorkflowTemplateRegistry;
use crate::models::result::ScanFinding;
use crate::models::template::{NucleiTemplate, WorkflowMatcher, WorkflowStep};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Aggregated result of running one workflow step against a target, used to
/// gate matchers and direct subtemplates (Go `runWorkflowStep` + `operators.Result`).
#[derive(Debug, Default, Clone)]
pub struct WorkflowStepResult {
    pub matched: bool,
    pub capture: RunCapture,
}

impl EngineRunner {
    /// Execute a workflow (list of top-level steps) against a target.
    ///
    /// Mirrors Go `executeWorkflow`: each step executes its resolved templates,
    /// extracts flow down through `extracted_vars`, and subtemplates are gated
    /// on whether the step matched (direct `subtemplates:`) or on named matcher
    /// results (`matchers:`).
    pub async fn execute_workflow(
        &self,
        workflows: &[WorkflowStep],
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        registry: Arc<WorkflowTemplateRegistry>,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for step in workflows {
            if self.is_cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            self.run_workflow_step(step, target, extracted_vars, &registry, result_tx)
                .await;
        }
    }

    /// Execute one workflow step and its gated subtemplates. Returns the
    /// aggregated result so parents can propagate match/extract names.
    ///
    /// Recursive async function — boxed to avoid infinite-size future (same
    /// pattern as `flow_exec::eval_flow_node`).
    fn run_workflow_step<'a>(
        &'a self,
        step: &'a WorkflowStep,
        target: &'a str,
        extracted_vars: &'a mut HashMap<String, String>,
        registry: &'a WorkflowTemplateRegistry,
        result_tx: &'a mpsc::Sender<ScanFinding>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WorkflowStepResult> + Send + 'a>> {
        Box::pin(async move {
            let mut result = WorkflowStepResult::default();
            let templates = registry.resolve_step(step);

            for t in &templates {
                let mut capture = RunCapture::default();
                self.execute_workflow_template(t, target, extracted_vars, &mut capture, result_tx)
                    .await;
                result.matched |= capture.matched;
                result
                    .capture
                    .matched_matchers
                    .extend(capture.matched_matchers);
                result
                    .capture
                    .extract_names
                    .extend(capture.extract_names);
            }

            // Direct `subtemplates:` run only if this step produced any result.
            if !step.subtemplates.is_empty() && result.matched {
                for sub in &step.subtemplates {
                    self.run_workflow_step(sub, target, extracted_vars, registry, result_tx)
                        .await;
                }
            }

            // Named `matchers:` gate their own subtemplates per-matcher.
            for matcher in &step.matchers {
                if workflow_matcher_matches(matcher, &result) {
                    for sub in &matcher.subtemplates {
                        self.run_workflow_step(sub, target, extracted_vars, registry, result_tx)
                            .await;
                    }
                }
            }

            result
        })
    }

    /// Execute one referenced template's protocol blocks against the target,
    /// emitting findings and capturing names for workflow gating.
    async fn execute_workflow_template(
        &self,
        template: &Arc<NucleiTemplate>,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        capture: &mut RunCapture,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        // Flow-controlled step templates run through their flow logic. Flow
        // captures only the aggregate match boolean (named gating for flow
        // templates is best-effort).
        if let Some(flow_expr) = &template.flow {
            if let Some(ast) = crate::engine::flow::parse_flow(flow_expr) {
                self.execute_flow_capture(
                    &ast,
                    template,
                    target,
                    extracted_vars,
                    capture,
                    result_tx,
                )
                .await;
            }
            return;
        }

        self.execute_protocols(template, target, extracted_vars, Some(capture), result_tx)
            .await;
    }
}

/// Go `matcher.Match` semantics: a name is satisfied by a matcher hit OR an
/// extractor hit (case-insensitive), with AND/OR over the name list.
fn workflow_matcher_matches(matcher: &WorkflowMatcher, result: &WorkflowStepResult) -> bool {
    let names = matcher.name_list();
    if names.is_empty() {
        return false;
    }
    let satisfied = |name: &str| result.capture.has_match(name) || result.capture.has_extract(name);
    if matcher.is_and() {
        names.iter().all(|n| satisfied(n))
    } else {
        names.iter().any(|n| satisfied(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::runner::RunCapture;

    #[test]
    fn test_matcher_match_or_default() {
        let m = WorkflowMatcher {
            name: crate::models::template::FlexibleStringList::List(vec![
                "alpha".into(),
                "beta".into(),
            ]),
            ..Default::default()
        };
        let mut res = WorkflowStepResult::default();
        res.capture.matched_matchers.push("alpha".into());
        assert!(workflow_matcher_matches(&m, &res));

        // OR false when none present.
        let res2 = WorkflowStepResult::default();
        assert!(!workflow_matcher_matches(&m, &res2));
    }

    #[test]
    fn test_matcher_match_and() {
        let m = WorkflowMatcher {
            condition: Some("and".into()),
            name: crate::models::template::FlexibleStringList::List(vec![
                "alpha".into(),
                "beta".into(),
            ]),
            ..Default::default()
        };
        let mut res = WorkflowStepResult::default();
        res.capture.matched_matchers.push("alpha".into());
        assert!(!workflow_matcher_matches(&m, &res));

        res.capture.matched_matchers.push("beta".into());
        assert!(workflow_matcher_matches(&m, &res));
    }

    #[test]
    fn test_matcher_match_satisfied_by_extract() {
        let m = WorkflowMatcher {
            name: crate::models::template::FlexibleStringList::Single("token".into()),
            ..Default::default()
        };
        let mut res = WorkflowStepResult::default();
        res.capture.extract_names.push("token".into());
        assert!(workflow_matcher_matches(&m, &res));
    }

    #[test]
    fn test_run_capture_case_insensitive() {
        let mut c = RunCapture::default();
        c.matched_matchers.push("Token".into());
        assert!(c.has_match("token"));
        assert!(!c.has_extract("nope"));
    }
}
