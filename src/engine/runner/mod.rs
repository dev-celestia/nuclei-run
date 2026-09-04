pub mod flow_exec;
pub mod helpers;
pub mod protocols;
pub mod workflow_exec;

#[allow(unused_imports)]
pub use helpers::{has_unresolved_variables, interpolate_matchers, yaml_value_to_string, RequestSpec};

use crate::engine::dsl::TemplateDsl;
use crate::engine::host_errors::HostErrorsCache;
use crate::engine::http_client::{HttpClient, HttpResponse};
use crate::engine::interactsh::{evaluate_interaction, InteractshClient, PendingRequest};
use crate::engine::runner::helpers::{INTERACTSH_COOLDOWN_SECS, INTERACTSH_POLL_SECS};
use crate::engine::workflow::WorkflowTemplateRegistry;
use crate::models::result::ScanFinding;
use crate::models::template::{HttpBlock, NucleiTemplate};
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// A unit of work: one target URL × one template.
pub struct ScanTask {
    pub target: String,
    pub template: Arc<NucleiTemplate>,
}

/// Result capture used by workflow execution to gate subtemplates on named
/// matcher/extractor results (Go `operators.Result` semantics). Populated
/// only when a workflow step template is executed.
#[derive(Debug, Default, Clone)]
pub struct RunCapture {
    /// Whether any non-internal matcher matched.
    pub matched: bool,
    /// Names (lowercased) of matchers that matched.
    pub matched_matchers: Vec<String>,
    /// Names of extractors that produced at least one value.
    pub extract_names: Vec<String>,
}

impl RunCapture {
    /// Go `Result.HasMatch(name)` — case-insensitive name lookup.
    pub fn has_match(&self, name: &str) -> bool {
        self.matched_matchers
            .iter()
            .any(|m| m.eq_ignore_ascii_case(name))
    }

    /// Go `Result.HasExtract(name)` — case-insensitive name lookup.
    pub fn has_extract(&self, name: &str) -> bool {
        self.extract_names
            .iter()
            .any(|e| e.eq_ignore_ascii_case(name))
    }

    fn record_matcher(&mut self, name: Option<String>) {
        self.matched = true;
        if let Some(n) = name {
            self.matched_matchers.push(n.to_lowercase());
        }
    }
}

/// The core scan engine orchestrating concurrent template execution.
pub struct EngineRunner {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub rate_limit_rps: u32,
    pub client: HttpClient,
    pub enable_code_templates: bool,
    pub headless_enabled: bool,
    pub host_errors: HostErrorsCache,
    pub request_counter: Arc<AtomicUsize>,
    pub is_cancelled: Arc<AtomicBool>,
    pub interactsh: Option<Arc<InteractshClient>>,
    /// Global `-fr` / `--follow-redirects`.
    pub follow_redirects: bool,
    /// Global `-fhr` / `--follow-host-redirects`.
    pub follow_host_redirects: bool,
    /// Global `-dr` / `--disable-redirects` (overrides template settings).
    pub disable_redirects: bool,
    /// Global `-mr` / `--max-redirects` (overrides per-block caps when set).
    pub global_max_redirects: usize,
    /// Global `-spm` / `--stop-at-first-match` flag.
    pub stop_at_first_match: bool,
    /// Registry of loaded templates for resolving workflow step references.
    pub workflow_registry: Option<Arc<WorkflowTemplateRegistry>>,
}

impl EngineRunner {
    pub fn new(
        concurrency: usize,
        timeout_secs: u64,
        rate_limit_rps: u32,
        max_redirects: usize,
        proxy_url: Option<&str>,
        custom_headers: &[(String, String)],
        enable_code_templates: bool,
        headless_enabled: bool,
        max_host_errors: usize,
        retries: u32,
        interactsh: Option<Arc<InteractshClient>>,
    ) -> Self {
        Self {
            concurrency,
            timeout_secs,
            rate_limit_rps,
            client: HttpClient::new(timeout_secs, proxy_url, custom_headers, retries),
            enable_code_templates,
            headless_enabled,
            host_errors: HostErrorsCache::new(max_host_errors),
            request_counter: Arc::new(AtomicUsize::new(0)),
            is_cancelled: Arc::new(AtomicBool::new(false)),
            interactsh,
            follow_redirects: false,
            follow_host_redirects: false,
            disable_redirects: false,
            global_max_redirects: max_redirects,
            stop_at_first_match: false,
            workflow_registry: None,
        }
    }

    /// Provide the registry of loaded templates so workflow steps can resolve
    /// their referenced templates by tag or path at execution time.
    pub fn with_workflow_registry(mut self, registry: Arc<WorkflowTemplateRegistry>) -> Self {
        self.workflow_registry = Some(registry);
        self
    }

    /// Set the global redirect flags (mirrors Go `-fr`/`-fhr`/`-dr`).
    pub fn with_redirect_flags(
        mut self,
        follow_redirects: bool,
        follow_host_redirects: bool,
        disable_redirects: bool,
    ) -> Self {
        self.follow_redirects = follow_redirects;
        self.follow_host_redirects = follow_host_redirects;
        self.disable_redirects = disable_redirects;
        self
    }

    /// Set the global stop-at-first-match flag (mirrors Go `-spm`).
    pub fn with_stop_at_first_match(mut self, enabled: bool) -> Self {
        self.stop_at_first_match = enabled;
        self
    }

    /// Compute the per-request-block HTTP behavior for an http block,
    /// mirroring Go's Compile() + clientpool override order
    /// (http.go:382-390, clientpool.go:432-451): template `redirects` /
    /// global `-fr` enable follow-all; `host-redirects` / `-fhr` narrow it to
    /// same-host; `-dr` disables everything; the global max wins when a
    /// global follow flag is active, otherwise the block cap (0 → default 10).
    pub fn block_request_policy(&self, block: &HttpBlock) -> crate::engine::http_client::RequestPolicy {
        use crate::engine::http_client::{RedirectFlow, RequestPolicy};

        let mut flow = RedirectFlow::DontFollow;
        if block.redirects.unwrap_or(false) || self.follow_redirects {
            flow = RedirectFlow::FollowAll;
        }
        if block.host_redirects.unwrap_or(false) || self.follow_host_redirects {
            flow = RedirectFlow::FollowSameHost;
        }
        let mut max_redirects = block.max_redirects.unwrap_or(0);
        if (self.follow_redirects || self.follow_host_redirects) && self.global_max_redirects > 0 {
            max_redirects = self.global_max_redirects;
        }
        if self.disable_redirects {
            flow = RedirectFlow::DontFollow;
        }
        RequestPolicy::new(flow, max_redirects, block.disable_cookie.unwrap_or(false))
    }

    /// Get the total number of HTTP requests sent so far.
    pub fn request_count(&self) -> usize {
        self.request_counter.load(Ordering::Relaxed)
    }

    /// Signal the engine to cancel all in-flight work.
    pub fn cancel(&self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
    }

    /// Run the full scan pipeline. Returns a channel of findings as they are discovered.
    pub async fn run(
        self: Arc<Self>,
        tasks: Vec<ScanTask>,
        finding_tx: mpsc::Sender<ScanFinding>,
    ) {
        // Start the Interactsh poller if OOB support is enabled.
        let poller_stop = if let Some(ref interactsh) = self.interactsh {
            match interactsh.register().await {
                Ok(()) => {
                    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
                    let poller = Arc::clone(interactsh);
                    let tx = finding_tx.clone();
                    tokio::spawn(async move {
                        poller.poll_loop(tx, stop_rx, INTERACTSH_POLL_SECS).await;
                    });
                    Some(stop_tx)
                }
                Err(e) => {
                    eprintln!("[WRN] Interactsh registration failed: {} (OOB disabled)", e);
                    None
                }
            }
        } else {
            None
        };

        // Set up rate limiter.
        let rate_limiter = if self.rate_limit_rps > 0 {
            let quota =
                Quota::per_second(NonZeroU32::new(self.rate_limit_rps).unwrap_or(NonZeroU32::new(150).unwrap()));
            Some(Arc::new(RateLimiter::direct(quota)))
        } else {
            None
        };

        // Set up work distribution channel.
        let (task_tx, task_rx) = async_channel::bounded::<ScanTask>(self.concurrency * 4);

        // Spawn worker pool.
        let mut worker_handles = Vec::with_capacity(self.concurrency);
        for _ in 0..self.concurrency {
            let worker_self = Arc::clone(&self);
            let worker_rx = task_rx.clone();
            let worker_tx = finding_tx.clone();
            let rl = rate_limiter.clone();

            let handle = tokio::spawn(async move {
                while let Ok(task) = worker_rx.recv().await {
                    if worker_self.is_cancelled.load(Ordering::Relaxed) {
                        break;
                    }

                    // Rate limit before executing.
                    if let Some(ref limiter) = rl {
                        limiter.until_ready().await;
                    }

                    worker_self.execute_task(task, &worker_tx).await;
                }
            });
            worker_handles.push(handle);
        }

        // Drop the receiver clone held by the spawning task so workers drain properly.
        drop(task_rx);

        // Producer: feed tasks into the bounded channel.
        let is_cancelled = Arc::clone(&self.is_cancelled);
        tokio::spawn(async move {
            for task in tasks {
                if is_cancelled.load(Ordering::Relaxed) {
                    break;
                }
                if task_tx.send(task).await.is_err() {
                    break;
                }
            }
        });

        // Wait for all workers to complete.
        for handle in worker_handles {
            let _ = handle.await;
        }

        // Shutdown the Interactsh poller: nuclei waits a cooldown period for
        // late interactions before stopping when URLs were generated.
        if let Some(stop_tx) = poller_stop {
            if let Some(ref interactsh) = self.interactsh {
                if interactsh.generated_any() {
                    tokio::time::sleep(std::time::Duration::from_secs(
                        INTERACTSH_COOLDOWN_SECS,
                    ))
                    .await;
                }
            }
            let _ = stop_tx.send(true);
            if let Some(ref interactsh) = self.interactsh {
                interactsh.deregister().await;
            }
        }
    }

    /// Run the clustered scan pipeline: for each cluster, send one HTTP request
    /// and evaluate every template in the cluster against the shared response.
    /// This is Go's `ClusterExecuter.Execute` equivalent.
    pub async fn run_clustered(
        self: Arc<Self>,
        clusters: Vec<crate::engine::clustering::ClusteredTask>,
        finding_tx: mpsc::Sender<ScanFinding>,
    ) {
        // Start the Interactsh poller if OOB support is enabled.
        let poller_stop = if let Some(ref interactsh) = self.interactsh {
            match interactsh.register().await {
                Ok(()) => {
                    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
                    let poller = Arc::clone(interactsh);
                    let tx = finding_tx.clone();
                    tokio::spawn(async move {
                        poller.poll_loop(tx, stop_rx, INTERACTSH_POLL_SECS).await;
                    });
                    Some(stop_tx)
                }
                Err(e) => {
                    eprintln!("[WRN] Interactsh registration failed: {} (OOB disabled)", e);
                    None
                }
            }
        } else {
            None
        };

        // Set up rate limiter.
        let rate_limiter = if self.rate_limit_rps > 0 {
            let quota = Quota::per_second(
                NonZeroU32::new(self.rate_limit_rps).unwrap_or(NonZeroU32::new(150).unwrap()),
            );
            Some(Arc::new(RateLimiter::direct(quota)))
        } else {
            None
        };

        let (task_tx, task_rx) =
            async_channel::bounded::<crate::engine::clustering::ClusteredTask>(self.concurrency * 4);

        let mut worker_handles = Vec::with_capacity(self.concurrency);
        for _ in 0..self.concurrency {
            let worker_self = Arc::clone(&self);
            let worker_rx = task_rx.clone();
            let worker_tx = finding_tx.clone();
            let rl = rate_limiter.clone();
            let handle = tokio::spawn(async move {
                while let Ok(cluster) = worker_rx.recv().await {
                    if worker_self.is_cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Some(ref limiter) = rl {
                        limiter.until_ready().await;
                    }
                    worker_self.execute_clustered(cluster, &worker_tx).await;
                }
            });
            worker_handles.push(handle);
        }
        drop(task_rx);

        let is_cancelled = Arc::clone(&self.is_cancelled);
        tokio::spawn(async move {
            for cluster in clusters {
                if is_cancelled.load(Ordering::Relaxed) {
                    break;
                }
                if task_tx.send(cluster).await.is_err() {
                    break;
                }
            }
        });

        for handle in worker_handles {
            let _ = handle.await;
        }

        // Shutdown the Interactsh poller.
        if let Some(stop_tx) = poller_stop {
            if let Some(ref interactsh) = self.interactsh {
                if interactsh.generated_any() {
                    tokio::time::sleep(std::time::Duration::from_secs(INTERACTSH_COOLDOWN_SECS))
                        .await;
                }
            }
            let _ = stop_tx.send(true);
            if let Some(ref interactsh) = self.interactsh {
                interactsh.deregister().await;
            }
        }
    }

    /// Execute a cluster: send the shared HTTP request once, then evaluate
    /// every template in the cluster against the single response.
    async fn execute_clustered(
        &self,
        cluster: crate::engine::clustering::ClusteredTask,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        use crate::engine::extractor::ExtractorEngine;
        use crate::engine::runner::helpers::{has_unresolved_variables, interpolate_matchers};
        use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};

        if cluster.templates.is_empty() || self.is_cancelled.load(Ordering::Relaxed) {
            return;
        }

        let first_template = match cluster.templates.first() {
            Some(t) => t,
            None => return,
        };
        let http_block = match first_template.http.first() {
            Some(b) => b,
            None => return,
        };

        // Build the shared request using the existing helper, which handles
        // path interpolation against {{BaseURL}} and the target URL.
        let empty_vars = HashMap::new();
        let specs = helpers::build_http_requests(http_block, &cluster.target, &empty_vars);
        let req_spec = match specs.into_iter().next() {
            Some(s) => s,
            None => return,
        };

        // Check for unresolved variables.
        match &req_spec {
            helpers::RequestSpec::Standard { url, body, .. } => {
                if has_unresolved_variables(url)
                    || body.as_ref().map_or(false, |b| has_unresolved_variables(b))
                {
                    return;
                }
            }
            helpers::RequestSpec::Raw(raw) => {
                if has_unresolved_variables(raw) {
                    return;
                }
            }
        }

        self.request_counter.fetch_add(1, Ordering::Relaxed);
        let started = std::time::Instant::now();

        let Some(response) = self.send_http_one(http_block, &cluster.target, &req_spec).await
        else {
            // Request failed — record errors for all templates in the cluster.
            for _t in &cluster.templates {
                if self.host_errors.record_error(&cluster.target).await {
                    eprintln!(
                        "[WRN] Too many errors for host {} — dropping it",
                        cluster.target
                    );
                }
            }
            return;
        };

        let _ = self.host_errors.record_success(&cluster.target).await;
        let duration_secs = started.elapsed().as_secs_f64();

        let matched_url = match &req_spec {
            helpers::RequestSpec::Standard { url, .. } => url.clone(),
            helpers::RequestSpec::Raw(_) => cluster.target.clone(),
        };

        // Evaluate each template's matchers against the shared response.
        for template in &cluster.templates {
            if self.is_cancelled.load(Ordering::Relaxed) {
                return;
            }
            if self.host_errors.is_dropped(&cluster.target).await {
                return;
            }

            let Some(template_block) = template.http.first() else {
                continue;
            };

            let mut extracted_vars: HashMap<String, String> = HashMap::new();

            let new_extractions =
                ExtractorEngine::extract_all(&template_block.extractors, &response);
            extracted_vars.extend(new_extractions);

            if template_block.matchers.is_empty() {
                let finding = ScanFinding {
                    template_id: template.id.clone(),
                    template_name: template.info.name.clone(),
                    severity: template.info.severity.to_lowercase(),
                    matched_url: matched_url.clone(),
                    matched_at: chrono::Utc::now().to_rfc3339(),
                    extracted_results: vec![],
                    protocol: "http".to_string(),
                    matcher_name: None,
                    tags: template.info.tags.clone(),
                };
                let _ = result_tx.send(finding).await;
                continue;
            }

            let eval_resp = EvaluatedResponse {
                status: response.status,
                headers: &response.headers_raw,
                body: &response.body,
                interactsh_protocol: None,
                interactsh_request: None,
                interactsh_response: None,
                duration_secs,
                named_parts: Some(&extracted_vars),
            };

            let condition = template_block.matchers_condition.as_deref().unwrap_or("or");
            let matchers =
                interpolate_matchers(&template_block.matchers, &cluster.target, &extracted_vars);
            let has_non_internal = template_block.matchers.iter().any(|m| !m.internal);

            if has_non_internal && MatcherEngine::evaluate_all(&matchers, condition, &eval_resp) {
                let output_values =
                    ExtractorEngine::extract_output_values(&template_block.extractors, &response);
                let finding = ScanFinding {
                    template_id: template.id.clone(),
                    template_name: template.info.name.clone(),
                    severity: template.info.severity.to_lowercase(),
                    matched_url: matched_url.clone(),
                    matched_at: chrono::Utc::now().to_rfc3339(),
                    extracted_results: output_values,
                    protocol: "http".to_string(),
                    matcher_name: MatcherEngine::matched_matcher_name(
                        &matchers,
                        condition,
                        &eval_resp,
                    ),
                    tags: template.info.tags.clone(),
                };
                let _ = result_tx.send(finding).await;
            }
        }
    }

    /// Execute a single scan task across all supported protocol blocks.
    pub async fn execute_task(&self, task: ScanTask, result_tx: &mpsc::Sender<ScanFinding>) {
        let target = &task.target;
        if self.host_errors.is_dropped(target).await {
            return;
        }

        let template = &task.template;
        let mut extracted_vars: HashMap<String, String> = HashMap::new();

        // `{{randstr}}` is pinned per template execution (nuclei semantics) so
        // the same value correlates across requests and matchers.
        let randstr: String = rand::Rng::sample_iter(
            &mut rand::thread_rng(),
            rand::distributions::Alphanumeric,
        )
        .take(8)
        .map(|b| b.to_ascii_lowercase() as char)
        .collect();
        extracted_vars.insert("randstr".to_string(), randstr);

        // Template-level `constants:` are resolved first (Go adds them to the
        // template context before variables are evaluated).
        for (name, value) in &template.constants {
            if let Some(s) = yaml_value_to_string(value) {
                extracted_vars.insert(
                    name.clone(),
                    TemplateDsl::interpolate(&s, target, &HashMap::new()),
                );
            }
        }

        // Template-level `variables:` are resolved once per execution and are
        // available to all requests (extracted values can override them later).
        for (name, value) in &template.variables {
            if let Some(s) = yaml_value_to_string(value) {
                extracted_vars.insert(
                    name.clone(),
                    TemplateDsl::interpolate(&s, target, &HashMap::new()),
                );
            }
        }

        // Workflow-controlled templates execute their steps (which reference
        // other templates) instead of running protocol blocks directly.
        if !template.workflows.is_empty() {
            if let Some(registry) = self.workflow_registry.clone() {
                self.execute_workflow(
                    &template.workflows,
                    target,
                    &mut extracted_vars,
                    registry,
                    result_tx,
                )
                .await;
            } else {
                eprintln!(
                    "[WRN] Workflow '{}' loaded without a template registry; skipped",
                    template.id
                );
            }
            return;
        }

        // Flow-controlled templates execute exclusively through their flow
        // logic — blocks are never run unconditionally (nuclei semantics).
        if let Some(flow_expr) = &template.flow {
            if let Some(ast) = crate::engine::flow::parse_flow(flow_expr) {
                self.execute_flow(&ast, template, target, &mut extracted_vars, result_tx)
                    .await;
            }
            // Unparseable flows are skipped as unsupported at load time.
            return;
        }

        self.execute_protocols(template, target, &mut extracted_vars, None, result_tx)
            .await;
    }

    /// Run all protocol blocks of a template against a target. When `capture`
    /// is `Some`, wrapper results (matched matchers, extractor names) are
    /// recorded for workflow gating.
    pub async fn execute_protocols(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        let mut spm_stop = false;

        // 1. DNS Protocol Execution
        self.execute_dns(
            template,
            target,
            extracted_vars,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 2. Network / TCP Protocol Execution
        self.execute_network(
            template,
            target,
            extracted_vars,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 3. SSL / TLS Protocol Execution
        self.execute_ssl(
            template,
            target,
            extracted_vars,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 4. WHOIS Protocol Execution
        self.execute_whois(
            template,
            target,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 5. File Protocol Execution
        self.execute_file(
            template,
            target,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 6. Code Execution Protocol
        self.execute_code(
            template,
            target,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 7. WebSocket Protocol Execution
        self.execute_websocket(
            template,
            target,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 8. Headless Browser Protocol Execution
        self.execute_headless(
            template,
            target,
            extracted_vars,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 9. JavaScript Protocol Execution
        self.execute_js(
            template,
            target,
            extracted_vars,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
        if spm_stop {
            return;
        }

        // 10. HTTP Request Blocks & Parameter Fuzzing
        self.execute_http(
            template,
            target,
            extracted_vars,
            capture.as_deref_mut(),
            &mut spm_stop,
            result_tx,
        )
        .await;
    }

    /// Replace `{{interactsh-url}}` markers with freshly generated correlation
    /// URLs. Returns the substituted text and the URLs generated.
    pub async fn substitute_interactsh(&self, text: &str) -> (String, Vec<String>) {
        const MARKER: &str = "{{interactsh-url}}";
        let Some(client) = self.interactsh.as_ref() else {
            return (text.to_string(), Vec::new());
        };
        if !text.contains(MARKER) {
            return (text.to_string(), Vec::new());
        }

        let mut out = String::with_capacity(text.len());
        let mut urls = Vec::new();
        let mut rest = text;
        while let Some(pos) = rest.find(MARKER) {
            out.push_str(&rest[..pos]);
            match client.generate_url().await {
                Ok(url) => {
                    urls.push(url.clone());
                    out.push_str(&url);
                }
                Err(_) => {
                    out.push_str(MARKER);
                }
            }
            rest = &rest[pos + MARKER.len()..];
        }
        out.push_str(rest);
        (out, urls)
    }

    /// Store pending-request contexts for generated correlation URLs so the
    /// poller can match interactions against this block's matchers.
    pub async fn register_interactsh_requests(
        &self,
        template: &NucleiTemplate,
        block: &HttpBlock,
        matched_url: String,
        response: &HttpResponse,
        urls: &[String],
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        let Some(client) = self.interactsh.as_ref() else {
            return;
        };
        if urls.is_empty() {
            return;
        }

        let pending = Arc::new(PendingRequest {
            template_id: template.id.clone(),
            template_name: template.info.name.clone(),
            severity: template.info.severity.to_lowercase(),
            tags: template.info.tags.clone(),
            matched_url,
            status: response.status,
            headers: response.headers_raw.clone(),
            body: response.body.clone(),
            matchers_condition: block
                .matchers_condition
                .clone()
                .unwrap_or_else(|| "or".to_string()),
            matchers: block.matchers.clone(),
            extractors: block.extractors.clone(),
        });

        for url in urls {
            let early = client.add_request(url, Arc::clone(&pending)).await;
            for interaction in early {
                if let Some(finding) = evaluate_interaction(&pending, &interaction) {
                    let _ = result_tx.send(finding).await;
                }
            }
        }
    }
}
