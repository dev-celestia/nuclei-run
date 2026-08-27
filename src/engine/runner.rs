use crate::engine::code_client::CodeClient;
use crate::engine::dns_client::DnsClient;
use crate::engine::dsl::TemplateDsl;
use crate::engine::extractor::ExtractorEngine;
use crate::engine::file_client::FileClient;
use crate::engine::flow::FlowNode;
use crate::engine::fuzzing::FuzzingEngine;
use crate::engine::headless_client::HeadlessClient;
use crate::engine::host_errors::HostErrorsCache;
use crate::engine::http_client::{HttpClient, HttpResponse};
use crate::engine::interactsh::{evaluate_interaction, InteractshClient, PendingRequest};
use crate::engine::js_client::JavaScriptClient;
use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};
use crate::engine::network_client::NetworkClient;
use crate::engine::ssl_client::SslClient;
use crate::engine::websocket_client::WebSocketClient;
use crate::engine::whois_client::WhoisClient;
use crate::models::result::ScanFinding;
use crate::models::template::{CodeBlock, DnsBlock, HttpBlock, NetworkBlock, NucleiTemplate, SslBlock};
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Interactsh poll cadence and the post-scan cooldown applied before stopping
/// the poller. The cooldown exceeds one poll interval so that a final poll
/// reliably runs after the last request is registered.
const INTERACTSH_POLL_SECS: u64 = 5;
const INTERACTSH_COOLDOWN_SECS: u64 = INTERACTSH_POLL_SECS + 2;

/// Check if a string still contains unresolved Nuclei template variables.
fn has_unresolved_variables(s: &str) -> bool {
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        if let Some(end) = rest[start..].find("}}") {
            let inner = &rest[start + 2..start + end];
            // Skip empty braces and known URL-safe patterns.
            if !inner.is_empty() && !inner.contains("http") {
                return true;
            }
            rest = &rest[start + end + 2..];
        } else {
            break;
        }
    }
    false
}

/// A unit of work: one target URL × one template.
pub struct ScanTask {
    pub target: String,
    pub template: Arc<NucleiTemplate>,
}

/// The core scan engine orchestrating concurrent template execution.
pub struct EngineRunner {
    concurrency: usize,
    timeout_secs: u64,
    rate_limit_rps: u32,
    client: HttpClient,
    enable_code_templates: bool,
    headless_enabled: bool,
    host_errors: HostErrorsCache,
    request_counter: Arc<AtomicUsize>,
    is_cancelled: Arc<AtomicBool>,
    interactsh: Option<Arc<InteractshClient>>,
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
        interactsh: Option<Arc<InteractshClient>>,
    ) -> Self {
        Self {
            concurrency,
            timeout_secs,
            rate_limit_rps,
            client: HttpClient::new(timeout_secs, max_redirects, proxy_url, custom_headers),
            enable_code_templates,
            headless_enabled,
            host_errors: HostErrorsCache::new(max_host_errors),
            request_counter: Arc::new(AtomicUsize::new(0)),
            is_cancelled: Arc::new(AtomicBool::new(false)),
            interactsh,
        }
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

    /// Execute a single scan task across all supported protocol blocks.
    async fn execute_task(&self, task: ScanTask, result_tx: &mpsc::Sender<ScanFinding>) {
        let target = &task.target;
        if self.host_errors.is_dropped(target).await {
            return;
        }

        let template = &task.template;
        let mut extracted_vars: HashMap<String, String> = HashMap::new();

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

        // 1. DNS Protocol Execution
        for dns_block in &template.dns {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(dns_resp) = DnsClient::execute(dns_block, target).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &dns_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = dns_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&dns_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: dns_resp.host,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: dns_resp.records,
                        protocol: "dns".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 2. Network / TCP Protocol Execution
        for net_block in &template.network {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(net_resp) = NetworkClient::execute(net_block, target, self.timeout_secs).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &net_resp.body,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = net_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&net_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: net_resp.host,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: if net_block.tls { "tls".to_string() } else { "tcp".to_string() },
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 3. SSL / TLS Protocol Execution
        for ssl_block in &template.ssl {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(ssl_resp) = SslClient::execute(ssl_block, target, self.timeout_secs).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: &ssl_resp.cipher_suite,
                    body: &ssl_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = ssl_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&ssl_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: ssl_resp.address,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![ssl_resp.subject_cn, ssl_resp.fingerprint_sha256],
                        protocol: "ssl".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 4. WHOIS Protocol Execution
        for whois_block in &template.whois {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(whois_resp) = WhoisClient::execute(whois_block, target, self.timeout_secs).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &whois_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = whois_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&whois_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: whois_resp.query,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: "whois".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 5. File Protocol Execution
        for file_block in &template.file {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            let file_responses = FileClient::scan_path(file_block, target);
            for f_resp in file_responses {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: &f_resp.extension,
                    body: &f_resp.content,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = file_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&file_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: f_resp.file_path,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: "file".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 6. Code Execution Protocol
        for code_block in &template.code {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(code_resp) = CodeClient::execute(code_block, target, self.enable_code_templates).await {
                let eval_resp = EvaluatedResponse {
                    status: code_resp.exit_code as u16,
                    headers: &code_resp.stderr,
                    body: &code_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = code_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&code_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: target.to_string(),
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![code_resp.stdout],
                        protocol: "code".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 7. WebSocket Protocol Execution
        for ws_block in &template.websocket {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(ws_resp) = WebSocketClient::execute(ws_block, target, self.timeout_secs).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &ws_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = ws_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&ws_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: ws_resp.url,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: ws_resp.responses,
                        protocol: "websocket".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 8. Headless Browser Protocol Execution — only when --headless is
        // enabled, mirroring nuclei's behavior of skipping headless templates
        // without the headless engine.
        for headless_block in &template.headless {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            if !self.headless_enabled {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(headless_resp) = HeadlessClient::execute(headless_block, target, &extracted_vars)
                .await
            {
                let eval_resp = EvaluatedResponse {
                    status: 200,
                    headers: "",
                    body: &headless_resp.dom_content,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: Some(&headless_resp.data),
                };
                let condition = headless_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&headless_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: headless_resp.url,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: "headless".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 9. JavaScript Protocol Execution — runs before HTTP so the result is
        // available as `javascript_response` to subsequent requests.
        for js_block in &template.javascript {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(js_resp) = JavaScriptClient::execute(js_block, target).await {
                if !js_resp.precondition_met {
                    continue;
                }
                extracted_vars.insert("javascript_response".to_string(), js_resp.output.clone());

                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &js_resp.output,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };
                let condition = js_block.matchers_condition.as_deref().unwrap_or("or");
                let has_non_internal_matchers = js_block.matchers.iter().any(|m| !m.internal);
                if has_non_internal_matchers
                    && MatcherEngine::evaluate_all(&js_block.matchers, condition, &eval_resp)
                {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: target.to_string(),
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![js_resp.output],
                        protocol: "javascript".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 10. HTTP Request Blocks & Parameter Fuzzing
        for http_block in &template.http {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }

            // Determine request mode: raw or path-based.
            let mut requests_to_send = build_http_requests(http_block, target, &extracted_vars);

            // If fuzzing blocks are specified, generate and append mutated fuzz requests
            for fuzz_block in &template.fuzzing {
                let fuzzed = FuzzingEngine::generate(
                    fuzz_block,
                    target,
                    &http_block.headers,
                    http_block.body.as_deref(),
                );
                for f_req in fuzzed {
                    requests_to_send.push(RequestSpec::Standard {
                        method: http_block.method.as_deref().unwrap_or("GET").to_uppercase(),
                        url: f_req.url,
                        headers: f_req.headers,
                        body: f_req.body,
                    });
                }
            }

            let has_matchers = !http_block.matchers.is_empty();
            let has_non_internal_matchers = http_block.matchers.iter().any(|m| !m.internal);

            // Substitute interactsh markers and track generated URLs per request.
            let mut interactsh_urls_per_request: Vec<Vec<String>> =
                Vec::with_capacity(requests_to_send.len());
            for spec in requests_to_send.iter_mut() {
                let urls = match spec {
                    RequestSpec::Raw(raw) => {
                        let (substituted, urls) = self.substitute_interactsh(raw).await;
                        *raw = substituted;
                        urls
                    }
                    RequestSpec::Standard { url, headers, body, .. } => {
                        let mut urls = Vec::new();
                        let (new_url, u) = self.substitute_interactsh(url).await;
                        urls.extend(u);
                        *url = new_url;
                        for value in headers.values_mut() {
                            let (new_value, u) = self.substitute_interactsh(value).await;
                            urls.extend(u);
                            *value = new_value;
                        }
                        if let Some(b) = body {
                            let (new_body, u) = self.substitute_interactsh(b).await;
                            urls.extend(u);
                            *b = new_body;
                        }
                        urls
                    }
                };
                interactsh_urls_per_request.push(urls);
            }

            for (req_index, req_spec) in requests_to_send.into_iter().enumerate() {
                if self.is_cancelled.load(Ordering::Relaxed) { return; }

                let has_unresolved = match &req_spec {
                    RequestSpec::Standard { url, body, .. } => {
                        has_unresolved_variables(url)
                            || body.as_ref().map_or(false, |b| has_unresolved_variables(b))
                    }
                    RequestSpec::Raw(raw_content) => has_unresolved_variables(raw_content),
                };
                if has_unresolved { continue; }

                self.request_counter.fetch_add(1, Ordering::Relaxed);

                let response: HttpResponse = match req_spec {
                    RequestSpec::Standard {
                        ref method,
                        ref url,
                        ref headers,
                        ref body,
                    } => match self.client.send(method, url, headers, body).await {
                        Ok(r) => {
                            self.host_errors.record_success(target).await;
                            r
                        }
                        Err(_) => {
                            if self.host_errors.record_error(target).await {
                                eprintln!("[WRN] Too many errors for host {} — dropping it", target);
                            }
                            continue;
                        }
                    },
                    RequestSpec::Raw(ref raw_content) => {
                        match self.client.send_raw(raw_content, target).await {
                            Ok(r) => {
                                self.host_errors.record_success(target).await;
                                r
                            }
                            Err(_) => {
                                if self.host_errors.record_error(target).await {
                                    eprintln!("[WRN] Too many errors for host {} — dropping it", target);
                                }
                                continue;
                            }
                        }
                    }
                };

                let new_extractions = ExtractorEngine::extract_all(&http_block.extractors, &response);
                extracted_vars.extend(new_extractions);

                // Register for OOB correlation when this request carried
                // interactsh URLs; early interactions are processed at once.
                if !interactsh_urls_per_request[req_index].is_empty() {
                    let matched_url = match &req_spec {
                        RequestSpec::Standard { url, .. } => url.clone(),
                        RequestSpec::Raw(_) => target.to_string(),
                    };
                    self.register_interactsh_requests(
                        template,
                        http_block,
                        matched_url,
                        &response,
                        &interactsh_urls_per_request[req_index],
                        result_tx,
                    )
                    .await;
                }

                if !has_matchers {
                    break;
                }

                let eval_resp = EvaluatedResponse {
                    status: response.status,
                    headers: &response.headers_raw,
                    body: &response.body,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    named_parts: None,
                };

                let condition = http_block.matchers_condition.as_deref().unwrap_or("or");
                let is_match = MatcherEngine::evaluate_all(&http_block.matchers, condition, &eval_resp);

                if is_match {
                    if has_non_internal_matchers {
                        let output_values = ExtractorEngine::extract_output_values(&http_block.extractors, &response);

                        let matched_url = match &req_spec {
                            RequestSpec::Standard { url, .. } => url.clone(),
                            RequestSpec::Raw(_) => target.to_string(),
                        };

                        let finding = ScanFinding {
                            template_id: template.id.clone(),
                            template_name: template.info.name.clone(),
                            severity: template.info.severity.to_lowercase(),
                            matched_url,
                            matched_at: chrono::Utc::now().to_rfc3339(),
                            extracted_results: output_values,
                            protocol: "http".to_string(),
                            matcher_name: None,
                            tags: template.info.tags.clone(),
                        };

                        let _ = result_tx.send(finding).await;
                    }

                    if !has_non_internal_matchers || http_block.stop_at_first_match {
                        break;
                    }
                }
            }

            // Nuclei executes each http block of a template independently — a
            // non-matching block must not prevent later blocks from running.
        }
    }

    // -----------------------------------------------------------------------
    // Interactsh OOB support
    // -----------------------------------------------------------------------

    /// Replace `{{interactsh-url}}` markers with freshly generated correlation
    /// URLs. Returns the substituted text and the URLs generated. Without an
    /// Interactsh client the text is returned unchanged (the unresolved-marker
    /// guard then skips the request, as before).
    async fn substitute_interactsh(&self, text: &str) -> (String, Vec<String>) {
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
                    // Leave the marker in place; the unresolved-variable guard
                    // skips the request.
                    out.push_str(MARKER);
                }
            }
            rest = &rest[pos + MARKER.len()..];
        }
        out.push_str(rest);
        (out, urls)
    }

    /// Store pending-request contexts for generated correlation URLs so the
    /// poller can match interactions against this block's matchers. Any
    /// interactions that arrived before registration are processed now.
    async fn register_interactsh_requests(
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

    // -----------------------------------------------------------------------
    // Flow-controlled execution
    // -----------------------------------------------------------------------

    /// Evaluate a parsed flow expression and emit a finding if it returns true.
    async fn execute_flow(
        &self,
        node: &FlowNode,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        let mut ctx = FlowMatchContext {
            matched_url: None,
            extracted: Vec::new(),
            protocol: "http".to_string(),
        };

        let matched = self
            .eval_flow_node(node, template, target, extracted_vars, &mut ctx, result_tx)
            .await;
        if !matched {
            return;
        }

        let finding = ScanFinding {
            template_id: template.id.clone(),
            template_name: template.info.name.clone(),
            severity: template.info.severity.to_lowercase(),
            matched_url: ctx.matched_url.unwrap_or_else(|| target.to_string()),
            matched_at: chrono::Utc::now().to_rfc3339(),
            extracted_results: ctx.extracted,
            protocol: ctx.protocol,
            matcher_name: None,
            tags: template.info.tags.clone(),
        };
        let _ = result_tx.send(finding).await;
    }

    /// Recursively evaluate a flow node with short-circuit `&&` / `||`
    /// semantics (mirroring nuclei's goja evaluation).
    fn eval_flow_node<'a>(
        &'a self,
        node: &'a FlowNode,
        template: &'a NucleiTemplate,
        target: &'a str,
        extracted_vars: &'a mut HashMap<String, String>,
        ctx: &'a mut FlowMatchContext,
        result_tx: &'a mpsc::Sender<ScanFinding>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match node {
                FlowNode::Bool(b) => *b,
                FlowNode::Not(n) => {
                    !self
                        .eval_flow_node(n, template, target, extracted_vars, ctx, result_tx)
                        .await
                }
                FlowNode::And(l, r) => {
                    self.eval_flow_node(l, template, target, extracted_vars, ctx, result_tx)
                        .await
                        && self
                            .eval_flow_node(r, template, target, extracted_vars, ctx, result_tx)
                            .await
                }
                FlowNode::Or(l, r) => {
                    self.eval_flow_node(l, template, target, extracted_vars, ctx, result_tx)
                        .await
                        || self
                            .eval_flow_node(r, template, target, extracted_vars, ctx, result_tx)
                            .await
                }
                FlowNode::Http(i) => match template.http.get(*i) {
                    Some(block) => {
                        self.flow_http_block(
                            template,
                            block,
                            target,
                            extracted_vars,
                            ctx,
                            result_tx,
                        )
                        .await
                    }
                    None => false,
                },
                FlowNode::Dns(i) => match template.dns.get(*i) {
                    Some(block) => self.flow_dns_block(block, target, ctx).await,
                    None => false,
                },
                FlowNode::Network(i) => match template.network.get(*i) {
                    Some(block) => self.flow_network_block(block, target, ctx).await,
                    None => false,
                },
                FlowNode::Ssl(i) => match template.ssl.get(*i) {
                    Some(block) => self.flow_ssl_block(block, target, ctx).await,
                    None => false,
                },
                FlowNode::Code(i) => match template.code.get(*i) {
                    Some(block) => self.flow_code_block(block, target, ctx).await,
                    None => false,
                },
            }
        })
    }

    /// Execute one http block referenced by a flow and report whether it matched.
    async fn flow_http_block(
        &self,
        template: &NucleiTemplate,
        block: &HttpBlock,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        ctx: &mut FlowMatchContext,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) -> bool {
        let mut requests_to_send = build_http_requests(block, target, extracted_vars);
        let has_matchers = !block.matchers.is_empty();
        let mut any_response = false;
        let mut matched_any = false;

        // Substitute interactsh markers and track generated URLs per request.
        let mut interactsh_urls_per_request: Vec<Vec<String>> =
            Vec::with_capacity(requests_to_send.len());
        for spec in requests_to_send.iter_mut() {
            let urls = match spec {
                RequestSpec::Raw(raw) => {
                    let (substituted, urls) = self.substitute_interactsh(raw).await;
                    *raw = substituted;
                    urls
                }
                RequestSpec::Standard { url, headers, body, .. } => {
                    let mut urls = Vec::new();
                    let (new_url, u) = self.substitute_interactsh(url).await;
                    urls.extend(u);
                    *url = new_url;
                    for value in headers.values_mut() {
                        let (new_value, u) = self.substitute_interactsh(value).await;
                        urls.extend(u);
                        *value = new_value;
                    }
                    if let Some(b) = body {
                        let (new_body, u) = self.substitute_interactsh(b).await;
                        urls.extend(u);
                        *b = new_body;
                    }
                    urls
                }
            };
            interactsh_urls_per_request.push(urls);
        }

        for (req_index, req_spec) in requests_to_send.into_iter().enumerate() {
            if self.is_cancelled.load(Ordering::Relaxed) {
                break;
            }

            let has_unresolved = match &req_spec {
                RequestSpec::Standard { url, body, .. } => {
                    has_unresolved_variables(url)
                        || body.as_ref().map_or(false, |b| has_unresolved_variables(b))
                }
                RequestSpec::Raw(raw_content) => has_unresolved_variables(raw_content),
            };
            if has_unresolved {
                continue;
            }

            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let response: HttpResponse = match req_spec {
                RequestSpec::Standard {
                    ref method,
                    ref url,
                    ref headers,
                    ref body,
                } => match self.client.send(method, url, headers, body).await {
                    Ok(r) => {
                        self.host_errors.record_success(target).await;
                        r
                    }
                    Err(_) => {
                        if self.host_errors.record_error(target).await {
                            eprintln!("[WRN] Too many errors for host {} — dropping it", target);
                        }
                        continue;
                    }
                },
                RequestSpec::Raw(ref raw_content) => {
                    match self.client.send_raw(raw_content, target).await {
                        Ok(r) => {
                            self.host_errors.record_success(target).await;
                            r
                        }
                        Err(_) => {
                            if self.host_errors.record_error(target).await {
                                eprintln!("[WRN] Too many errors for host {} — dropping it", target);
                            }
                            continue;
                        }
                    }
                }
            };
            any_response = true;

            let new_extractions = ExtractorEngine::extract_all(&block.extractors, &response);
            extracted_vars.extend(new_extractions);

            // Register for OOB correlation when this request carried
            // interactsh URLs; early interactions are processed at once.
            if !interactsh_urls_per_request[req_index].is_empty() {
                let matched_url = match &req_spec {
                    RequestSpec::Standard { url, .. } => url.clone(),
                    RequestSpec::Raw(_) => target.to_string(),
                };
                self.register_interactsh_requests(
                    template,
                    block,
                    matched_url,
                    &response,
                    &interactsh_urls_per_request[req_index],
                    result_tx,
                )
                .await;
            }

            if !has_matchers {
                continue;
            }

            let eval_resp = EvaluatedResponse {
                status: response.status,
                headers: &response.headers_raw,
                body: &response.body,
                interactsh_protocol: None,
                interactsh_request: None,
                interactsh_response: None,
                named_parts: None,
            };

            let condition = block.matchers_condition.as_deref().unwrap_or("or");
            if MatcherEngine::evaluate_all(&block.matchers, condition, &eval_resp) {
                matched_any = true;
                ctx.matched_url = Some(match &req_spec {
                    RequestSpec::Standard { url, .. } => url.clone(),
                    RequestSpec::Raw(_) => target.to_string(),
                });
                ctx.extracted = ExtractorEngine::extract_output_values(&block.extractors, &response);
                ctx.protocol = "http".to_string();
                if block.stop_at_first_match {
                    break;
                }
            }
        }

        // Blocks without matchers match when they executed successfully,
        // mirroring nuclei's unconditional match for matcher-less requests.
        if has_matchers { matched_any } else { any_response }
    }

    /// Execute one dns block referenced by a flow and report whether it matched.
    async fn flow_dns_block(&self, block: &DnsBlock, target: &str, ctx: &mut FlowMatchContext) -> bool {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
        let Ok(dns_resp) = DnsClient::execute(block, target).await else {
            return false;
        };
        if block.matchers.is_empty() {
            ctx.matched_url = Some(dns_resp.host.clone());
            ctx.protocol = "dns".to_string();
            return true;
        }
        let eval_resp = EvaluatedResponse {
            status: 0,
            headers: "",
            body: &dns_resp.raw,
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
        };
        let condition = block.matchers_condition.as_deref().unwrap_or("or");
        let matched = MatcherEngine::evaluate_all(&block.matchers, condition, &eval_resp);
        if matched {
            ctx.matched_url = Some(dns_resp.host.clone());
            ctx.extracted = dns_resp.records.clone();
            ctx.protocol = "dns".to_string();
        }
        matched
    }

    /// Execute one network block referenced by a flow and report whether it matched.
    async fn flow_network_block(
        &self,
        block: &NetworkBlock,
        target: &str,
        ctx: &mut FlowMatchContext,
    ) -> bool {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
        let Ok(net_resp) = NetworkClient::execute(block, target, self.timeout_secs).await else {
            return false;
        };
        if block.matchers.is_empty() {
            ctx.matched_url = Some(net_resp.host.clone());
            ctx.protocol = if block.tls { "tls".to_string() } else { "tcp".to_string() };
            return true;
        }
        let eval_resp = EvaluatedResponse {
            status: 0,
            headers: "",
            body: &net_resp.body,
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
        };
        let condition = block.matchers_condition.as_deref().unwrap_or("or");
        let matched = MatcherEngine::evaluate_all(&block.matchers, condition, &eval_resp);
        if matched {
            ctx.matched_url = Some(net_resp.host.clone());
            ctx.protocol = if block.tls { "tls".to_string() } else { "tcp".to_string() };
        }
        matched
    }

    /// Execute one ssl block referenced by a flow and report whether it matched.
    async fn flow_ssl_block(&self, block: &SslBlock, target: &str, ctx: &mut FlowMatchContext) -> bool {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
        let Ok(ssl_resp) = SslClient::execute(block, target, self.timeout_secs).await else {
            return false;
        };
        if block.matchers.is_empty() {
            ctx.matched_url = Some(ssl_resp.address.clone());
            ctx.protocol = "ssl".to_string();
            return true;
        }
        let eval_resp = EvaluatedResponse {
            status: 0,
            headers: &ssl_resp.cipher_suite,
            body: &ssl_resp.raw,
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
        };
        let condition = block.matchers_condition.as_deref().unwrap_or("or");
        let matched = MatcherEngine::evaluate_all(&block.matchers, condition, &eval_resp);
        if matched {
            ctx.matched_url = Some(ssl_resp.address.clone());
            ctx.extracted = vec![ssl_resp.subject_cn.clone(), ssl_resp.fingerprint_sha256.clone()];
            ctx.protocol = "ssl".to_string();
        }
        matched
    }

    /// Execute one code block referenced by a flow and report whether it matched.
    async fn flow_code_block(&self, block: &CodeBlock, target: &str, ctx: &mut FlowMatchContext) -> bool {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
        let Ok(code_resp) =
            CodeClient::execute(block, target, self.enable_code_templates).await
        else {
            return false;
        };
        if block.matchers.is_empty() {
            ctx.matched_url = Some(target.to_string());
            ctx.protocol = "code".to_string();
            return true;
        }
        let eval_resp = EvaluatedResponse {
            status: code_resp.exit_code as u16,
            headers: &code_resp.stderr,
            body: &code_resp.raw,
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            named_parts: None,
        };
        let condition = block.matchers_condition.as_deref().unwrap_or("or");
        let matched = MatcherEngine::evaluate_all(&block.matchers, condition, &eval_resp);
        if matched {
            ctx.matched_url = Some(target.to_string());
            ctx.extracted = vec![code_resp.stdout.clone()];
            ctx.protocol = "code".to_string();
        }
        matched
    }
}

/// Match context accumulated while evaluating a flow expression.
struct FlowMatchContext {
    matched_url: Option<String>,
    extracted: Vec<String>,
    protocol: String,
}

/// Build the concrete requests (raw or path-based) for one http block.
fn build_http_requests(
    http_block: &HttpBlock,
    target: &str,
    extracted_vars: &HashMap<String, String>,
) -> Vec<RequestSpec> {
    if !http_block.raw.is_empty() {
        http_block
            .raw
            .iter()
            .map(|raw| {
                let interpolated = TemplateDsl::interpolate(raw, target, extracted_vars);
                RequestSpec::Raw(interpolated)
            })
            .collect()
    } else {
        let method = http_block.method.as_deref().unwrap_or("GET").to_uppercase();

        http_block
            .path
            .iter()
            .map(|path| {
                let resolved = TemplateDsl::interpolate(path, target, extracted_vars);
                let url = if resolved.starts_with("http://") || resolved.starts_with("https://") {
                    resolved
                } else {
                    let base = target.trim_end_matches('/');
                    if resolved.starts_with('/') {
                        format!("{}{}", base, resolved)
                    } else {
                        format!("{}/{}", base, resolved)
                    }
                };

                let mut headers = HashMap::new();
                for (k, v) in &http_block.headers {
                    headers.insert(k.clone(), TemplateDsl::interpolate(v, target, extracted_vars));
                }
                let body = http_block
                    .body
                    .as_ref()
                    .map(|b| TemplateDsl::interpolate(b, target, extracted_vars));

                RequestSpec::Standard {
                    method: method.clone(),
                    url,
                    headers,
                    body,
                }
            })
            .collect()
    }
}

/// Internal representation of a request to be sent.
enum RequestSpec {
    Standard {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
    Raw(String),
}

