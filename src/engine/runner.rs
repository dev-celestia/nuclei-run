use crate::engine::code_client::CodeClient;
use crate::engine::dns_client::DnsClient;
use crate::engine::dsl::TemplateDsl;
use crate::engine::extractor::ExtractorEngine;
use crate::engine::file_client::FileClient;
use crate::engine::fuzzing::FuzzingEngine;
use crate::engine::headless_client::HeadlessClient;
use crate::engine::host_errors::HostErrorsCache;
use crate::engine::http_client::{HttpClient, HttpResponse};
use crate::engine::js_client::JavaScriptClient;
use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};
use crate::engine::network_client::NetworkClient;
use crate::engine::ssl_client::SslClient;
use crate::engine::websocket_client::WebSocketClient;
use crate::engine::whois_client::WhoisClient;
use crate::models::result::ScanFinding;
use crate::models::template::NucleiTemplate;
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

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
    host_errors: HostErrorsCache,
    request_counter: Arc<AtomicUsize>,
    is_cancelled: Arc<AtomicBool>,
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
        max_host_errors: usize,
    ) -> Self {
        Self {
            concurrency,
            timeout_secs,
            rate_limit_rps,
            client: HttpClient::new(timeout_secs, max_redirects, proxy_url, custom_headers),
            enable_code_templates,
            host_errors: HostErrorsCache::new(max_host_errors),
            request_counter: Arc::new(AtomicUsize::new(0)),
            is_cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the total number of HTTP requests sent so far.
    pub fn request_count(&self) -> usize {
        self.request_counter.load(Ordering::Relaxed)
    }

    /// Signal the engine to cancel all in-flight work.
    #[allow(dead_code)]
    pub fn cancel(&self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
    }

    /// Run the full scan pipeline. Returns a channel of findings as they are discovered.
    pub async fn run(
        self: Arc<Self>,
        tasks: Vec<ScanTask>,
        finding_tx: mpsc::Sender<ScanFinding>,
    ) {
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
    }

    /// Execute a single scan task across all supported protocol blocks.
    async fn execute_task(&self, task: ScanTask, result_tx: &mpsc::Sender<ScanFinding>) {
        let target = &task.target;
        if self.host_errors.is_dropped(target).await {
            return;
        }

        let template = &task.template;
        let mut extracted_vars: HashMap<String, String> = HashMap::new();

        // 1. DNS Protocol Execution
        for dns_block in &template.dns {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(dns_resp) = DnsClient::execute(dns_block, target).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &dns_resp.raw,
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

        // 8. Headless Browser Protocol Execution
        for headless_block in &template.headless {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(headless_resp) = HeadlessClient::execute(headless_block, target, self.timeout_secs).await {
                let eval_resp = EvaluatedResponse {
                    status: 200,
                    headers: "",
                    body: &headless_resp.raw,
                };
                let condition = headless_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&headless_block.matchers, condition, &eval_resp) {
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: headless_resp.url,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: headless_resp.script_results,
                        protocol: "headless".to_string(),
                        matcher_name: None,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }

        // 9. JavaScript Protocol Execution
        for js_block in &template.javascript {
            if self.is_cancelled.load(Ordering::Relaxed) { return; }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            if let Ok(js_resp) = JavaScriptClient::execute(js_block, target).await {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &js_resp.raw,
                };
                let condition = js_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&js_block.matchers, condition, &eval_resp) {
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
            let mut requests_to_send: Vec<RequestSpec> = if !http_block.raw.is_empty() {
                http_block
                    .raw
                    .iter()
                    .map(|raw| {
                        let interpolated = TemplateDsl::interpolate(raw, target, &extracted_vars);
                        RequestSpec::Raw(interpolated)
                    })
                    .collect()
            } else {
                let method = http_block.method.as_deref().unwrap_or("GET").to_uppercase();

                http_block
                    .path
                    .iter()
                    .map(|path| {
                        let resolved = TemplateDsl::interpolate(path, target, &extracted_vars);
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
                            headers.insert(k.clone(), TemplateDsl::interpolate(v, target, &extracted_vars));
                        }
                        let body = http_block.body.as_ref().map(|b| TemplateDsl::interpolate(b, target, &extracted_vars));

                        RequestSpec::Standard {
                            method: method.clone(),
                            url,
                            headers,
                            body,
                        }
                    })
                    .collect()
            };

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

            let mut block_matched = false;
            let has_matchers = !http_block.matchers.is_empty();
            let has_non_internal_matchers = http_block.matchers.iter().any(|m| !m.internal);

            for req_spec in requests_to_send {
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
                        Ok(r) => r,
                        Err(_) => continue,
                    },
                    RequestSpec::Raw(ref raw_content) => {
                        match self.client.send_raw(raw_content, target).await {
                            Ok(r) => r,
                            Err(_) => continue,
                        }
                    }
                };

                let new_extractions = ExtractorEngine::extract_all(&http_block.extractors, &response);
                extracted_vars.extend(new_extractions);

                if !has_matchers {
                    block_matched = true;
                    break;
                }

                let eval_resp = EvaluatedResponse {
                    status: response.status,
                    headers: &response.headers_raw,
                    body: &response.body,
                };

                let condition = http_block.matchers_condition.as_deref().unwrap_or("or");
                let is_match = MatcherEngine::evaluate_all(&http_block.matchers, condition, &eval_resp);

                if is_match {
                    block_matched = true;

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

            if has_matchers && !block_matched {
                return;
            }
        }
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

