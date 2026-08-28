pub mod flow_exec;
pub mod helpers;
pub mod protocols;

#[allow(unused_imports)]
pub use helpers::{has_unresolved_variables, interpolate_matchers, yaml_value_to_string, RequestSpec};

use crate::engine::dsl::TemplateDsl;
use crate::engine::host_errors::HostErrorsCache;
use crate::engine::http_client::{HttpClient, HttpResponse};
use crate::engine::interactsh::{evaluate_interaction, InteractshClient, PendingRequest};
use crate::engine::runner::helpers::{INTERACTSH_COOLDOWN_SECS, INTERACTSH_POLL_SECS};
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
            client: HttpClient::new(timeout_secs, max_redirects, proxy_url, custom_headers, retries),
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
        self.execute_dns(template, target, result_tx).await;

        // 2. Network / TCP Protocol Execution
        self.execute_network(template, target, result_tx).await;

        // 3. SSL / TLS Protocol Execution
        self.execute_ssl(template, target, result_tx).await;

        // 4. WHOIS Protocol Execution
        self.execute_whois(template, target, result_tx).await;

        // 5. File Protocol Execution
        self.execute_file(template, target, result_tx).await;

        // 6. Code Execution Protocol
        self.execute_code(template, target, result_tx).await;

        // 7. WebSocket Protocol Execution
        self.execute_websocket(template, target, result_tx).await;

        // 8. Headless Browser Protocol Execution
        self.execute_headless(template, target, &extracted_vars, result_tx).await;

        // 9. JavaScript Protocol Execution
        self.execute_js(template, target, &mut extracted_vars, result_tx).await;

        // 10. HTTP Request Blocks & Parameter Fuzzing
        self.execute_http(template, target, &mut extracted_vars, result_tx).await;
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
