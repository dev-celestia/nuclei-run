use crate::engine::dsl::TemplateDsl;
use crate::engine::extractor::ExtractorEngine;
use crate::engine::http_client::{HttpClient, HttpResponse};
use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};
use crate::models::result::ScanFinding;
use crate::models::template::NucleiTemplate;
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
    concurrency: usize,
    rate_limit_rps: u32,
    client: HttpClient,
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
    ) -> Self {
        Self {
            concurrency,
            rate_limit_rps,
            client: HttpClient::new(timeout_secs, max_redirects, proxy_url, custom_headers),
            request_counter: Arc::new(AtomicUsize::new(0)),
            is_cancelled: Arc::new(AtomicBool::new(false)),
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
            // Closing the sender causes workers to exit after draining.
        });

        // Wait for all workers to complete.
        for handle in worker_handles {
            let _ = handle.await;
        }
    }

    /// Execute a single scan task (one target × one template with all HTTP blocks).
    async fn execute_task(&self, task: ScanTask, result_tx: &mpsc::Sender<ScanFinding>) {
        let target = &task.target;
        let template = &task.template;

        // Accumulate extracted variables across request blocks (for chaining).
        let mut extracted_vars: HashMap<String, String> = HashMap::new();

        for http_block in &template.http {
            if self.is_cancelled.load(Ordering::Relaxed) {
                return;
            }

            // Determine request mode: raw or path-based.
            let requests_to_send: Vec<RequestSpec> = if !http_block.raw.is_empty() {
                // Raw request mode.
                http_block
                    .raw
                    .iter()
                    .map(|raw| {
                        let interpolated =
                            TemplateDsl::interpolate(raw, target, &extracted_vars);
                        RequestSpec::Raw(interpolated)
                    })
                    .collect()
            } else {
                // Path-based request mode.
                let method = http_block
                    .method
                    .as_deref()
                    .unwrap_or("GET")
                    .to_uppercase();

                http_block
                    .path
                    .iter()
                    .map(|path| {
                        let resolved = TemplateDsl::interpolate(path, target, &extracted_vars);
                        // Build full URL from resolved path.
                        let url = if resolved.starts_with("http://")
                            || resolved.starts_with("https://")
                        {
                            resolved
                        } else {
                            let base = target.trim_end_matches('/');
                            if resolved.starts_with('/') {
                                format!("{}{}", base, resolved)
                            } else {
                                format!("{}/{}", base, resolved)
                            }
                        };

                        // Interpolate headers and body.
                        let mut headers = HashMap::new();
                        for (k, v) in &http_block.headers {
                            headers.insert(
                                k.clone(),
                                TemplateDsl::interpolate(v, target, &extracted_vars),
                            );
                        }
                        let body = http_block
                            .body
                            .as_ref()
                            .map(|b| TemplateDsl::interpolate(b, target, &extracted_vars));

                        RequestSpec::Standard {
                            method: method.clone(),
                            url,
                            headers,
                            body,
                        }
                    })
                    .collect()
            };

            for req_spec in requests_to_send {
                if self.is_cancelled.load(Ordering::Relaxed) {
                    return;
                }

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

                // Run extractors first (for chaining, even before matching).
                let new_extractions =
                    ExtractorEngine::extract_all(&http_block.extractors, &response);
                extracted_vars.extend(new_extractions);

                // Evaluate matchers.
                let eval_resp = EvaluatedResponse {
                    status: response.status,
                    headers: &response.headers_raw,
                    body: &response.body,
                };

                let condition = http_block
                    .matchers_condition
                    .as_deref()
                    .unwrap_or("or");

                let is_vulnerable =
                    MatcherEngine::evaluate_all(&http_block.matchers, condition, &eval_resp);

                if is_vulnerable {
                    // Get output-visible extracted values.
                    let output_values =
                        ExtractorEngine::extract_output_values(&http_block.extractors, &response);

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

                    // If stop-at-first-match, skip remaining paths in this block.
                    if http_block.stop_at_first_match {
                        break;
                    }
                }
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
