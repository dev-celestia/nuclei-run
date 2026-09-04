#![allow(dead_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

// ---------------------------------------------------------------------------
// Event Types
// ---------------------------------------------------------------------------

/// Configuration passed from the UI layer to start a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiScanConfig {
    pub targets: Vec<String>,
    #[serde(default)]
    pub template_paths: Vec<String>,
    #[serde(default)]
    pub raw_templates: Vec<String>,
    pub concurrency: usize,
    pub rate_limit_rps: u32,
    pub timeout_seconds: u64,
}

/// Real-time event emitted from the Rust engine to the UI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "data")]
pub enum ScannerEvent {
    /// Scan has been initialized and is starting execution.
    ScanStarted {
        total_templates: usize,
        total_targets: usize,
    },
    /// Progress update with current completion stats.
    ProgressUpdate {
        completed_requests: usize,
        total_requests: usize,
        rps: f64,
    },
    /// A vulnerability finding was discovered.
    FindingDiscovered(UiFinding),
    /// An error occurred while scanning a specific target.
    ScanError {
        target: String,
        message: String,
    },
    /// Scan has completed.
    ScanCompleted {
        elapsed_millis: u128,
        total_findings: usize,
    },
}

/// Structured finding ready for UI rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiFinding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub matched_url: String,
    pub matched_at: String,
    pub extracted_results: Vec<String>,
}

// ---------------------------------------------------------------------------
// Adapter Trait
// ---------------------------------------------------------------------------

/// Generic pluggable interface for connecting the scan engine to any UI framework.
/// Implementations can target Tauri, egui, iced, WebAssembly, or IPC channels.
#[async_trait]
pub trait UiScannerAdapter: Send + Sync {
    /// Start a scan session. Events will be emitted through the `event_sender`.
    async fn start_scan(
        &self,
        config: UiScanConfig,
        event_sender: mpsc::Sender<ScannerEvent>,
    ) -> Result<(), String>;

    /// Pause the active scan.
    async fn pause_scan(&self) -> Result<(), String>;

    /// Resume a paused scan.
    async fn resume_scan(&self) -> Result<(), String>;

    /// Cancel the scan and drop the worker pool.
    async fn cancel_scan(&self) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Concrete Implementation
// ---------------------------------------------------------------------------

/// Engine controller that manages scan lifecycle and emits events to the UI.
pub struct NucleiUiEngine {
    is_paused: Arc<AtomicBool>,
    cancel_tx: Arc<tokio::sync::Mutex<Option<watch::Sender<bool>>>>,
}

impl NucleiUiEngine {
    pub fn new() -> Self {
        Self {
            is_paused: Arc::new(AtomicBool::new(false)),
            cancel_tx: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

impl Default for NucleiUiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UiScannerAdapter for NucleiUiEngine {
    async fn start_scan(
        &self,
        config: UiScanConfig,
        event_tx: mpsc::Sender<ScannerEvent>,
    ) -> Result<(), String> {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        {
            let mut guard = self.cancel_tx.lock().await;
            *guard = Some(cancel_tx);
        }

        let is_paused = Arc::clone(&self.is_paused);
        is_paused.store(false, Ordering::SeqCst);

        // Load templates from disk paths.
        let filter = crate::parser::yaml_loader::TemplateFilter::default();
        let mut templates = Vec::new();
        for path in &config.template_paths {
            let result = crate::parser::yaml_loader::load_templates(path, &filter);
            templates.extend(result.templates);
        }

        // Load templates from raw in-memory YAML strings.
        for (idx, raw) in config.raw_templates.iter().enumerate() {
            if raw.trim().is_empty() {
                continue;
            }
            match serde_yaml::from_str::<crate::models::template::NucleiTemplate>(raw) {
                Ok(mut t) => {
                    t.source_path = format!("memory://template-{}.yaml", idx + 1).into();
                    templates.push(t);
                }
                Err(e) => {
                    let _ = event_tx
                        .send(ScannerEvent::ScanError {
                            target: format!("memory-template-{}", idx + 1),
                            message: format!("Failed to parse YAML template: {}", e),
                        })
                        .await;
                }
            }
        }

        let total_templates = templates.len();
        let total_targets = config.targets.len();

        // Notify UI: scan started.
        let _ = event_tx
            .send(ScannerEvent::ScanStarted {
                total_templates,
                total_targets,
            })
            .await;

        // Build scan tasks.
        let templates_arc: Vec<Arc<crate::models::template::NucleiTemplate>> =
            templates.into_iter().map(Arc::new).collect();

        let mut tasks = Vec::new();
        for target in &config.targets {
            for template in &templates_arc {
                tasks.push(crate::engine::runner::ScanTask {
                    target: target.clone(),
                    template: Arc::clone(template),
                });
            }
        }

        let total_tasks = tasks.len();

        // Create error reporting channel.
        let (err_tx, mut err_rx) = mpsc::channel::<(String, String)>(500);

        // Create engine.
        let engine = Arc::new(
            crate::engine::runner::EngineRunner::new(
                config.concurrency,
                config.timeout_seconds,
                config.rate_limit_rps,
                10,
                None,
                &[],
                false,
                false,
                50,
                1,
                None,
            )
            .with_error_sender(err_tx),
        );

        // Forward target connection / network errors to UI.
        let event_tx_err = event_tx.clone();
        tokio::spawn(async move {
            let mut last_error_time = std::time::Instant::now();
            let mut err_count = 0usize;
            let mut last_msg = String::new();

            while let Some((target, message)) = err_rx.recv().await {
                err_count += 1;
                let elapsed_ms = last_error_time.elapsed().as_millis();
                // Send first 5 errors immediately, then rate-limit duplicates to 1/sec
                if err_count <= 5 || elapsed_ms >= 1000 || message != last_msg {
                    last_error_time = std::time::Instant::now();
                    last_msg = message.clone();
                    let _ = event_tx_err
                        .send(ScannerEvent::ScanError { target, message })
                        .await;
                }
            }
        });

        // Create internal finding channel.
        let (finding_tx, mut finding_rx) = mpsc::channel(500);

        // Start engine in background task.
        let engine_clone = Arc::clone(&engine);
        let scan_join_handle = tokio::spawn(async move {
            engine_clone.run(tasks, finding_tx).await;
        });

        // Forward findings and progress to UI event channel.
        let _cancel_rx = cancel_rx;
        let engine_for_progress = Arc::clone(&engine);
        let event_tx_clone = event_tx.clone();

        tokio::spawn(async move {
            let start_time = std::time::Instant::now();
            let mut finding_count = 0usize;

            // Spawn background heartbeat ticker for continuous progress updates (every 250ms)
            let is_paused_ticker = Arc::clone(&is_paused);
            let engine_ticker = Arc::clone(&engine_for_progress);
            let event_tx_ticker = event_tx_clone.clone();

            let (ticker_stop_tx, mut ticker_stop_rx) = tokio::sync::watch::channel(false);

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(250));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if *ticker_stop_rx.borrow() {
                                break;
                            }
                            if !is_paused_ticker.load(Ordering::SeqCst) {
                                let completed = engine_ticker.request_count();
                                let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
                                let _ = event_tx_ticker.send(ScannerEvent::ProgressUpdate {
                                    completed_requests: completed.min(total_tasks),
                                    total_requests: total_tasks,
                                    rps: (completed as f64 / elapsed * 10.0).round() / 10.0,
                                }).await;
                            }
                        }
                        _ = ticker_stop_rx.changed() => {
                            break;
                        }
                    }
                }
            });

            // Process discovered findings
            while let Some(finding) = finding_rx.recv().await {
                // Handle pause.
                while is_paused.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }

                finding_count += 1;

                // Emit finding event.
                let _ = event_tx
                    .send(ScannerEvent::FindingDiscovered(UiFinding {
                        template_id: finding.template_id,
                        template_name: finding.template_name,
                        severity: finding.severity,
                        matched_url: finding.matched_url,
                        matched_at: finding.matched_at,
                        extracted_results: finding.extracted_results,
                    }))
                    .await;
            }

            // Wait for engine to finish all remaining tasks
            let _ = scan_join_handle.await;

            // Stop progress ticker
            let _ = ticker_stop_tx.send(true);

            // Final progress update
            let final_completed = engine_for_progress.request_count().max(total_tasks);
            let final_elapsed = start_time.elapsed().as_secs_f64().max(0.1);
            let _ = event_tx
                .send(ScannerEvent::ProgressUpdate {
                    completed_requests: total_tasks,
                    total_requests: total_tasks,
                    rps: (final_completed as f64 / final_elapsed * 10.0).round() / 10.0,
                })
                .await;

            // Emit completion event.
            let _ = event_tx
                .send(ScannerEvent::ScanCompleted {
                    elapsed_millis: start_time.elapsed().as_millis(),
                    total_findings: finding_count,
                })
                .await;
        });

        Ok(())
    }

    async fn pause_scan(&self) -> Result<(), String> {
        self.is_paused.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn resume_scan(&self) -> Result<(), String> {
        self.is_paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn cancel_scan(&self) -> Result<(), String> {
        let guard = self.cancel_tx.lock().await;
        if let Some(tx) = &*guard {
            let _ = tx.send(true);
        }
        Ok(())
    }
}
