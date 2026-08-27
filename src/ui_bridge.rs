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
    pub template_paths: Vec<String>,
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

        // Load templates.
        let filter = crate::parser::yaml_loader::TemplateFilter::default();
        let mut templates = Vec::new();
        for path in &config.template_paths {
            let result = crate::parser::yaml_loader::load_templates(path, &filter);
            templates.extend(result.templates);
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

        // Create engine.
        let engine = Arc::new(crate::engine::runner::EngineRunner::new(
            config.concurrency,
            config.timeout_seconds,
            config.rate_limit_rps,
            10,
            None,
            &[],
            false,
            false,
            0,
            None,
        ));

        // Create internal finding channel.
        let (finding_tx, mut finding_rx) = mpsc::channel(500);

        // Start engine.
        let engine_clone = Arc::clone(&engine);
        tokio::spawn(async move {
            engine_clone.run(tasks, finding_tx).await;
        });

        // Forward findings to UI event channel.
        let _cancel_rx = cancel_rx;
        tokio::spawn(async move {
            let start_time = std::time::Instant::now();
            let mut finding_count = 0usize;
            let mut request_count = 0usize;

            while let Some(finding) = finding_rx.recv().await {
                // Handle pause.
                while is_paused.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }

                finding_count += 1;
                request_count += 1;

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

                // Emit progress event.
                let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
                let _ = event_tx
                    .send(ScannerEvent::ProgressUpdate {
                        completed_requests: request_count,
                        total_requests: total_tasks,
                        rps: request_count as f64 / elapsed,
                    })
                    .await;
            }

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
