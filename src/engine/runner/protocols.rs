use crate::engine::code_client::CodeClient;
use crate::engine::dns_client::DnsClient;
use crate::engine::extractor::ExtractorEngine;
use crate::engine::file_client::FileClient;
use crate::engine::fuzzing::FuzzingEngine;
use crate::engine::headless_client::HeadlessClient;
use crate::engine::http_client::HttpResponse;
use crate::engine::js_client::JavaScriptClient;
use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};
use crate::engine::network_client::NetworkClient;
use crate::engine::runner::helpers::{
    build_http_requests, has_unresolved_variables, interpolate_matchers, RequestSpec,
};
use crate::engine::runner::{EngineRunner, RunCapture};
use crate::engine::ssl_client::SslClient;
use crate::engine::websocket_client::WebSocketClient;
use crate::engine::whois_client::WhoisClient;
use crate::models::result::ScanFinding;
use crate::models::template::{HttpBlock, NucleiTemplate, TemplateExtractor};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::mpsc;

/// Record which workflow-named extractors produced at least one value, using
/// Go's effective extractor name (`name` or the extractor type). The merged
/// extraction map keeps the extractor name as a key when it produced values.
fn capture_extract_names(
    capture: &mut RunCapture,
    extractors: &[TemplateExtractor],
    extracted: &HashMap<String, String>,
) {
    for ext in extractors {
        let eff = ext
            .name
            .clone()
            .unwrap_or_else(|| ext.extractor_type.clone());
        if extracted.contains_key(&eff) {
            capture.extract_names.push(eff.to_lowercase());
        }
    }
}

impl EngineRunner {
    pub async fn execute_dns(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for dns_block in &template.dns {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(dns_resp) =
                DnsClient::execute(dns_block, target, extracted_vars, self.timeout_secs).await
            {
                let duration_secs = started.elapsed().as_secs_f64();

                // Go-parity variable map: rcode/sections/record-type keys
                // serve both `part:` lookups and DSL evaluation.
                let mut vars = extracted_vars.clone();
                vars.extend(dns_resp.variables());

                let new_extractions = ExtractorEngine::extract_from_parts(
                    &dns_block.extractors,
                    &vars,
                    "raw",
                    duration_secs,
                );
                if let Some(c) = capture.as_deref_mut() {
                    capture_extract_names(c, &dns_block.extractors, &new_extractions);
                }
                extracted_vars.extend(new_extractions);

                if dns_block.matchers.is_empty() {
                    continue;
                }

                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &dns_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs,
                    named_parts: Some(&vars),
                };
                let condition = dns_block.matchers_condition.as_deref().unwrap_or("or");
                let matchers = interpolate_matchers(&dns_block.matchers, target, extracted_vars);
                let has_non_internal_matchers = dns_block.matchers.iter().any(|m| !m.internal);
                if has_non_internal_matchers
                    && MatcherEngine::evaluate_all(&matchers, condition, &eval_resp)
                {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let output_values = ExtractorEngine::extract_output_from_parts(
                        &dns_block.extractors,
                        &vars,
                        "raw",
                        duration_secs,
                    );
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: dns_resp.host,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: output_values,
                        protocol: "dns".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_network(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for net_block in &template.network {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(net_resp) =
                NetworkClient::execute(net_block, target, extracted_vars, self.timeout_secs).await
            {
                let duration_secs = started.elapsed().as_secs_f64();

                // Go-parity variable map: data (final read, default part),
                // raw, request, ip, and named input buffers.
                let mut vars = extracted_vars.clone();
                vars.extend(net_resp.variables());

                let new_extractions = ExtractorEngine::extract_from_parts(
                    &net_block.extractors,
                    &vars,
                    "data",
                    duration_secs,
                );
                if let Some(c) = capture.as_deref_mut() {
                    capture_extract_names(c, &net_block.extractors, &new_extractions);
                }
                extracted_vars.extend(new_extractions);

                if net_block.matchers.is_empty() {
                    continue;
                }

                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &net_resp.data,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs,
                    named_parts: Some(&vars),
                };
                let condition = net_block.matchers_condition.as_deref().unwrap_or("or");
                let matchers = interpolate_matchers(&net_block.matchers, target, extracted_vars);
                let has_non_internal_matchers = net_block.matchers.iter().any(|m| !m.internal);
                if has_non_internal_matchers
                    && MatcherEngine::evaluate_all(&matchers, condition, &eval_resp)
                {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let output_values = ExtractorEngine::extract_output_from_parts(
                        &net_block.extractors,
                        &vars,
                        "data",
                        duration_secs,
                    );
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: net_resp.address,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: output_values,
                        protocol: "network".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_ssl(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for ssl_block in &template.ssl {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(ssl_resp) =
                SslClient::execute(ssl_block, target, extracted_vars, self.timeout_secs).await
            {
                let duration_secs = started.elapsed().as_secs_f64();

                // Go-parity variable map: tlsx fields by json tag plus the
                // full `response` JSON (the default match part). `duration` is
                // measured here (Go `data["duration"] = duration.Seconds()`).
                let mut vars = extracted_vars.clone();
                vars.extend(ssl_resp.variables());
                vars.insert("duration".to_string(), duration_secs.to_string());

                let new_extractions = ExtractorEngine::extract_from_parts(
                    &ssl_block.extractors,
                    &vars,
                    "response",
                    duration_secs,
                );
                if let Some(c) = capture.as_deref_mut() {
                    capture_extract_names(c, &ssl_block.extractors, &new_extractions);
                }
                extracted_vars.extend(new_extractions);

                if ssl_block.matchers.is_empty() {
                    continue;
                }

                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &ssl_resp.response,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs,
                    named_parts: Some(&vars),
                };
                let condition = ssl_block.matchers_condition.as_deref().unwrap_or("or");
                let matchers = interpolate_matchers(&ssl_block.matchers, target, extracted_vars);
                let has_non_internal_matchers = ssl_block.matchers.iter().any(|m| !m.internal);
                if has_non_internal_matchers
                    && MatcherEngine::evaluate_all(&matchers, condition, &eval_resp)
                {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let output_values = ExtractorEngine::extract_output_from_parts(
                        &ssl_block.extractors,
                        &vars,
                        "response",
                        duration_secs,
                    );
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: ssl_resp.matched,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: output_values,
                        protocol: "ssl".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_whois(
        &self,
        template: &NucleiTemplate,
        target: &str,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for whois_block in &template.whois {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(whois_resp) =
                WhoisClient::execute(whois_block, target, self.timeout_secs).await
            {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &whois_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs: started.elapsed().as_secs_f64(),
                    named_parts: None,
                };
                let condition = whois_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&whois_block.matchers, condition, &eval_resp) {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &whois_block.matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: whois_resp.query,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: "whois".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &whois_block.matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_file(
        &self,
        template: &NucleiTemplate,
        target: &str,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for file_block in &template.file {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            let started = Instant::now();
            let file_responses = FileClient::scan_path(file_block, target);
            for f_resp in file_responses {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: &f_resp.extension,
                    body: &f_resp.content,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs: started.elapsed().as_secs_f64(),
                    named_parts: None,
                };
                let condition = file_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&file_block.matchers, condition, &eval_resp) {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &file_block.matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: f_resp.file_path,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: "file".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &file_block.matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_code(
        &self,
        template: &NucleiTemplate,
        target: &str,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for code_block in &template.code {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(code_resp) =
                CodeClient::execute(code_block, target, self.enable_code_templates).await
            {
                let eval_resp = EvaluatedResponse {
                    status: code_resp.exit_code as u16,
                    headers: &code_resp.stderr,
                    body: &code_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs: started.elapsed().as_secs_f64(),
                    named_parts: None,
                };
                let condition = code_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&code_block.matchers, condition, &eval_resp) {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &code_block.matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: target.to_string(),
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![code_resp.stdout],
                        protocol: "code".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &code_block.matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_websocket(
        &self,
        template: &NucleiTemplate,
        target: &str,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for ws_block in &template.websocket {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(ws_resp) = WebSocketClient::execute(ws_block, target, self.timeout_secs).await
            {
                let eval_resp = EvaluatedResponse {
                    status: 0,
                    headers: "",
                    body: &ws_resp.raw,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs: started.elapsed().as_secs_f64(),
                    named_parts: None,
                };
                let condition = ws_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&ws_block.matchers, condition, &eval_resp) {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &ws_block.matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: ws_resp.url,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: ws_resp.responses,
                        protocol: "websocket".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &ws_block.matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_headless(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for headless_block in &template.headless {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            if !self.headless_enabled {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
            if let Ok(headless_resp) =
                HeadlessClient::execute(headless_block, target, extracted_vars).await
            {
                let eval_resp = EvaluatedResponse {
                    status: headless_resp.status,
                    headers: &headless_resp.headers,
                    body: &headless_resp.dom_content,
                    interactsh_protocol: None,
                    interactsh_request: None,
                    interactsh_response: None,
                    duration_secs: started.elapsed().as_secs_f64(),
                    named_parts: Some(&headless_resp.data),
                };
                let condition = headless_block.matchers_condition.as_deref().unwrap_or("or");
                if MatcherEngine::evaluate_all(&headless_block.matchers, condition, &eval_resp) {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &headless_block.matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: headless_resp.url,
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![],
                        protocol: "headless".to_string(),
                        matcher_name: MatcherEngine::matched_matcher_name(
                            &headless_block.matchers,
                            condition,
                            &eval_resp,
                        ),
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                    if self.stop_at_first_match {
                        *spm_stop = true;
                        return;
                    }
                }
            }
        }
    }

    pub async fn execute_js(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for js_block in &template.javascript {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }
            self.request_counter.fetch_add(1, Ordering::Relaxed);

            let started = Instant::now();
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
                    duration_secs: started.elapsed().as_secs_f64(),
                    named_parts: None,
                };
                let condition = js_block.matchers_condition.as_deref().unwrap_or("or");
                let has_non_internal_matchers = js_block.matchers.iter().any(|m| !m.internal);
                if has_non_internal_matchers
                    && MatcherEngine::evaluate_all(&js_block.matchers, condition, &eval_resp)
                {
                    if let Some(c) = capture.as_deref_mut() {
                        c.record_matcher(MatcherEngine::matched_matcher_name(
                            &js_block.matchers,
                            condition,
                            &eval_resp,
                        ));
                    }
                    // Compute the matcher name before moving `js_resp.output` into
                    // the finding (eval_resp borrows it for DSL matching).
                    let matcher_name = MatcherEngine::matched_matcher_name(
                        &js_block.matchers,
                        condition,
                        &eval_resp,
                    );
                    let finding = ScanFinding {
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        severity: template.info.severity.to_lowercase(),
                        matched_url: target.to_string(),
                        matched_at: chrono::Utc::now().to_rfc3339(),
                        extracted_results: vec![js_resp.output],
                        protocol: "javascript".to_string(),
                        matcher_name,
                        tags: template.info.tags.clone(),
                    };
                    let _ = result_tx.send(finding).await;
                }
            }
        }
    }

    /// Send a single HTTP request for a block, handling host-error bookkeeping.
    /// Returns `None` when the request failed (or the host was dropped).
    pub(super) async fn send_http_one(
        &self,
        http_block: &HttpBlock,
        target: &str,
        req_spec: &RequestSpec,
    ) -> Option<HttpResponse> {
        let policy = self.block_request_policy(http_block);
        let outcome: Result<HttpResponse, String> = match req_spec {
            RequestSpec::Standard {
                method,
                url,
                headers,
                body,
            } => self
                .client
                .send(method, url, headers, body, &policy)
                .await
                .map_err(|e| e.to_string()),
            RequestSpec::Raw(raw_content) => {
                self.client.send_raw(raw_content, target, &policy).await
            }
        };
        match outcome {
            Ok(r) => {
                self.host_errors.record_success(target).await;
                Some(r)
            }
            Err(e) => {
                if let Some(ref tx) = self.error_sender {
                    let _ = tx.try_send((target.to_string(), e.clone()));
                }
                if self.host_errors.record_error(target).await {
                    eprintln!("[WRN] Too many errors for host {} — dropping it", target);
                }
                None
            }
        }
    }

    /// Evaluate one HTTP response: run extractors, register OOB interactions,
    /// and emit a finding when the block's matchers match. Returns `true` when
    /// the caller should stop iterating (no matchers, or stop-at-first-match).
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_http_response(
        &self,
        http_block: &HttpBlock,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        req_spec: &RequestSpec,
        response: &HttpResponse,
        interactsh_urls: &[String],
        result_tx: &mpsc::Sender<ScanFinding>,
    ) -> bool {
        let has_non_internal_matchers = http_block.matchers.iter().any(|m| !m.internal);

        let new_extractions = ExtractorEngine::extract_all(&http_block.extractors, response);
        if let Some(c) = capture.as_mut() {
            capture_extract_names(c, &http_block.extractors, &new_extractions);
        }
        extracted_vars.extend(new_extractions);

        // Register for OOB correlation when this request carried interactsh
        // URLs; early interactions are processed at once.
        if !interactsh_urls.is_empty() {
            let matched_url = match req_spec {
                RequestSpec::Standard { url, .. } => url.clone(),
                RequestSpec::Raw(_) => target.to_string(),
            };
            self.register_interactsh_requests(
                template,
                http_block,
                matched_url,
                response,
                interactsh_urls,
                result_tx,
            )
            .await;
        }

        if http_block.matchers.is_empty() {
            return true;
        }

        let eval_resp = EvaluatedResponse {
            status: response.status,
            headers: &response.headers_raw,
            body: &response.body,
            interactsh_protocol: None,
            interactsh_request: None,
            interactsh_response: None,
            duration_secs: response.duration_secs,
            // Extracted values are visible to DSL matchers, as Go merges them
            // into the data map before operator execution.
            named_parts: Some(extracted_vars),
        };

        let condition = http_block.matchers_condition.as_deref().unwrap_or("or");
        let matchers = interpolate_matchers(&http_block.matchers, target, extracted_vars);
        let is_match = MatcherEngine::evaluate_all(&matchers, condition, &eval_resp);

        if is_match {
            if let Some(c) = capture.as_mut() {
                c.record_matcher(MatcherEngine::matched_matcher_name(
                    &matchers,
                    condition,
                    &eval_resp,
                ));
            }
            if has_non_internal_matchers {
                let output_values =
                    ExtractorEngine::extract_output_values(&http_block.extractors, response);

                let matched_url = match req_spec {
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
                    matcher_name: MatcherEngine::matched_matcher_name(
                        &matchers,
                        condition,
                        &eval_resp,
                    ),
                    tags: template.info.tags.clone(),
                };

                let _ = result_tx.send(finding).await;
            }

            let should_stop =
                !has_non_internal_matchers || http_block.stop_at_first_match || self.stop_at_first_match;
            if should_stop {
                if self.stop_at_first_match {
                    *spm_stop = true;
                }
                return true;
            }
        }

        false
    }

    pub async fn execute_http(
        &self,
        template: &NucleiTemplate,
        target: &str,
        extracted_vars: &mut HashMap<String, String>,
        mut capture: Option<&mut RunCapture>,
        spm_stop: &mut bool,
        result_tx: &mpsc::Sender<ScanFinding>,
    ) {
        for http_block in &template.http {
            if self.is_cancelled.load(Ordering::Relaxed) || *spm_stop {
                return;
            }

            // Determine request mode: raw or path-based.
            let mut requests_to_send = build_http_requests(http_block, target, extracted_vars);

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
                    RequestSpec::Standard {
                        url, headers, body, ..
                    } => {
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
                    return;
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

                let race_n = if http_block.race {
                    http_block.race_number.filter(|n| *n > 0).unwrap_or(1)
                } else {
                    1
                };

                if race_n > 1 {
                    // Race condition testing: fire `race_n` identical requests
                    // concurrently (Go `executeRaceRequest`), then evaluate the
                    // responses. Only the requests are concurrent — evaluation
                    // is sequential to keep variable capture deterministic.
                    let interactsh_urls = interactsh_urls_per_request[req_index].clone();
                    for _ in 0..race_n {
                        self.request_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    let futures: Vec<_> = (0..race_n)
                        .map(|_| self.send_http_one(http_block, target, &req_spec))
                        .collect();
                    let responses: Vec<Option<HttpResponse>> =
                        futures_util::future::join_all(futures).await;

                    let mut stop = false;
                    for response in responses.into_iter().flatten() {
                        if self
                            .evaluate_http_response(
                                http_block,
                                template,
                                target,
                                extracted_vars,
                                capture.as_deref_mut(),
                                spm_stop,
                                &req_spec,
                                &response,
                                &interactsh_urls,
                                result_tx,
                            )
                            .await
                        {
                            stop = true;
                            break;
                        }
                    }
                    if stop {
                        break;
                    }
                } else {
                    self.request_counter.fetch_add(1, Ordering::Relaxed);
                    if let Some(response) =
                        self.send_http_one(http_block, target, &req_spec).await
                    {
                        if self
                            .evaluate_http_response(
                                http_block,
                                template,
                                target,
                                extracted_vars,
                                capture.as_deref_mut(),
                                spm_stop,
                                &req_spec,
                                &response,
                                &interactsh_urls_per_request[req_index],
                                result_tx,
                            )
                            .await
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
}
