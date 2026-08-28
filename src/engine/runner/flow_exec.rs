use crate::engine::code_client::CodeClient;
use crate::engine::dns_client::DnsClient;
use crate::engine::extractor::ExtractorEngine;
use crate::engine::flow::FlowNode;
use crate::engine::http_client::HttpResponse;
use crate::engine::matcher::{EvaluatedResponse, MatcherEngine};
use crate::engine::network_client::NetworkClient;
use crate::engine::runner::helpers::{build_http_requests, has_unresolved_variables, interpolate_matchers, RequestSpec};
use crate::engine::runner::EngineRunner;
use crate::engine::ssl_client::SslClient;
use crate::models::result::ScanFinding;
use crate::models::template::{CodeBlock, DnsBlock, HttpBlock, NetworkBlock, NucleiTemplate, SslBlock};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

/// Match context accumulated while evaluating a flow expression.
pub struct FlowMatchContext {
    pub matched_url: Option<String>,
    pub extracted: Vec<String>,
    pub protocol: String,
}

impl EngineRunner {
    /// Evaluate a parsed flow expression and emit a finding if it returns true.
    pub async fn execute_flow(
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
    pub fn eval_flow_node<'a>(
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

            let follow_redirects = block.redirects.unwrap_or(false);
            let response: HttpResponse = match req_spec {
                RequestSpec::Standard {
                    ref method,
                    ref url,
                    ref headers,
                    ref body,
                } => match if follow_redirects {
                    self.client.send_following(method, url, headers, body).await
                } else {
                    self.client.send(method, url, headers, body).await
                } {
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
                    match self.client.send_raw(raw_content, target, follow_redirects).await {
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
                duration_secs: response.duration_secs,
                named_parts: None,
            };

            let condition = block.matchers_condition.as_deref().unwrap_or("or");
            let matchers = interpolate_matchers(&block.matchers, target, extracted_vars);
            if MatcherEngine::evaluate_all(&matchers, condition, &eval_resp) {
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
            duration_secs: 0.0,
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
            duration_secs: 0.0,
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
            duration_secs: 0.0,
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
            duration_secs: 0.0,
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
