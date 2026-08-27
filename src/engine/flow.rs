use crate::models::template::NucleiTemplate;

/// Flow step execution instructions.
#[derive(Debug, Clone)]
pub enum FlowStep {
    Http(usize),
    Dns(usize),
    Network(usize),
    Ssl(usize),
    Code(usize),
}

pub struct FlowEngine;

impl FlowEngine {
    /// Parse a simple flow script into executable protocol sequence steps.
    pub fn parse_flow_steps(flow_script: &str, template: &NucleiTemplate) -> Vec<FlowStep> {
        let mut steps = Vec::new();

        for line in flow_script.lines() {
            let trimmed = line.trim();
            if trimmed.contains("http(") {
                if let Some(idx) = extract_index(trimmed, "http") {
                    if idx < template.http.len() {
                        steps.push(FlowStep::Http(idx));
                    }
                }
            } else if trimmed.contains("dns(") {
                if let Some(idx) = extract_index(trimmed, "dns") {
                    if idx < template.dns.len() {
                        steps.push(FlowStep::Dns(idx));
                    }
                }
            } else if trimmed.contains("network(") || trimmed.contains("tcp(") {
                if let Some(idx) = extract_index(trimmed, "network").or_else(|| extract_index(trimmed, "tcp")) {
                    if idx < template.network.len() {
                        steps.push(FlowStep::Network(idx));
                    }
                }
            } else if trimmed.contains("ssl(") {
                if let Some(idx) = extract_index(trimmed, "ssl") {
                    if idx < template.ssl.len() {
                        steps.push(FlowStep::Ssl(idx));
                    }
                }
            } else if trimmed.contains("code(") {
                if let Some(idx) = extract_index(trimmed, "code") {
                    if idx < template.code.len() {
                        steps.push(FlowStep::Code(idx));
                    }
                }
            }
        }

        // If no explicit steps were parsed, default to executing all blocks sequentially
        if steps.is_empty() {
            for i in 0..template.http.len() {
                steps.push(FlowStep::Http(i));
            }
            for i in 0..template.dns.len() {
                steps.push(FlowStep::Dns(i));
            }
            for i in 0..template.network.len() {
                steps.push(FlowStep::Network(i));
            }
            for i in 0..template.ssl.len() {
                steps.push(FlowStep::Ssl(i));
            }
            for i in 0..template.code.len() {
                steps.push(FlowStep::Code(i));
            }
        }

        steps
    }
}

fn extract_index(s: &str, func_name: &str) -> Option<usize> {
    let pat = format!("{}(", func_name);
    if let Some(start) = s.find(&pat) {
        if let Some(end) = s[start + pat.len()..].find(')') {
            let inner = &s[start + pat.len()..start + pat.len() + end].trim().trim_matches('\'').trim_matches('"');
            return inner.parse::<usize>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::template::{HttpBlock, TemplateInfo};

    #[test]
    fn test_flow_parsing() {
        let mut template = NucleiTemplate {
            id: "flow-test".to_string(),
            info: TemplateInfo {
                name: "Flow Test".to_string(),
                author: Default::default(),
                severity: "info".to_string(),
                description: None,
                reference: None,
                tags: None,
                metadata: None,
                classification: None,
                remediation: None,
            },
            http: vec![HttpBlock {
                method: Some("GET".to_string()),
                path: vec!["/".to_string()],
                raw: vec![],
                headers: Default::default(),
                body: None,
                matchers_condition: None,
                matchers: vec![],
                extractors: vec![],
                stop_at_first_match: false,
                max_redirects: None,
                redirects: None,
                cookie_reuse: None,
                race: false,
                race_number: None,
            }],
            dns: vec![],
            network: vec![],
            ssl: vec![],
            whois: vec![],
            file: vec![],
            code: vec![],
            websocket: vec![],
            headless: vec![],
            javascript: vec![],
            fuzzing: vec![],
            flow: Some("http(0)".to_string()),
            signature: None,
            self_contained: false,
            variables: Default::default(),
            constants: Default::default(),
        };

        let steps = FlowEngine::parse_flow_steps("http(0)", &template);
        assert_eq!(steps.len(), 1);
        match steps[0] {
            FlowStep::Http(0) => {}
            _ => panic!("Expected Http(0)"),
        }
    }
}
