use crate::models::template::HeadlessBlock;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HeadlessResponse {
    pub url: String,
    pub dom_content: String,
    pub script_results: Vec<String>,
    pub extracted_data: HashMap<String, String>,
    pub raw: String,
}

pub struct HeadlessClient;

impl HeadlessClient {
    /// Execute headless browser steps. Emulates action dispatch and JavaScript evaluation.
    pub async fn execute(
        block: &HeadlessBlock,
        target: &str,
        timeout_secs: u64,
    ) -> Result<HeadlessResponse, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs.max(2)))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| e.to_string())?;

        let mut current_url = target.to_string();
        let mut script_results = Vec::new();
        let mut extracted_data = HashMap::new();
        let mut dom_content = String::new();

        for step in &block.steps {
            match step.action.as_str() {
                "navigate" => {
                    let dest = step.target.as_deref().unwrap_or(target);
                    current_url = if dest.starts_with("http://") || dest.starts_with("https://") {
                        dest.to_string()
                    } else {
                        format!("{}/{}", target.trim_end_matches('/'), dest.trim_start_matches('/'))
                    };
                    if let Ok(res) = client.get(&current_url).send().await {
                        if let Ok(text) = res.text().await {
                            dom_content = text;
                        }
                    }
                }
                "script" => {
                    if let Some(ref script) = step.code {
                        let sim_res = format!("evaluated: {}", script);
                        script_results.push(sim_res);
                    }
                }
                "type" => {
                    if let (Some(ref sel), Some(ref val)) = (&step.target, &step.value) {
                        extracted_data.insert(sel.clone(), val.clone());
                    }
                }
                "wait-for" => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                "extract" => {
                    if let Some(ref sel) = step.target {
                        extracted_data.insert(sel.clone(), dom_content.clone());
                    }
                }
                _ => {}
            }
        }

        // If no explicit navigate step was present, fetch base target DOM
        if dom_content.is_empty() {
            if let Ok(res) = client.get(target).send().await {
                if let Ok(text) = res.text().await {
                    dom_content = text;
                }
            }
        }

        let raw = format!("{}\n{}", dom_content, script_results.join("\n"));
        Ok(HeadlessResponse {
            url: current_url,
            dom_content,
            script_results,
            extracted_data,
            raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::template::HeadlessStep;

    #[test]
    fn test_headless_step_parsing() {
        let block = HeadlessBlock {
            steps: vec![
                HeadlessStep {
                    action: "navigate".to_string(),
                    target: Some("https://example.com".to_string()),
                    code: None,
                    key: None,
                    value: None,
                    args: vec![],
                },
            ],
            matchers_condition: None,
            matchers: vec![],
            extractors: vec![],
        };
        assert_eq!(block.steps.len(), 1);
        assert_eq!(block.steps[0].action, "navigate");
    }
}
