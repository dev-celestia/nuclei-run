use crate::models::template::FuzzingBlock;
use std::collections::HashMap;

/// Mutation strategy for web parameter fuzzing.
#[derive(Debug, Clone)]
pub struct FuzzRequest {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub parameter_name: String,
    pub payload_value: String,
}

pub struct FuzzingEngine;

impl FuzzingEngine {
    /// Generate fuzzed requests based on attack type, mode, and target URL/body.
    pub fn generate(
        block: &FuzzingBlock,
        base_url: &str,
        base_headers: &HashMap<String, String>,
        base_body: Option<&str>,
    ) -> Vec<FuzzRequest> {
        let mut requests = Vec::new();
        let attack_type = block.attack_type.as_deref().unwrap_or("sniper");
        let mode = block.mode.as_deref().unwrap_or("replace");

        match attack_type {
            "pitchfork" => {
                // Lockstep mutation across payload lists
                let mut max_len = 0;
                for payloads in block.payloads.values() {
                    max_len = max_len.max(payloads.len());
                }

                for i in 0..max_len {
                    let mut current_url = base_url.to_string();
                    let mut current_headers = base_headers.clone();
                    let mut current_body = base_body.map(|b| b.to_string());

                    for (key, payloads) in &block.payloads {
                        if let Some(payload) = payloads.get(i) {
                            Self::apply_injection(
                                block.part.as_deref().unwrap_or("query"),
                                key,
                                payload,
                                mode,
                                &mut current_url,
                                &mut current_headers,
                                &mut current_body,
                            );
                        }
                    }

                    requests.push(FuzzRequest {
                        url: current_url,
                        headers: current_headers,
                        body: current_body,
                        parameter_name: "pitchfork".to_string(),
                        payload_value: format!("step-{}", i),
                    });
                }
            }
            "clusterbomb" => {
                // Cartesian product
                let keys: Vec<&String> = block.payloads.keys().collect();
                let mut combinations: Vec<Vec<(String, String)>> = vec![vec![]];

                for key in keys {
                    let payloads = &block.payloads[key];
                    let mut next = Vec::new();
                    for comb in &combinations {
                        for p in payloads {
                            let mut new_comb = comb.clone();
                            new_comb.push((key.clone(), p.clone()));
                            next.push(new_comb);
                        }
                    }
                    combinations = next;
                }

                for comb in combinations {
                    let mut current_url = base_url.to_string();
                    let mut current_headers = base_headers.clone();
                    let mut current_body = base_body.map(|b| b.to_string());

                    for (k, v) in &comb {
                        Self::apply_injection(
                            block.part.as_deref().unwrap_or("query"),
                            k,
                            v,
                            mode,
                            &mut current_url,
                            &mut current_headers,
                            &mut current_body,
                        );
                    }

                    requests.push(FuzzRequest {
                        url: current_url,
                        headers: current_headers,
                        body: current_body,
                        parameter_name: "clusterbomb".to_string(),
                        payload_value: format!("{:?}", comb),
                    });
                }
            }
            _ => {
                // Sniper: test one parameter at a time with each payload
                for (key, payloads) in &block.payloads {
                    for payload in payloads {
                        let mut current_url = base_url.to_string();
                        let mut current_headers = base_headers.clone();
                        let mut current_body = base_body.map(|b| b.to_string());

                        Self::apply_injection(
                            block.part.as_deref().unwrap_or("query"),
                            key,
                            payload,
                            mode,
                            &mut current_url,
                            &mut current_headers,
                            &mut current_body,
                        );

                        requests.push(FuzzRequest {
                            url: current_url,
                            headers: current_headers,
                            body: current_body,
                            parameter_name: key.clone(),
                            payload_value: payload.clone(),
                        });
                    }
                }
            }
        }

        requests
    }

    fn apply_injection(
        part: &str,
        param_name: &str,
        payload: &str,
        mode: &str,
        url: &mut String,
        headers: &mut HashMap<String, String>,
        body: &mut Option<String>,
    ) {
        let mutate = |original: &str| -> String {
            match mode {
                "prefix" => format!("{}{}", payload, original),
                "postfix" => format!("{}{}", original, payload),
                "infix" => {
                    let half = original.len() / 2;
                    format!("{}{}{}", &original[..half], payload, &original[half..])
                }
                _ => payload.to_string(), // replace
            }
        };

        match part {
            "header" | "headers" => {
                if let Some(existing) = headers.get_mut(param_name) {
                    *existing = mutate(existing);
                } else {
                    headers.insert(param_name.to_string(), payload.to_string());
                }
            }
            "body" => {
                if let Some(ref mut b) = body {
                    if b.contains(param_name) {
                        *b = b.replace(param_name, payload);
                    } else {
                        *b = mutate(b);
                    }
                } else {
                    *body = Some(payload.to_string());
                }
            }
            _ => {
                // Query parameter
                if url.contains('?') {
                    if url.contains(&format!("{}=", param_name)) {
                        let pat = format!("{}=", param_name);
                        let mutated_param = format!("{}={}", param_name, payload);
                        *url = url.replace(&pat, &mutated_param);
                    } else {
                        url.push_str(&format!("&{}={}", param_name, payload));
                    }
                } else {
                    url.push_str(&format!("?{}={}", param_name, payload));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniper_fuzzing() {
        let mut payloads = HashMap::new();
        payloads.insert("id".to_string(), vec!["1' OR '1'='1".to_string(), "2".to_string()]);

        let block = FuzzingBlock {
            part: Some("query".to_string()),
            attack_type: Some("sniper".to_string()),
            mode: Some("replace".to_string()),
            keys: vec!["id".to_string()],
            payloads,
            matchers_condition: None,
            matchers: vec![],
            extractors: vec![],
        };

        let reqs = FuzzingEngine::generate(&block, "http://target.com/page?id=1", &HashMap::new(), None);
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].url.contains("id=1' OR '1'='1"));
        assert!(reqs[1].url.contains("id=2"));
    }

    #[test]
    fn test_pitchfork_fuzzing() {
        let mut payloads = HashMap::new();
        payloads.insert("user".to_string(), vec!["admin".to_string(), "guest".to_string()]);
        payloads.insert("pass".to_string(), vec!["1234".to_string(), "pass".to_string()]);

        let block = FuzzingBlock {
            part: Some("query".to_string()),
            attack_type: Some("pitchfork".to_string()),
            mode: Some("replace".to_string()),
            keys: vec!["user".to_string(), "pass".to_string()],
            payloads,
            matchers_condition: None,
            matchers: vec![],
            extractors: vec![],
        };

        let reqs = FuzzingEngine::generate(&block, "http://target.com/login", &HashMap::new(), None);
        assert_eq!(reqs.len(), 2);
    }
}
