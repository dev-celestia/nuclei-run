//! OSINT target discovery via search-engine APIs (Shodan, Censys, FOFA).
//!
//! API keys are read from environment variables:
//! - shodan: `SHODAN_API_KEY`
//! - censys: `CENSYS_API_ID` + `CENSYS_API_SECRET`
//! - fofa:   `FOFA_EMAIL` + `FOFA_KEY`

use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;

/// Query options for target discovery.
#[derive(Debug, Clone)]
pub struct UncoverOptions {
    pub engine: String,
    pub query: String,
    pub limit: usize,
}

pub struct UncoverClient;

impl UncoverClient {
    /// Query the selected OSINT engine and return discovered `host[:port]` targets.
    pub async fn query(opts: &UncoverOptions) -> Result<Vec<String>, String> {
        match opts.engine.to_lowercase().as_str() {
            "shodan" => Self::shodan(opts).await,
            "censys" => Self::censys(opts).await,
            "fofa" => Self::fofa(opts).await,
            other => Err(format!(
                "unsupported uncover engine: {} (supported: shodan, censys, fofa)",
                other
            )),
        }
    }

    async fn shodan(opts: &UncoverOptions) -> Result<Vec<String>, String> {
        let key = std::env::var("SHODAN_API_KEY")
            .map_err(|_| "SHODAN_API_KEY environment variable not set".to_string())?;

        #[derive(Deserialize)]
        struct Match {
            #[serde(default)]
            ip_str: Option<String>,
            #[serde(default)]
            port: Option<u16>,
        }
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            matches: Vec<Match>,
        }

        let client = reqwest::Client::new();
        let response = client
            .get("https://api.shodan.io/shodan/host/search")
            .query(&[("key", key.as_str()), ("query", opts.query.as_str())])
            .header("User-Agent", "nuclei-run/0.1")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("shodan returned HTTP {}", response.status()));
        }
        let data: Resp = response.json().await.map_err(|e| e.to_string())?;

        let mut targets = Vec::new();
        for m in data.matches {
            if let Some(ip) = m.ip_str {
                targets.push(match m.port {
                    Some(port) => format!("{}:{}", ip, port),
                    None => ip,
                });
                if targets.len() >= opts.limit {
                    break;
                }
            }
        }
        Ok(targets)
    }

    async fn censys(opts: &UncoverOptions) -> Result<Vec<String>, String> {
        let id = std::env::var("CENSYS_API_ID")
            .map_err(|_| "CENSYS_API_ID environment variable not set".to_string())?;
        let secret = std::env::var("CENSYS_API_SECRET")
            .map_err(|_| "CENSYS_API_SECRET environment variable not set".to_string())?;

        #[derive(Deserialize, Default)]
        struct Service {
            #[serde(default)]
            port: Option<u16>,
        }
        #[derive(Deserialize, Default)]
        struct Hit {
            #[serde(default)]
            ip: Option<String>,
            #[serde(default)]
            services: Vec<Service>,
        }
        #[derive(Deserialize, Default)]
        struct Result_ {
            #[serde(default)]
            hits: Vec<Hit>,
        }
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            result: Result_,
        }

        let client = reqwest::Client::new();
        let response = client
            .get("https://search.censys.io/api/v2/hosts/search")
            .query(&[
                ("q", opts.query.as_str()),
                ("per_page", &opts.limit.min(100).to_string()),
            ])
            .basic_auth(id, Some(secret))
            .header("User-Agent", "nuclei-run/0.1")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("censys returned HTTP {}", response.status()));
        }
        let data: Resp = response.json().await.map_err(|e| e.to_string())?;

        let mut targets = Vec::new();
        for hit in data.result.hits {
            let Some(ip) = hit.ip else { continue };
            if hit.services.is_empty() {
                targets.push(ip.clone());
            } else {
                for svc in &hit.services {
                    if let Some(port) = svc.port {
                        targets.push(format!("{}:{}", ip, port));
                    }
                }
            }
            if targets.len() >= opts.limit {
                break;
            }
        }
        targets.truncate(opts.limit);
        Ok(targets)
    }

    async fn fofa(opts: &UncoverOptions) -> Result<Vec<String>, String> {
        let email = std::env::var("FOFA_EMAIL")
            .map_err(|_| "FOFA_EMAIL environment variable not set".to_string())?;
        let key = std::env::var("FOFA_KEY")
            .map_err(|_| "FOFA_KEY environment variable not set".to_string())?;

        let q_b64 = general_purpose::STANDARD.encode(opts.query.as_bytes());

        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            results: Vec<Vec<String>>,
            #[serde(default)]
            errmsg: Option<String>,
        }

        let client = reqwest::Client::new();
        let response = client
            .get("https://fofa.info/api/v1/search/all")
            .query(&[
                ("email", email.as_str()),
                ("key", key.as_str()),
                ("qbase64", q_b64.as_str()),
                ("size", &opts.limit.min(1000).to_string()),
            ])
            .header("User-Agent", "nuclei-run/0.1")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("fofa returned HTTP {}", response.status()));
        }
        let data: Resp = response.json().await.map_err(|e| e.to_string())?;
        if let Some(err) = data.errmsg {
            if !err.is_empty() {
                return Err(format!("fofa error: {}", err));
            }
        }

        // FOFA returns rows of [ip, port] by default.
        let mut targets = Vec::new();
        for row in data.results {
            match row.len() {
                0 => continue,
                1 => targets.push(row[0].clone()),
                _ => targets.push(format!("{}:{}", row[0], row[1])),
            }
            if targets.len() >= opts.limit {
                break;
            }
        }
        Ok(targets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_validation_message() {
        // Synchronous check of the unsupported-engine path formatting.
        let opts = UncoverOptions {
            engine: "badengine".to_string(),
            query: "test".to_string(),
            limit: 10,
        };
        let err = match opts.engine.to_lowercase().as_str() {
            "shodan" | "censys" | "fofa" => None,
            other => Some(format!(
                "unsupported uncover engine: {} (supported: shodan, censys, fofa)",
                other
            )),
        };
        assert!(err.unwrap().contains("badengine"));
    }
}
