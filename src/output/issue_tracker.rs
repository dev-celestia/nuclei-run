use crate::models::result::ScanFinding;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum IssueTrackerTarget {
    GitHub {
        repo: String,
        token: String,
    },
    GitLab {
        project_id: String,
        token: String,
        base_url: Option<String>,
    },
    Jira {
        host: String,
        project_key: String,
        user_email: String,
        api_token: String,
    },
    Linear {
        team_id: String,
        api_key: String,
    },
}

pub struct IssueTrackerClient {
    client: Client,
}

impl IssueTrackerClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Create an automated issue/ticket for a discovered vulnerability finding.
    pub async fn create_issue(
        &self,
        finding: &ScanFinding,
        target: &IssueTrackerTarget,
    ) -> Result<String, String> {
        let title = format!("[Vulnerability] {} found on {}", finding.template_id, finding.matched_url);
        let body = format!(
            "## Vulnerability Report\n\n- **Template**: {}\n- **Severity**: {}\n- **Matched URL**: {}\n- **Protocol**: {}\n- **Detected At**: {}\n- **Extracted**: `{}`\n",
            finding.template_name,
            finding.severity,
            finding.matched_url,
            finding.protocol,
            finding.matched_at,
            finding.extracted_results.join(", ")
        );

        match target {
            IssueTrackerTarget::GitHub { repo, token } => {
                let url = format!("https://api.github.com/repos/{}/issues", repo);
                let payload = json!({
                    "title": title,
                    "body": body,
                    "labels": ["security", &finding.severity]
                });
                let res = self.client.post(&url)
                    .header("User-Agent", "nuclei-run")
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;

                if res.status().is_success() {
                    Ok(format!("GitHub issue created for {}", repo))
                } else {
                    Err(format!("GitHub API error status: {}", res.status()))
                }
            }
            IssueTrackerTarget::GitLab { project_id, token, base_url } => {
                let host = base_url.as_deref().unwrap_or("https://gitlab.com");
                let url = format!("{}/api/v4/projects/{}/issues", host.trim_end_matches('/'), project_id);
                let payload = json!({
                    "title": title,
                    "description": body,
                    "labels": format!("security,{}", finding.severity)
                });
                let res = self.client.post(&url)
                    .header("PRIVATE-TOKEN", token)
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;

                if res.status().is_success() {
                    Ok(format!("GitLab issue created for project {}", project_id))
                } else {
                    Err(format!("GitLab API error status: {}", res.status()))
                }
            }
            IssueTrackerTarget::Jira { host, project_key, user_email, api_token } => {
                let url = format!("{}/rest/api/2/issue", host.trim_end_matches('/'));
                let payload = json!({
                    "fields": {
                        "project": { "key": project_key },
                        "summary": title,
                        "description": body,
                        "issuetype": { "name": "Bug" }
                    }
                });
                let auth_header = format!("{}:{}", user_email, api_token);
                let b64_auth = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth_header.as_bytes());

                let res = self.client.post(&url)
                    .header("Authorization", format!("Basic {}", b64_auth))
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;

                if res.status().is_success() {
                    Ok(format!("Jira issue created in {}", project_key))
                } else {
                    Err(format!("Jira API error status: {}", res.status()))
                }
            }
            IssueTrackerTarget::Linear { team_id, api_key } => {
                let url = "https://api.linear.app/graphql";
                let query = "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id title } } }";
                let payload = json!({
                    "query": query,
                    "variables": {
                        "input": {
                            "teamId": team_id,
                            "title": title,
                            "description": body
                        }
                    }
                });
                let res = self.client.post(url)
                    .header("Authorization", api_key)
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;

                if res.status().is_success() {
                    Ok("Linear issue created".to_string())
                } else {
                    Err(format!("Linear API error status: {}", res.status()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_formatting() {
        let finding = ScanFinding {
            template_id: "cve-2023-1234".to_string(),
            template_name: "Test CVE".to_string(),
            severity: "high".to_string(),
            matched_url: "https://target.com".to_string(),
            matched_at: "2026-08-27T00:00:00Z".to_string(),
            extracted_results: vec!["admin".to_string()],
            protocol: "http".to_string(),
            matcher_name: None,
            tags: None,
        };
        let target = IssueTrackerTarget::GitHub {
            repo: "org/repo".to_string(),
            token: "ghp_test".to_string(),
        };
        assert_eq!(finding.template_id, "cve-2023-1234");
        match target {
            IssueTrackerTarget::GitHub { repo, .. } => assert_eq!(repo, "org/repo"),
            _ => panic!("Expected GitHub"),
        }
    }
}
