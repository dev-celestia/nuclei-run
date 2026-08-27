use crate::models::template::NucleiTemplate;
use std::collections::HashMap;
use std::sync::Arc;

/// A clustered request unit combining multiple templates that share identical HTTP paths/methods.
#[derive(Debug, Clone)]
pub struct ClusteredTask {
    #[allow(dead_code)]
    pub target: String,
    #[allow(dead_code)]
    pub path: String,
    #[allow(dead_code)]
    pub method: String,
    #[allow(dead_code)]
    pub templates: Vec<Arc<NucleiTemplate>>,
}

pub struct RequestClusterer;

impl RequestClusterer {
    /// Group scan tasks into clustered requests where possible.
    pub fn cluster(
        targets: &[String],
        templates: &[Arc<NucleiTemplate>],
    ) -> Vec<ClusteredTask> {
        let mut cluster_map: HashMap<(String, String, String), Vec<Arc<NucleiTemplate>>> = HashMap::new();

        for target in targets {
            for template in templates {
                if template.http.len() == 1 && template.http[0].raw.is_empty() && template.http[0].path.len() == 1 {
                    let method = template.http[0].method.as_deref().unwrap_or("GET").to_uppercase();
                    let path = template.http[0].path[0].clone();
                    let key = (target.clone(), method, path);
                    cluster_map.entry(key).or_default().push(Arc::clone(template));
                }
            }
        }

        cluster_map
            .into_iter()
            .map(|((target, method, path), tmpls)| ClusteredTask {
                target,
                method,
                path,
                templates: tmpls,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::template::{HttpBlock, TemplateInfo};

    #[test]
    fn test_request_clustering() {
        let t1 = Arc::new(NucleiTemplate {
            id: "t1".to_string(),
            info: TemplateInfo {
                name: "T1".to_string(),
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
                path: vec!["/index.php".to_string()],
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
            flow: None,
            signature: None,
            self_contained: false,
            variables: Default::default(),
            constants: Default::default(),
        });

        let t2 = Arc::new(NucleiTemplate {
            id: "t2".to_string(),
            info: TemplateInfo {
                name: "T2".to_string(),
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
                path: vec!["/index.php".to_string()],
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
            flow: None,
            signature: None,
            self_contained: false,
            variables: Default::default(),
            constants: Default::default(),
        });

        let targets = vec!["https://example.com".to_string()];
        let clusters = RequestClusterer::cluster(&targets, &[t1, t2]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].templates.len(), 2);
    }
}
