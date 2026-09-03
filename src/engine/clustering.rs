use crate::models::template::NucleiTemplate;
use std::collections::HashMap;
use std::sync::Arc;

/// A clustered request unit combining multiple templates that share identical
/// HTTP paths/methods. All templates in the group hit the same request; the
/// response is fetched once and each template's matchers run against it.
#[derive(Debug, Clone)]
pub struct ClusteredTask {
    pub target: String,
    pub templates: Vec<Arc<NucleiTemplate>>,
}

pub struct RequestClusterer;

impl RequestClusterer {
    /// Group scan tasks into clustered requests where possible.
    ///
    /// Mirrors Go's `Cluster` (`pkg/templates/cluster.go:46`): a template is
    /// clusterable only when it has exactly one HTTP request with a single
    /// path and no raw body/headers. Templates that cannot be clustered (flow,
    /// multi-block, multi-path, raw) are emitted as singletons.
    pub fn cluster(
        targets: &[String],
        templates: &[Arc<NucleiTemplate>],
    ) -> Vec<ClusteredTask> {
        let mut cluster_map: HashMap<(String, String, String), Vec<Arc<NucleiTemplate>>> =
            HashMap::new();
        let mut singletons: Vec<ClusteredTask> = Vec::new();

        for target in targets {
            for template in templates {
                if is_clusterable_http(template) {
                    let method = template.http[0]
                        .method
                        .as_deref()
                        .unwrap_or("GET")
                        .to_uppercase();
                    let path = template.http[0].path[0].clone();
                    let key = (target.clone(), method.clone(), path.clone());
                    cluster_map.entry(key).or_default().push(Arc::clone(template));
                } else {
                    singletons.push(ClusteredTask {
                        target: target.clone(),
                        templates: vec![Arc::clone(template)],
                    });
                }
            }
        }

        let mut out: Vec<ClusteredTask> = cluster_map
            .into_iter()
            .map(|((target, _method, _path), tmpls)| ClusteredTask {
                target,
                templates: tmpls,
            })
            .collect();
        out.extend(singletons);
        out
    }
}

/// A template is clusterable when it has exactly one HTTP block with a single
/// path, no raw request, and no body — the request is fully shared.
fn is_clusterable_http(template: &NucleiTemplate) -> bool {
    template.flow.is_none()
        && template.http.len() == 1
        && template.http[0].raw.is_empty()
        && template.http[0].path.len() == 1
        && template.http[0].body.is_none()
        && template.http[0].headers.is_empty()
        && template.http[0].extractors.is_empty()
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
                host_redirects: None,
                disable_cookie: None,
                self_contained: false,
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
            workflows: vec![],
            source_path: None,
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
                host_redirects: None,
                disable_cookie: None,
                self_contained: false,
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
            workflows: vec![],
            source_path: None,
        });

        let targets = vec!["https://example.com".to_string()];
        let clusters = RequestClusterer::cluster(&targets, &[t1, t2]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].templates.len(), 2);
    }
}
