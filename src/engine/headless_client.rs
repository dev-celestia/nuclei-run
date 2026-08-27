//! Headless browser protocol engine driven by a real Chrome/Chromium instance
//! over the Chrome DevTools Protocol (via `chromiumoxide`).
//!
//! Implements the actions used by nuclei headless templates: `navigate`,
//! `waitload` and `script`. Script results are captured under their step
//! `name:` so matchers can target them with `part: <name>`; the final DOM
//! content is exposed as the response body.

use crate::engine::dsl::TemplateDsl;
use crate::models::template::HeadlessBlock;
use chromiumoxide::{Browser, BrowserConfig, Page};
use futures_util::StreamExt;
use std::collections::HashMap;

/// Result of executing a headless block.
#[derive(Debug, Clone)]
pub struct HeadlessResponse {
    pub url: String,
    /// Rendered DOM content after all steps (used as the matcher body).
    pub dom_content: String,
    /// Named script results keyed by step `name:` (matched via `part: <name>`).
    pub data: HashMap<String, String>,
}

pub struct HeadlessClient;

impl HeadlessClient {
    /// Execute a headless block against a target URL.
    pub async fn execute(
        block: &HeadlessBlock,
        target: &str,
        extracted_vars: &HashMap<String, String>,
    ) -> Result<HeadlessResponse, String> {
        let chrome = locate_chrome().ok_or_else(|| {
            "no Chrome/Chromium executable found (set CHROME_PATH to override)".to_string()
        })?;

        let config = BrowserConfig::builder()
            .chrome_executable(&chrome)
            .no_sandbox()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--no-first-run")
            .build()
            .map_err(|e| e.to_string())?;

        let (mut browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| e.to_string())?;
        // Drive the browser event handler.
        tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        let page: Page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| e.to_string())?;

        let mut current_url = target.to_string();
        let mut named: HashMap<String, String> = HashMap::new();

        for step in &block.steps {
            match step.action.as_str() {
                "navigate" => {
                    let raw = step
                        .args
                        .get("url")
                        .map(|s| s.as_str())
                        .or(step.target.as_deref())
                        .unwrap_or(target);
                    let url = TemplateDsl::interpolate(raw, target, extracted_vars);
                    current_url = url.clone();
                    // goto waits for the load event by default.
                    page.goto(url)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                "waitload" => {
                    // goto above already awaits the load event; nothing extra.
                }
                "script" => {
                    let code = step
                        .args
                        .get("code")
                        .map(|s| s.as_str())
                        .or(step.code.as_deref())
                        .unwrap_or("");
                    let code = TemplateDsl::interpolate(code, target, extracted_vars);
                    let result = page
                        .evaluate(code)
                        .await
                        .map_err(|e| e.to_string())?;
                    let value = result
                        .value()
                        .map(js_value_to_string)
                        .unwrap_or_default();
                    if let Some(name) = &step.name {
                        named.insert(name.clone(), value);
                    }
                }
                other => {
                    return Err(format!("unsupported headless action: {}", other));
                }
            }
        }

        let dom_content = page.content().await.map_err(|e| e.to_string())?;
        let _ = page.close().await;
        let _ = browser.close().await;

        Ok(HeadlessResponse {
            url: current_url,
            dom_content,
            data: named,
        })
    }
}

/// Render a CDP-evaluated JS value as a string for matcher use.
fn js_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Locate a Chrome/Chromium executable.
fn locate_chrome() -> Option<String> {
    for env in ["CHROME_PATH", "CHROMIUM_PATH"] {
        if let Ok(p) = std::env::var(env) {
            if !p.is_empty() && std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
    }

    const CANDIDATES: &[&str] = &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ];
    CANDIDATES
        .iter()
        .map(|p| p.to_string())
        .find(|p| std::path::Path::new(p).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_js_value_to_string() {
        assert_eq!(js_value_to_string(&serde_json::json!(true)), "true");
        assert_eq!(js_value_to_string(&serde_json::json!("abc")), "abc");
        assert_eq!(js_value_to_string(&serde_json::json!(42)), "42");
        assert_eq!(js_value_to_string(&serde_json::json!(null)), "");
    }
}
