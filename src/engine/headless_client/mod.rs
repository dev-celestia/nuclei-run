//! Headless browser protocol engine driven by a real Chrome/Chromium instance
//! over the Chrome DevTools Protocol (via `chromiumoxide`).
//!
//! Implements the complete set of nuclei headless actions:
//! `navigate`, `waitload`, `wait-for`, `click`, `rightclick`, `text`/`type`,
//! `sleep`, `screenshot`, `setheader`, `extract`, `keyboard`, and `select`.
//! Script/extract results are captured under step `name:` so matchers can
//! target them with `part: <name>`; rendered DOM is exposed as the response body.

pub mod actions;
pub mod browser;
pub mod utils;

pub use actions::execute_step;
pub use browser::locate_chrome;
#[allow(unused_imports)]
pub use utils::{get_step_target, get_step_value, js_value_to_string, parse_duration};

use crate::models::template::HeadlessBlock;
use chromiumoxide::cdp::browser_protocol::network::EventResponseReceived;
use chromiumoxide::{Browser, BrowserConfig, Page};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;

/// Result of executing a headless block.
#[derive(Debug, Clone)]
pub struct HeadlessResponse {
    pub url: String,
    /// HTTP status code from navigation response.
    pub status: u16,
    /// HTTP headers from navigation response.
    pub headers: String,
    /// Rendered DOM content after all steps (used as the matcher body).
    pub dom_content: String,
    /// Named script/extract results keyed by step `name:` (matched via `part: <name>`).
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

        let user_data_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let config = BrowserConfig::builder()
            .chrome_executable(&chrome)
            .user_data_dir(user_data_dir.path())
            .no_sandbox()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--no-first-run")
            .build()
            .map_err(|e| e.to_string())?;

        let (mut browser, mut handler) =
            Browser::launch(config).await.map_err(|e| e.to_string())?;

        // Drive the browser event handler.
        tokio::spawn(async move { while handler.next().await.is_some() {} });

        let page: Page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| e.to_string())?;

        let mut response_events = page
            .event_listener::<EventResponseReceived>()
            .await
            .map_err(|e| e.to_string())?;

        let last_status = Arc::new(tokio::sync::Mutex::new(200u16));
        let last_headers = Arc::new(tokio::sync::Mutex::new(String::new()));

        let st_clone = last_status.clone();
        let hd_clone = last_headers.clone();
        tokio::spawn(async move {
            while let Some(event) = response_events.next().await {
                let status = event.response.status as u16;
                *st_clone.lock().await = status;

                let mut raw_headers = String::new();
                let h_val = event.response.headers.inner();
                if let Some(map) = h_val.as_object() {
                    for (k, v) in map {
                        let val_str = if let Some(s) = v.as_str() {
                            s.to_string()
                        } else {
                            v.to_string()
                        };
                        raw_headers.push_str(&format!("{}: {}\r\n", k, val_str));
                    }
                }
                *hd_clone.lock().await = raw_headers;
            }
        });

        let mut current_url = target.to_string();
        let mut named: HashMap<String, String> = HashMap::new();
        let mut extra_headers: HashMap<String, String> = HashMap::new();

        for step in &block.steps {
            execute_step(
                &page,
                step,
                target,
                &mut current_url,
                &mut named,
                &mut extra_headers,
                extracted_vars,
            )
            .await?;
        }

        let dom_content = page.content().await.map_err(|e| e.to_string())?;
        let status = *last_status.lock().await;
        let headers = last_headers.lock().await.clone();
        let _ = page.close().await;
        let _ = browser.close().await;

        Ok(HeadlessResponse {
            url: current_url,
            status,
            headers,
            dom_content,
            data: named,
        })
    }

    /// Execute an individual headless action step (delegates to actions::execute_step).
    #[allow(dead_code)]
    pub async fn execute_step(
        page: &Page,
        step: &crate::models::template::HeadlessStep,
        target: &str,
        current_url: &mut String,
        named: &mut HashMap<String, String>,
        extra_headers: &mut HashMap<String, String>,
        extracted_vars: &HashMap<String, String>,
    ) -> Result<(), String> {
        execute_step(
            page,
            step,
            target,
            current_url,
            named,
            extra_headers,
            extracted_vars,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::template::HeadlessStep;
    use std::time::Duration;

    #[test]
    fn test_js_value_to_string() {
        assert_eq!(js_value_to_string(&serde_json::json!(true)), "true");
        assert_eq!(js_value_to_string(&serde_json::json!("abc")), "abc");
        assert_eq!(js_value_to_string(&serde_json::json!(42)), "42");
        assert_eq!(js_value_to_string(&serde_json::json!(null)), "");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("500ms"), Duration::from_millis(500));
        assert_eq!(parse_duration("2s"), Duration::from_secs(2));
        assert_eq!(parse_duration("1.5s"), Duration::from_millis(1500));
        assert_eq!(parse_duration("3"), Duration::from_secs(3));
        assert_eq!(parse_duration("250"), Duration::from_millis(250));
        assert_eq!(parse_duration(""), Duration::from_secs(1));
        // Edge cases
        assert_eq!(parse_duration("1.5"), Duration::from_millis(1500));
        assert_eq!(parse_duration("49"), Duration::from_secs(49));
        assert_eq!(parse_duration("50"), Duration::from_millis(50));
        assert_eq!(parse_duration("0"), Duration::from_millis(0));
        assert_eq!(parse_duration("garbage"), Duration::from_secs(1));
        assert_eq!(parse_duration("  2s  "), Duration::from_secs(2));
        assert_eq!(parse_duration("1000ms"), Duration::from_secs(1));
    }

    #[test]
    fn test_js_value_to_string_containers() {
        assert_eq!(
            js_value_to_string(&serde_json::json!(["a", "b"])),
            r#"["a","b"]"#
        );
        assert_eq!(
            js_value_to_string(&serde_json::json!({"k": 1})),
            r#"{"k":1}"#
        );
        assert_eq!(js_value_to_string(&serde_json::json!(3.14)), "3.14");
    }

    #[test]
    fn test_get_step_target_alias_precedence() {
        let mut step = HeadlessStep {
            action: "text".to_string(),
            name: None,
            target: None,
            code: None,
            key: Some("key-fallback".to_string()),
            value: None,
            headers: HashMap::new(),
            attribute: None,
            args: HashMap::new(),
        };

        // Fallback: key
        assert_eq!(get_step_target(&step), Some("key-fallback"));

        // args.selector wins over key
        step.args
            .insert("selector".to_string(), "#selector".to_string());
        assert_eq!(get_step_target(&step), Some("#selector"));

        // args.by wins over args.selector
        step.args.insert("by".to_string(), "#by".to_string());
        assert_eq!(get_step_target(&step), Some("#by"));

        // target wins over all
        step.target = Some("#direct-target".to_string());
        assert_eq!(get_step_target(&step), Some("#direct-target"));
    }

    #[test]
    fn test_get_step_target_and_value_aliases() {
        let mut step = HeadlessStep {
            action: "text".to_string(),
            name: None,
            target: None,
            code: None,
            key: None,
            value: None,
            headers: HashMap::new(),
            attribute: None,
            args: HashMap::new(),
        };

        step.args
            .insert("by".to_string(), "#user-input".to_string());
        step.args.insert("value".to_string(), "admin".to_string());
        assert_eq!(get_step_target(&step), Some("#user-input"));
        assert_eq!(get_step_value(&step), Some("admin"));

        step.target = Some("#direct-target".to_string());
        step.value = Some("secret".to_string());
        assert_eq!(get_step_target(&step), Some("#direct-target"));
        assert_eq!(get_step_value(&step), Some("secret"));
    }
}
