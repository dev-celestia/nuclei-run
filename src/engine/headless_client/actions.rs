use crate::engine::dsl::TemplateDsl;
use crate::engine::headless_client::utils::{get_step_target, get_step_value, js_value_to_string, parse_duration};
use crate::models::template::HeadlessStep;
use chromiumoxide::cdp::browser_protocol::network::{Headers as CdpHeaders, SetExtraHttpHeadersParams};
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::Page;
use std::collections::HashMap;
use std::time::Duration;

/// Execute an individual headless action step.
pub async fn execute_step(
    page: &Page,
    step: &HeadlessStep,
    target: &str,
    current_url: &mut String,
    named: &mut HashMap<String, String>,
    extra_headers: &mut HashMap<String, String>,
    extracted_vars: &HashMap<String, String>,
) -> Result<(), String> {
    let action_name = step.action.to_lowercase();
    match action_name.as_str() {
        "navigate" => {
            let raw = step
                .args
                .get("url")
                .map(|s| s.as_str())
                .or(step.target.as_deref())
                .unwrap_or(target);
            let url = TemplateDsl::interpolate(raw, target, extracted_vars);
            *current_url = url.clone();
            page.goto(url).await.map_err(|e| e.to_string())?;
        }

        "waitload" | "wait-load" => {
            let check_js = "document.readyState === 'complete'";
            for _ in 0..50 {
                if let Ok(res) = page.evaluate(check_js).await {
                    if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        "waitdom" | "wait-dom" => {
            let check_js = "document.readyState === 'interactive' || document.readyState === 'complete'";
            for _ in 0..50 {
                if let Ok(res) = page.evaluate(check_js).await {
                    if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        "waitfcp" | "wait-fcp" => {
            let check_js = "(window.performance && performance.getEntriesByName && performance.getEntriesByName('first-contentful-paint').length > 0) || document.readyState === 'complete'";
            for _ in 0..50 {
                if let Ok(res) = page.evaluate(check_js).await {
                    if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        "waitfmp" | "wait-fmp" => {
            let check_js = "document.readyState === 'complete'";
            for _ in 0..50 {
                if let Ok(res) = page.evaluate(check_js).await {
                    if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        "waitidle" | "wait-idle" | "waitstable" | "wait-stable" => {
            let raw_dur = get_step_value(step)
                .or_else(|| step.args.get("duration").map(|s| s.as_str()))
                .or_else(|| step.args.get("time").map(|s| s.as_str()))
                .unwrap_or("500ms");
            let dur = parse_duration(raw_dur);
            tokio::time::sleep(dur).await;
        }

        "waitvisible" | "wait-visible" => {
            let sel = get_step_target(step).ok_or_else(|| "waitvisible action missing target/selector".to_string())?;
            let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
            let check_js = format!(
                "(function() {{ var el = document.querySelector({}); if (!el) return false; var style = window.getComputedStyle(el); return style && style.display !== 'none' && style.visibility !== 'hidden' && (el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0); }})()",
                serde_json::to_string(&sel).unwrap_or_default()
            );
            for _ in 0..50 {
                if let Ok(res) = page.evaluate(check_js.as_str()).await {
                    if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        "waitdialog" | "wait-dialog" | "dialog" => {
            let js = "window.alert = function(){}; window.confirm = function(){ return true; }; window.prompt = function(){ return ''; };";
            let _ = page.evaluate(js).await;
        }

        "waitevent" | "wait-event" => {
            let evt_name = get_step_value(step)
                .or_else(|| step.args.get("event").map(|s| s.as_str()))
                .unwrap_or("load");
            let js = format!(
                "new Promise(resolve => {{ if (document.readyState === 'complete') return resolve(true); window.addEventListener({}, () => resolve(true), {{once: true}}); setTimeout(() => resolve(true), 3000); }})",
                serde_json::to_string(evt_name).unwrap_or_default()
            );
            let _ = page.evaluate(js.as_str()).await;
        }

        "getresource" | "get-resource" => {
            let url_to_fetch = get_step_value(step)
                .or_else(|| step.args.get("url").map(|s| s.as_str()))
                .or(step.target.as_deref())
                .unwrap_or(target);
            let url_to_fetch = TemplateDsl::interpolate(url_to_fetch, target, extracted_vars);
            let js = format!(
                "(async function() {{ try {{ var res = await fetch({}); return await res.text(); }} catch(e) {{ return ''; }} }})()",
                serde_json::to_string(&url_to_fetch).unwrap_or_default()
            );
            if let Ok(res) = page.evaluate(js.as_str()).await {
                let value = res.value().map(js_value_to_string).unwrap_or_default();
                let step_name = step.name.as_deref().unwrap_or("resource");
                named.insert(step_name.to_string(), value);
            }
        }

        "time" => {
            if let Some(sel) = get_step_target(step) {
                let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
                let val = get_step_value(step).unwrap_or("");
                let val = TemplateDsl::interpolate(val, target, extracted_vars);
                let js = format!(
                    "(function() {{ var el = document.querySelector({}); if (el) {{ el.focus(); el.value = {}; el.dispatchEvent(new Event('input', {{bubbles: true}})); el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }} return false; }})()",
                    serde_json::to_string(&sel).unwrap_or_default(),
                    serde_json::to_string(&val).unwrap_or_default()
                );
                page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
            } else if let Some(val) = get_step_value(step) {
                let dur = parse_duration(val);
                tokio::time::sleep(dur).await;
            }
        }

        "files" => {
            if let Some(sel) = get_step_target(step) {
                let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
                let val = get_step_value(step).unwrap_or("");
                let val = TemplateDsl::interpolate(val, target, extracted_vars);
                let js = format!(
                    "(function() {{ var el = document.querySelector({}); if (el) {{ try {{ var dt = new DataTransfer(); var f = new File([''], {}); dt.items.add(f); el.files = dt.files; el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }} catch(e) {{ return false; }} }} return false; }})()",
                    serde_json::to_string(&sel).unwrap_or_default(),
                    serde_json::to_string(&val).unwrap_or_default()
                );
                let _ = page.evaluate(js.as_str()).await;
            }
        }

        "debug" => {
            let code = step
                .args
                .get("code")
                .map(|s| s.as_str())
                .or(step.code.as_deref())
                .or(step.target.as_deref())
                .unwrap_or("console.log('debug action')");
            let code = TemplateDsl::interpolate(code, target, extracted_vars);
            let _ = page.evaluate(code).await;
        }

        "wait-for" | "wait_for" | "wait" => {
            let selector = get_step_target(step);
            if let Some(sel) = selector {
                let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
                let check_js = format!("document.querySelector({}) !== null", serde_json::to_string(&sel).unwrap_or_default());
                for _ in 0..50 {
                    if let Ok(res) = page.evaluate(check_js.as_str()).await {
                        if res.value().and_then(|v| v.as_bool()).unwrap_or(false) {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } else if let Some(val) = get_step_value(step) {
                let dur = parse_duration(val);
                tokio::time::sleep(dur).await;
            }
        }

        "sleep" => {
            let raw_dur = get_step_value(step)
                .or_else(|| step.args.get("duration").map(|s| s.as_str()))
                .or_else(|| step.args.get("time").map(|s| s.as_str()))
                .or(step.target.as_deref())
                .unwrap_or("1s");
            let dur = parse_duration(raw_dur);
            tokio::time::sleep(dur).await;
        }

        "click" => {
            let sel = get_step_target(step).ok_or_else(|| "click action missing target/selector".to_string())?;
            let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
            let js = format!(
                "(function() {{ var el = document.querySelector({}); if (el) {{ el.scrollIntoView({{block:'center'}}); el.click(); return true; }} return false; }})()",
                serde_json::to_string(&sel).unwrap_or_default()
            );
            page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
        }

        "rightclick" | "right-click" => {
            let sel = get_step_target(step).ok_or_else(|| "rightclick action missing target/selector".to_string())?;
            let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
            let js = format!(
                "(function() {{ var el = document.querySelector({}); if (el) {{ el.scrollIntoView({{block:'center'}}); var evt = new MouseEvent('contextmenu', {{bubbles: true, cancelable: true, view: window, buttons: 2}}); el.dispatchEvent(evt); return true; }} return false; }})()",
                serde_json::to_string(&sel).unwrap_or_default()
            );
            page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
        }

        "text" | "type" => {
            let sel = get_step_target(step).ok_or_else(|| "text/type action missing target/selector".to_string())?;
            let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
            let val = get_step_value(step).unwrap_or("");
            let val = TemplateDsl::interpolate(val, target, extracted_vars);
            let js = format!(
                "(function() {{ var el = document.querySelector({}); if (el) {{ el.focus(); el.value = {}; el.dispatchEvent(new Event('input', {{bubbles: true}})); el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }} return false; }})()",
                serde_json::to_string(&sel).unwrap_or_default(),
                serde_json::to_string(&val).unwrap_or_default()
            );
            page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
        }

        "script" => {
            let code = step
                .args
                .get("code")
                .map(|s| s.as_str())
                .or(step.code.as_deref())
                .or(step.target.as_deref())
                .unwrap_or("");
            let code = TemplateDsl::interpolate(code, target, extracted_vars);
            let result = page.evaluate(code).await.map_err(|e| e.to_string())?;
            let value = result.value().map(js_value_to_string).unwrap_or_default();
            if let Some(name) = &step.name {
                named.insert(name.clone(), value);
            }
        }

        "screenshot" => {
            let bytes = page
                .screenshot(ScreenshotParams::builder().build())
                .await
                .map_err(|e| e.to_string())?;
            let dest = step
                .args
                .get("to")
                .map(|s| s.as_str())
                .or(step.target.as_deref())
                .or(step.value.as_deref());
            if let Some(path) = dest {
                let path = TemplateDsl::interpolate(path, target, extracted_vars);
                let _ = std::fs::write(&path, &bytes);
            }
            if let Some(name) = &step.name {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                named.insert(name.clone(), b64);
            }
        }

        "setheader" | "set-header" | "setheaders" => {
            let mut hdrs: HashMap<String, String> = step.headers.clone();
            for (k, v) in &step.args {
                if k != "part" && k != "key" && k != "value" {
                    hdrs.insert(k.clone(), v.clone());
                }
            }
            if let (Some(k), Some(v)) = (&step.key, &step.value) {
                hdrs.insert(k.clone(), v.clone());
            } else if let (Some(k), Some(v)) = (step.args.get("key"), step.args.get("value")) {
                hdrs.insert(k.clone(), v.clone());
            }
            for (k, v) in hdrs {
                let k = TemplateDsl::interpolate(&k, target, extracted_vars);
                let v = TemplateDsl::interpolate(&v, target, extracted_vars);
                extra_headers.insert(k, v);
            }
            let json_headers: serde_json::Value = serde_json::to_value(&extra_headers).unwrap_or_default();
            let cdp_headers = CdpHeaders::new(json_headers);
            let _ = page.execute(SetExtraHttpHeadersParams::new(cdp_headers)).await;
        }

        "addheader" | "add-header" => {
            let mut hdrs: HashMap<String, String> = step.headers.clone();
            for (k, v) in &step.args {
                if k != "part" && k != "key" && k != "value" {
                    hdrs.insert(k.clone(), v.clone());
                }
            }
            if let (Some(k), Some(v)) = (&step.key, &step.value) {
                hdrs.insert(k.clone(), v.clone());
            } else if let (Some(k), Some(v)) = (step.args.get("key"), step.args.get("value")) {
                hdrs.insert(k.clone(), v.clone());
            }
            for (k, v) in hdrs {
                let k = TemplateDsl::interpolate(&k, target, extracted_vars);
                let v = TemplateDsl::interpolate(&v, target, extracted_vars);
                extra_headers.insert(k, v);
            }
            let json_headers: serde_json::Value = serde_json::to_value(&extra_headers).unwrap_or_default();
            let cdp_headers = CdpHeaders::new(json_headers);
            let _ = page.execute(SetExtraHttpHeadersParams::new(cdp_headers)).await;
        }

        "deleteheader" | "delete-header" => {
            let key = step
                .key
                .as_deref()
                .or_else(|| step.args.get("key").map(|s| s.as_str()))
                .or(step.target.as_deref())
                .or(step.value.as_deref());
            if let Some(k) = key {
                let k = TemplateDsl::interpolate(k, target, extracted_vars);
                extra_headers.remove(&k);
                let json_headers: serde_json::Value = serde_json::to_value(&extra_headers).unwrap_or_default();
                let cdp_headers = CdpHeaders::new(json_headers);
                let _ = page.execute(SetExtraHttpHeadersParams::new(cdp_headers)).await;
            }
        }

        "extract" => {
            let sel = get_step_target(step);
            let attr = step
                .attribute
                .as_deref()
                .or_else(|| step.args.get("attribute").map(|s| s.as_str()))
                .or(step.key.as_deref())
                .unwrap_or("text");

            if let Some(sel) = sel {
                let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
                let js = format!(
                    "(function() {{ var el = document.querySelector({}); if (!el) return ''; var attr = {}; if (attr === 'text' || attr === 'innerText') return el.innerText || el.textContent || ''; if (attr === 'html' || attr === 'innerHTML') return el.innerHTML || ''; if (attr === 'outerHTML') return el.outerHTML || ''; return el.getAttribute(attr) || el[attr] || ''; }})()",
                    serde_json::to_string(&sel).unwrap_or_default(),
                    serde_json::to_string(attr).unwrap_or_default()
                );
                let result = page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
                let value = result.value().map(js_value_to_string).unwrap_or_default();
                let step_name = step.name.as_deref().unwrap_or("extract");
                named.insert(step_name.to_string(), value);
            } else if let Some(code) = step.code.as_deref().or_else(|| step.args.get("code").map(|s| s.as_str())) {
                let code = TemplateDsl::interpolate(code, target, extracted_vars);
                let result = page.evaluate(code).await.map_err(|e| e.to_string())?;
                let value = result.value().map(js_value_to_string).unwrap_or_default();
                let step_name = step.name.as_deref().unwrap_or("extract");
                named.insert(step_name.to_string(), value);
            }
        }

        "keyboard" | "key" => {
            let key_name = get_step_value(step)
                .or_else(|| step.args.get("key").map(|s| s.as_str()))
                .or(step.target.as_deref())
                .unwrap_or("Enter");
            let js = format!(
                "(function() {{ var k = {}; var evt = new KeyboardEvent('keydown', {{key: k, code: k, bubbles: true}}); (document.activeElement || document.body).dispatchEvent(evt); var evt2 = new KeyboardEvent('keyup', {{key: k, code: k, bubbles: true}}); (document.activeElement || document.body).dispatchEvent(evt2); return true; }})()",
                serde_json::to_string(key_name).unwrap_or_default()
            );
            page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
        }

        "select" => {
            let sel = get_step_target(step).ok_or_else(|| "select action missing target/selector".to_string())?;
            let sel = TemplateDsl::interpolate(sel, target, extracted_vars);
            let val = get_step_value(step).unwrap_or("");
            let val = TemplateDsl::interpolate(val, target, extracted_vars);
            let js = format!(
                "(function() {{ var el = document.querySelector({}); if (el) {{ for (var i = 0; i < el.options.length; i++) {{ if (el.options[i].value === {} || el.options[i].text === {}) {{ el.selectedIndex = i; el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }} }} }} return false; }})()",
                serde_json::to_string(&sel).unwrap_or_default(),
                serde_json::to_string(&val).unwrap_or_default(),
                serde_json::to_string(&val).unwrap_or_default()
            );
            page.evaluate(js.as_str()).await.map_err(|e| e.to_string())?;
        }

        other => {
            return Err(format!("unsupported headless action: {}", other));
        }
    }

    Ok(())
}
