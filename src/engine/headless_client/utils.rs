use crate::models::template::HeadlessStep;
use std::time::Duration;

/// Retrieve the selector / target from a step using aliases.
pub fn get_step_target<'a>(step: &'a HeadlessStep) -> Option<&'a str> {
    step.target
        .as_deref()
        .or_else(|| step.args.get("by").map(|s| s.as_str()))
        .or_else(|| step.args.get("selector").map(|s| s.as_str()))
        .or_else(|| step.key.as_deref())
}

/// Retrieve the value from a step using aliases.
pub fn get_step_value<'a>(step: &'a HeadlessStep) -> Option<&'a str> {
    step.value
        .as_deref()
        .or_else(|| step.args.get("value").map(|s| s.as_str()))
}

/// Parse time string like "2s", "500ms", "1.5s", or numeric string into Duration.
pub fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    if s.is_empty() {
        return Duration::from_secs(1);
    }
    if let Some(ms_str) = s.strip_suffix("ms") {
        if let Ok(ms) = ms_str.trim().parse::<u64>() {
            return Duration::from_millis(ms);
        }
    }
    if let Some(s_str) = s.strip_suffix('s') {
        if let Ok(secs) = s_str.trim().parse::<f64>() {
            return Duration::from_millis((secs * 1000.0) as u64);
        }
    }
    if let Ok(num) = s.parse::<f64>() {
        if num >= 50.0 {
            // Assume milliseconds if number is >= 50
            return Duration::from_millis(num as u64);
        } else {
            return Duration::from_millis((num * 1000.0) as u64);
        }
    }
    Duration::from_secs(1)
}

/// Render a CDP-evaluated JS value as a string for matcher use.
pub fn js_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}
