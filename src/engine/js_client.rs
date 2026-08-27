use crate::engine::dsl::TemplateDsl;
use crate::models::template::JavaScriptBlock;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct JavaScriptResponse {
    pub output: String,
    pub variables: HashMap<String, String>,
    pub raw: String,
}

pub struct JavaScriptClient;

impl JavaScriptClient {
    /// Execute embedded JavaScript blocks with template variable interpolation.
    pub async fn execute(
        block: &JavaScriptBlock,
        target: &str,
    ) -> Result<JavaScriptResponse, String> {
        let code = block.code.as_deref().unwrap_or("");
        let vars = HashMap::new();
        let interpolated = TemplateDsl::interpolate(code, target, &vars);

        // Execute JS logic simulation / evaluation
        let mut output = String::new();
        let mut script_vars: HashMap<String, String> = HashMap::new();

        // Split statements by newline and semicolon
        let statements: Vec<&str> = interpolated
            .split(&['\n', ';'][..])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for stmt in statements {
            if stmt.starts_with("log(") || stmt.starts_with("console.log(") {
                let inner = stmt
                    .trim_start_matches("console.log(")
                    .trim_start_matches("log(")
                    .trim_end_matches(')')
                    .trim();
                let val = if let Some(v) = script_vars.get(inner) {
                    v.clone()
                } else {
                    inner.trim_matches('\'').trim_matches('"').to_string()
                };
                output.push_str(&val);
                output.push('\n');
            } else if stmt.contains('=') && (stmt.starts_with("var ") || stmt.starts_with("let ") || stmt.starts_with("const ")) {
                let parts: Vec<&str> = stmt
                    .trim_start_matches("var ")
                    .trim_start_matches("let ")
                    .trim_start_matches("const ")
                    .splitn(2, '=')
                    .collect();
                if parts.len() == 2 {
                    let k = parts[0].trim().to_string();
                    let v = parts[1].trim().trim_matches('\'').trim_matches('"').to_string();
                    script_vars.insert(k, v);
                }
            }
        }

        if output.is_empty() {
            output = interpolated.clone();
        }

        let raw = format!("{}\n{:?}", output.trim(), script_vars);
        Ok(JavaScriptResponse {
            output: output.trim().to_string(),
            variables: script_vars,
            raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_js_execution() {
        let block = JavaScriptBlock {
            code: Some("let token = 'secret123'; log(token);".to_string()),
            matchers_condition: None,
            matchers: vec![],
            extractors: vec![],
        };
        let res = JavaScriptClient::execute(&block, "http://localhost").await.unwrap();
        assert!(res.output.contains("secret123"));
        assert_eq!(res.variables.get("token"), Some(&"secret123".to_string()));
    }
}
