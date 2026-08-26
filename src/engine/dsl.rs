use md5::{Digest, Md5};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use std::collections::HashMap;

/// Evaluates dynamic Nuclei DSL expressions, helper functions, and variable interpolation.
pub struct TemplateDsl;

impl TemplateDsl {
    /// Interpolate all dynamic variables, standard placeholders, custom variables,
    /// and helper functions in the given input string.
    pub fn interpolate(
        input: &str,
        target_url: &str,
        custom_vars: &HashMap<String, String>,
    ) -> String {
        // Step 1: Resolve standard URL placeholders via the variable resolver.
        let mut resolved = crate::engine::variables::VariableResolver::resolve(input, target_url);

        // Step 2: Substitute custom/extracted variables (e.g., from previous requests).
        for (k, v) in custom_vars {
            resolved = resolved.replace(&format!("{{{{{}}}}}", k), v);
        }

        // Step 3: Dynamic random generators.
        resolved = Self::resolve_random_generators(&resolved);

        // Step 4: Helper functions.
        resolved = Self::resolve_helper_functions(&resolved);

        resolved
    }

    /// Replace `{{randstr}}` with a 12-char random alphanumeric string
    /// and `{{rand_int(min,max)}}` with a random integer in the given range.
    fn resolve_random_generators(input: &str) -> String {
        let mut result = input.to_string();

        // Handle {{randstr}} — each occurrence gets a unique value.
        while result.contains("{{randstr}}") {
            let rand_val: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(12)
                .map(char::from)
                .collect();
            result = result.replacen("{{randstr}}", &rand_val, 1);
        }

        // Handle {{rand_int(min,max)}}
        while let Some(start) = result.find("{{rand_int(") {
            if let Some(end) = result[start..].find(")}}") {
                let inner = &result[start + 11..start + end];
                let parts: Vec<&str> = inner.split(',').collect();
                if parts.len() == 2 {
                    let min: i64 = parts[0].trim().parse().unwrap_or(0);
                    let max: i64 = parts[1].trim().parse().unwrap_or(9999);
                    let val = rand::thread_rng().gen_range(min..=max);
                    result.replace_range(start..start + end + 3, &val.to_string());
                } else {
                    // Malformed — generate a default random int.
                    let val = rand::thread_rng().gen_range(1000..9999);
                    result.replace_range(start..start + end + 3, &val.to_string());
                }
            } else {
                break;
            }
        }

        result
    }

    /// Resolve inline helper functions: {{base64('...')}}, {{md5('...')}},
    /// {{to_lower('...')}}, {{to_upper('...')}}, {{url_encode('...')}}.
    fn resolve_helper_functions(input: &str) -> String {
        let mut result = input.to_string();

        // {{base64('...')}}
        result = Self::resolve_func(&result, "base64", |inner| {
            general_purpose::STANDARD.encode(inner.as_bytes())
        });

        // {{base64_decode('...')}}
        result = Self::resolve_func(&result, "base64_decode", |inner| {
            general_purpose::STANDARD
                .decode(inner.as_bytes())
                .map(|v| String::from_utf8_lossy(&v).to_string())
                .unwrap_or_else(|_| inner.to_string())
        });

        // {{md5('...')}}
        result = Self::resolve_func(&result, "md5", |inner| {
            let mut hasher = Md5::new();
            hasher.update(inner.as_bytes());
            format!("{:x}", hasher.finalize())
        });

        // {{to_lower('...')}}
        result = Self::resolve_func(&result, "to_lower", |inner| inner.to_lowercase());

        // {{to_upper('...')}}
        result = Self::resolve_func(&result, "to_upper", |inner| inner.to_uppercase());

        // {{url_encode('...')}}
        result = Self::resolve_func(&result, "url_encode", |inner| {
            urlencoding_encode(inner)
        });

        result
    }

    /// Generic helper to resolve `{{func_name('...')}}` or `{{func_name("...")}}` patterns.
    fn resolve_func<F>(input: &str, func_name: &str, transform: F) -> String
    where
        F: Fn(&str) -> String,
    {
        let mut result = input.to_string();
        let prefix = format!("{{{{{}(", func_name);

        while let Some(start) = result.find(&prefix) {
            if let Some(end) = result[start..].find(")}}") {
                let inner_raw = &result[start + prefix.len()..start + end];
                // Strip surrounding quotes if present.
                let inner = inner_raw
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"');
                let transformed = transform(inner);
                result.replace_range(start..start + end + 3, &transformed);
            } else {
                break;
            }
        }

        result
    }

    // -----------------------------------------------------------------------
    // DSL Expression Evaluator (for matcher type = "dsl")
    // -----------------------------------------------------------------------

    /// Evaluate a simple DSL expression against response data.
    /// Supports: `status_code == 200`, `contains(body, "text")`,
    /// `content_length > 0`, boolean operators `&&` and `||`.
    pub fn evaluate_dsl(
        expr: &str,
        status_code: u16,
        headers: &str,
        body: &str,
        content_length: usize,
    ) -> bool {
        let expr = expr.trim();

        // Handle boolean AND
        if let Some(pos) = find_top_level_operator(expr, "&&") {
            let left = &expr[..pos].trim();
            let right = &expr[pos + 2..].trim();
            return Self::evaluate_dsl(left, status_code, headers, body, content_length)
                && Self::evaluate_dsl(right, status_code, headers, body, content_length);
        }

        // Handle boolean OR
        if let Some(pos) = find_top_level_operator(expr, "||") {
            let left = &expr[..pos].trim();
            let right = &expr[pos + 2..].trim();
            return Self::evaluate_dsl(left, status_code, headers, body, content_length)
                || Self::evaluate_dsl(right, status_code, headers, body, content_length);
        }

        // Handle negation prefix
        if let Some(inner) = expr.strip_prefix('!') {
            return !Self::evaluate_dsl(inner.trim(), status_code, headers, body, content_length);
        }

        // Handle parenthesized sub-expressions
        if expr.starts_with('(') && expr.ends_with(')') {
            return Self::evaluate_dsl(
                &expr[1..expr.len() - 1],
                status_code,
                headers,
                body,
                content_length,
            );
        }

        // contains(part, "value")
        if let Some(args) = extract_func_args(expr, "contains") {
            if let Some((part_name, value)) = split_two_args(&args) {
                let content = resolve_part_name(&part_name, status_code, headers, body);
                return content.contains(&value);
            }
        }

        // starts_with(part, "value")
        if let Some(args) = extract_func_args(expr, "starts_with") {
            if let Some((part_name, value)) = split_two_args(&args) {
                let content = resolve_part_name(&part_name, status_code, headers, body);
                return content.starts_with(&value);
            }
        }

        // ends_with(part, "value")
        if let Some(args) = extract_func_args(expr, "ends_with") {
            if let Some((part_name, value)) = split_two_args(&args) {
                let content = resolve_part_name(&part_name, status_code, headers, body);
                return content.ends_with(&value);
            }
        }

        // len(part) operator value
        if expr.starts_with("len(") {
            // Not commonly used, skip for now.
            return false;
        }

        // Comparison: status_code == 200, content_length > 100, etc.
        if let Some(result) = evaluate_comparison(expr, status_code, content_length) {
            return result;
        }

        // Fallback: treat as a contains check on the body.
        false
    }
}

/// Simple URL encoding without pulling in another crate.
fn urlencoding_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Find the position of a top-level boolean operator (not inside parentheses).
fn find_top_level_operator(expr: &str, op: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut string_char = '"';
    let bytes = expr.as_bytes();
    let op_bytes = op.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;

        if in_string {
            if c == string_char && (i == 0 || bytes[i - 1] != b'\\') {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == '"' || c == '\'' {
            in_string = true;
            string_char = c;
            i += 1;
            continue;
        }

        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        }

        if depth == 0 && i + op_bytes.len() <= bytes.len() && &bytes[i..i + op_bytes.len()] == op_bytes {
            return Some(i);
        }

        i += 1;
    }

    None
}

/// Extract arguments from a function call like `func_name(args)`.
fn extract_func_args(expr: &str, func_name: &str) -> Option<String> {
    let prefix = format!("{}(", func_name);
    if !expr.starts_with(&prefix) || !expr.ends_with(')') {
        return None;
    }
    Some(expr[prefix.len()..expr.len() - 1].to_string())
}

/// Split two comma-separated arguments, handling quoted strings.
fn split_two_args(args: &str) -> Option<(String, String)> {
    // Find the first comma that's not inside quotes.
    let mut in_string = false;
    let mut string_char = '"';
    let mut split_pos = None;

    for (i, c) in args.char_indices() {
        if in_string {
            if c == string_char {
                in_string = false;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = true;
            string_char = c;
            continue;
        }
        if c == ',' {
            split_pos = Some(i);
            break;
        }
    }

    let pos = split_pos?;
    let first = args[..pos].trim().trim_matches('"').trim_matches('\'').to_string();
    let second = args[pos + 1..].trim().trim_matches('"').trim_matches('\'').to_string();
    Some((first, second))
}

/// Resolve a part name to its content string.
fn resolve_part_name(name: &str, status_code: u16, headers: &str, body: &str) -> String {
    match name.trim().to_lowercase().as_str() {
        "body" | "response" => body.to_string(),
        "header" | "headers" | "all_headers" => headers.to_string(),
        "status_code" => status_code.to_string(),
        _ => body.to_string(),
    }
}

/// Evaluate a simple comparison expression like `status_code == 200`.
fn evaluate_comparison(expr: &str, status_code: u16, content_length: usize) -> Option<bool> {
    // Supported comparisons: ==, !=, >, <, >=, <=
    let operators = ["==", "!=", ">=", "<=", ">", "<"];

    for op in &operators {
        if let Some(pos) = expr.find(op) {
            let lhs = expr[..pos].trim();
            let rhs = expr[pos + op.len()..].trim();

            let lhs_val = resolve_numeric_var(lhs, status_code, content_length)?;
            let rhs_val: i64 = rhs.parse().ok()?;

            return Some(match *op {
                "==" => lhs_val == rhs_val,
                "!=" => lhs_val != rhs_val,
                ">=" => lhs_val >= rhs_val,
                "<=" => lhs_val <= rhs_val,
                ">" => lhs_val > rhs_val,
                "<" => lhs_val < rhs_val,
                _ => false,
            });
        }
    }

    None
}

/// Resolve a named numeric variable to its value.
fn resolve_numeric_var(name: &str, status_code: u16, content_length: usize) -> Option<i64> {
    match name.trim() {
        "status_code" => Some(status_code as i64),
        "content_length" => Some(content_length as i64),
        _ => name.trim().parse::<i64>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_base64() {
        let result = TemplateDsl::interpolate(
            "{{base64('admin:admin')}}",
            "http://localhost",
            &HashMap::new(),
        );
        assert_eq!(result, "YWRtaW46YWRtaW4=");
    }

    #[test]
    fn test_interpolate_md5() {
        let result = TemplateDsl::interpolate(
            "{{md5('test')}}",
            "http://localhost",
            &HashMap::new(),
        );
        assert_eq!(result, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_dsl_status_code() {
        assert!(TemplateDsl::evaluate_dsl("status_code == 200", 200, "", "", 0));
        assert!(!TemplateDsl::evaluate_dsl("status_code == 200", 404, "", "", 0));
    }

    #[test]
    fn test_dsl_contains() {
        assert!(TemplateDsl::evaluate_dsl(
            "contains(body, \"admin\")",
            200,
            "",
            "Welcome admin panel",
            0
        ));
    }

    #[test]
    fn test_dsl_and_operator() {
        assert!(TemplateDsl::evaluate_dsl(
            "status_code == 200 && contains(body, \"index\")",
            200,
            "",
            "index.php",
            0
        ));
    }

    #[test]
    fn test_randstr_unique() {
        let result = TemplateDsl::interpolate(
            "{{randstr}}-{{randstr}}",
            "http://localhost",
            &HashMap::new(),
        );
        let parts: Vec<&str> = result.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert_ne!(parts[0], parts[1]); // Each {{randstr}} should produce a unique value.
    }
}
