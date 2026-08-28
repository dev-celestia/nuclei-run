use base64::{engine::general_purpose, Engine as _};
use crate::engine::dsl::functions::{html_unescape, urlencoding_decode};

/// Evaluate a DSL expression against response data.
pub fn evaluate_dsl(
    expr: &str,
    status_code: u16,
    headers: &str,
    body: &str,
    content_length: usize,
    duration_secs: f64,
) -> bool {
    let expr = expr.trim();

    // Handle boolean AND
    if let Some(pos) = find_top_level_operator(expr, "&&") {
        let left = expr[..pos].trim();
        let right = expr[pos + 2..].trim();
        return evaluate_dsl(left, status_code, headers, body, content_length, duration_secs)
            && evaluate_dsl(right, status_code, headers, body, content_length, duration_secs);
    }

    // Handle boolean OR
    if let Some(pos) = find_top_level_operator(expr, "||") {
        let left = expr[..pos].trim();
        let right = expr[pos + 2..].trim();
        return evaluate_dsl(left, status_code, headers, body, content_length, duration_secs)
            || evaluate_dsl(right, status_code, headers, body, content_length, duration_secs);
    }

    // Handle negation prefix
    if let Some(inner) = expr.strip_prefix('!') {
        return !evaluate_dsl(inner.trim(), status_code, headers, body, content_length, duration_secs);
    }

    // Handle parenthesized sub-expressions
    if expr.starts_with('(') && expr.ends_with(')') {
        return evaluate_dsl(
            &expr[1..expr.len() - 1],
            status_code,
            headers,
            body,
            content_length,
            duration_secs,
        );
    }

    // contains(part, "value")
    if let Some(args) = extract_func_args(expr, "contains") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content = resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs);
            return content.contains(&parsed[1]);
        }
    }

    // contains_all(part, "val1", "val2", ...)
    if let Some(args) = extract_func_args(expr, "contains_all") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content = resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs);
            return parsed[1..].iter().all(|val| content.contains(val));
        }
    }

    // contains_any(part, "val1", "val2", ...)
    if let Some(args) = extract_func_args(expr, "contains_any") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content = resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs);
            return parsed[1..].iter().any(|val| content.contains(val));
        }
    }

    // starts_with(part, "value")
    if let Some(args) = extract_func_args(expr, "starts_with") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content = resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs);
            return content.starts_with(&parsed[1]);
        }
    }

    // ends_with(part, "value")
    if let Some(args) = extract_func_args(expr, "ends_with") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content = resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs);
            return content.ends_with(&parsed[1]);
        }
    }

    // compare_versions(v1, op, v2)
    if let Some(args) = extract_func_args(expr, "compare_versions") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 3 {
            return evaluate_version_comparison(&parsed[0], &parsed[1], &parsed[2]);
        }
    }

    // Comparison: status_code == 200, content_length > 100, etc.
    if let Some(result) = evaluate_comparison(expr, status_code, content_length, duration_secs) {
        return result;
    }

    // True / False literals
    if expr.eq_ignore_ascii_case("true") {
        return true;
    }
    if expr.eq_ignore_ascii_case("false") {
        return false;
    }

    // Fallback: treat as a contains check on the body.
    false
}

/// Parse comma-separated arguments, respecting quotes.
pub fn parse_comma_args(args: &str) -> Vec<String> {
    let mut list = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut had_quote = false;

    for c in args.chars() {
        if in_string {
            if c == string_char {
                in_string = false;
            } else {
                current.push(c);
            }
            continue;
        }

        if c == '"' || c == '\'' {
            if current.trim().is_empty() {
                current.clear();
            }
            in_string = true;
            string_char = c;
            had_quote = true;
            continue;
        }

        if c == ',' {
            if had_quote {
                list.push(current.clone());
            } else {
                list.push(current.trim().to_string());
            }
            current.clear();
            had_quote = false;
        } else if !had_quote {
            current.push(c);
        }
    }

    if had_quote {
        list.push(current);
    } else if !current.trim().is_empty() || args.contains(',') {
        list.push(current.trim().to_string());
    }

    list
}

/// Find top level boolean operator outside of strings and parentheses.
pub fn find_top_level_operator(expr: &str, op: &str) -> Option<usize> {
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

        if depth == 0
            && i + op_bytes.len() <= bytes.len()
            && &bytes[i..i + op_bytes.len()] == op_bytes
        {
            return Some(i);
        }

        i += 1;
    }

    None
}

/// Extract arguments from `func_name(...)`.
pub fn extract_func_args(expr: &str, func_name: &str) -> Option<String> {
    let prefix = format!("{}(", func_name);
    if !expr.starts_with(&prefix) || !expr.ends_with(')') {
        return None;
    }
    Some(expr[prefix.len()..expr.len() - 1].to_string())
}

/// Resolve a part expression to its content string. Supports plain part names
/// and nested single-argument helper functions like `to_lower(header)`
/// (mirroring nuclei's DSL composition).
pub fn resolve_part_expr(expr: &str, status_code: u16, headers: &str, body: &str, duration_secs: f64) -> String {
    let expr = expr.trim();

    // Nested helper function: name(inner)
    for fname in [
        "to_lower",
        "to_upper",
        "trim",
        "reverse",
        "url_decode",
        "base64_decode",
        "hex_decode",
        "html_unescape",
        "len",
    ] {
        let prefix = format!("{}(", fname);
        if expr.starts_with(&prefix) && expr.ends_with(')') {
            let inner = &expr[prefix.len()..expr.len() - 1];
            let value = resolve_part_expr(inner, status_code, headers, body, duration_secs);
            return match fname {
                "to_lower" => value.to_lowercase(),
                "to_upper" => value.to_uppercase(),
                "trim" => value.trim().to_string(),
                "reverse" => value.chars().rev().collect(),
                "url_decode" => urlencoding_decode(&value).unwrap_or(value),
                "base64_decode" => general_purpose::STANDARD
                    .decode(value.as_bytes())
                    .map(|v| String::from_utf8_lossy(&v).to_string())
                    .unwrap_or(value),
                "hex_decode" => hex::decode(&value)
                    .map(|v| String::from_utf8_lossy(&v).to_string())
                    .unwrap_or(value),
                "html_unescape" => html_unescape(&value),
                "len" => value.len().to_string(),
                _ => value,
            };
        }
    }

    // Quoted literal
    if (expr.starts_with('\'') && expr.ends_with('\'') && expr.len() >= 2)
        || (expr.starts_with('"') && expr.ends_with('"') && expr.len() >= 2)
    {
        return expr[1..expr.len() - 1].to_string();
    }

    match expr.to_lowercase().as_str() {
        "body" => body.to_string(),
        "response" | "all" => format!("{}\n{}", headers, body),
        "header" | "headers" | "all_headers" => headers.to_string(),
        "status_code" => status_code.to_string(),
        "content_length" => body.len().to_string(),
        "duration" => duration_secs.to_string(),
        _ => body.to_string(),
    }
}

/// Evaluate comparison expression like `status_code == 200`.
pub fn evaluate_comparison(expr: &str, status_code: u16, content_length: usize, duration_secs: f64) -> Option<bool> {
    let operators = ["==", "!=", ">=", "<=", ">", "<"];

    for op in &operators {
        if let Some(pos) = expr.find(op) {
            let lhs = expr[..pos].trim();
            let rhs = expr[pos + op.len()..].trim();

            let lhs_val = resolve_numeric_var(lhs, status_code, content_length, duration_secs)?;
            let rhs_val: f64 = rhs.parse().ok()?;

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

pub fn resolve_numeric_var(name: &str, status_code: u16, content_length: usize, duration_secs: f64) -> Option<f64> {
    match name.trim() {
        "status_code" => Some(status_code as f64),
        "content_length" => Some(content_length as f64),
        "duration" => Some(duration_secs),
        _ => name.trim().parse::<f64>().ok(),
    }
}

/// Version comparator helper (e.g. `compare_versions("1.2.3", "<=", "2.0.0")`).
pub fn evaluate_version_comparison(v1: &str, op: &str, v2: &str) -> bool {
    let parse_v = |s: &str| -> Vec<u64> {
        s.split('.')
            .filter_map(|part| {
                let num_str: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
                num_str.parse().ok()
            })
            .collect()
    };

    let p1 = parse_v(v1);
    let p2 = parse_v(v2);

    match op.trim() {
        "<" => p1 < p2,
        "<=" => p1 <= p2,
        ">" => p1 > p2,
        ">=" => p1 >= p2,
        "==" | "=" => p1 == p2,
        "!=" => p1 != p2,
        _ => false,
    }
}
