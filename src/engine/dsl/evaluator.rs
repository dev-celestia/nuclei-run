use crate::engine::dsl::functions::{
    crc32_hex, html_escape, html_unescape, md5_hex, murmur3_hash_str, sha1_hex, sha256_hex,
    sha512_hex, urlencoding_decode, urlencoding_encode,
};
use crate::engine::matcher::parts::calculate_content_length;
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use std::collections::HashMap;

/// Evaluate a DSL expression against response data.
/// `vars` carries the per-response variable map (response headers, cookies,
/// and extracted values) that Go nuclei exposes to every DSL expression.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_dsl(
    expr: &str,
    status_code: u16,
    headers: &str,
    body: &str,
    content_length: usize,
    duration_secs: f64,
    vars: &HashMap<String, String>,
) -> bool {
    let expr = expr.trim();

    // Handle boolean AND
    if let Some(pos) = find_top_level_operator(expr, "&&") {
        let left = expr[..pos].trim();
        let right = expr[pos + 2..].trim();
        return evaluate_dsl(left, status_code, headers, body, content_length, duration_secs, vars)
            && evaluate_dsl(right, status_code, headers, body, content_length, duration_secs, vars);
    }

    // Handle boolean OR
    if let Some(pos) = find_top_level_operator(expr, "||") {
        let left = expr[..pos].trim();
        let right = expr[pos + 2..].trim();
        return evaluate_dsl(left, status_code, headers, body, content_length, duration_secs, vars)
            || evaluate_dsl(right, status_code, headers, body, content_length, duration_secs, vars);
    }

    // Handle negation prefix
    if let Some(inner) = expr.strip_prefix('!') {
        return !evaluate_dsl(
            inner.trim(),
            status_code,
            headers,
            body,
            content_length,
            duration_secs,
            vars,
        );
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
            vars,
        );
    }

    // contains(part, "value")
    if let Some(args) = extract_func_args(expr, "contains") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            return content.contains(unquote(&parsed[1]));
        }
    }

    // contains_all(part, "val1", "val2", ...)
    if let Some(args) = extract_func_args(expr, "contains_all") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            return parsed[1..].iter().all(|val| content.contains(unquote(val)));
        }
    }

    // contains_any(part, "val1", "val2", ...)
    if let Some(args) = extract_func_args(expr, "contains_any") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            return parsed[1..].iter().any(|val| content.contains(unquote(val)));
        }
    }

    // starts_with(part, "value")
    if let Some(args) = extract_func_args(expr, "starts_with") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            return content.starts_with(unquote(&parsed[1]));
        }
    }

    // ends_with(part, "value")
    if let Some(args) = extract_func_args(expr, "ends_with") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            return content.ends_with(unquote(&parsed[1]));
        }
    }

    // equals_any(part, "val1", "val2", ...)
    if let Some(args) = extract_func_args(expr, "equals_any") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            return parsed[1..]
                .iter()
                .any(|val| content == unquote(val));
        }
    }

    // line_starts_with(part, "prefix")
    if let Some(args) = extract_func_args(expr, "line_starts_with") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            let prefix = unquote(&parsed[1]);
            return content.lines().any(|line| line.starts_with(prefix));
        }
    }

    // line_ends_with(part, "suffix")
    if let Some(args) = extract_func_args(expr, "line_ends_with") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 2 {
            let content =
                resolve_part_expr(&parsed[0], status_code, headers, body, duration_secs, vars);
            let suffix = unquote(&parsed[1]);
            return content.lines().any(|line| line.ends_with(suffix));
        }
    }

    // compare_versions(v1, op, v2)
    if let Some(args) = extract_func_args(expr, "compare_versions") {
        let parsed = parse_comma_args(&args);
        if parsed.len() >= 3 {
            return evaluate_version_comparison(
                unquote(&parsed[0]),
                unquote(&parsed[1]),
                unquote(&parsed[2]),
            );
        }
    }

    // Comparison: status_code == 200, content_length > 100, etc.
    if let Some(result) =
        evaluate_comparison(expr, status_code, headers, body, content_length, duration_secs, vars)
    {
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

/// Evaluate a DSL expression and return its value, mirroring Go's
/// `ExtractDSL`: boolean expressions render as "true"/"false", everything
/// else resolves through the part/function/variable machinery.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_dsl_value(
    expr: &str,
    status_code: u16,
    headers: &str,
    body: &str,
    content_length: usize,
    duration_secs: f64,
    vars: &HashMap<String, String>,
) -> Option<String> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }

    let looks_boolean = expr.eq_ignore_ascii_case("true")
        || expr.eq_ignore_ascii_case("false")
        || expr.starts_with('!')
        || find_top_level_operator(expr, "&&").is_some()
        || find_top_level_operator(expr, "||").is_some()
        || evaluate_comparison(expr, status_code, headers, body, content_length, duration_secs, vars)
            .is_some();

    if looks_boolean {
        return Some(evaluate_dsl(expr, status_code, headers, body, content_length, duration_secs, vars).to_string());
    }

    Some(resolve_part_expr(expr, status_code, headers, body, duration_secs, vars))
}

/// Strip surrounding single or double quotes if present.
pub fn unquote(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Parse comma-separated arguments, respecting quotes and parentheses.
pub fn parse_comma_args(args: &str) -> Vec<String> {
    let mut list = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut paren_depth = 0i32;

    for c in args.chars() {
        if in_string {
            current.push(c);
            if c == string_char {
                in_string = false;
            }
            continue;
        }

        if c == '"' || c == '\'' {
            in_string = true;
            string_char = c;
            current.push(c);
            continue;
        }

        if c == '(' {
            paren_depth += 1;
            current.push(c);
            continue;
        }

        if c == ')' {
            paren_depth -= 1;
            current.push(c);
            continue;
        }

        if c == ',' && paren_depth == 0 {
            list.push(current.trim().to_string());
            current.clear();
            continue;
        }

        current.push(c);
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() || !list.is_empty() {
        list.push(trimmed.to_string());
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

/// Split a `name(args...)` expression into function name and raw arguments.
fn split_func_call(expr: &str) -> Option<(&str, &str)> {
    if !expr.ends_with(')') {
        return None;
    }
    let open = expr.find('(')?;
    let name = &expr[..open];
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some((name, &expr[open + 1..expr.len() - 1]))
}

/// Resolve a function argument: quoted literals stay literal, everything
/// else is resolved recursively as a part/function/variable expression.
fn resolve_argument(
    arg: &str,
    status_code: u16,
    headers: &str,
    body: &str,
    duration_secs: f64,
    vars: &HashMap<String, String>,
) -> String {
    let arg = arg.trim();
    if (arg.starts_with('"') && arg.ends_with('"') && arg.len() >= 2)
        || (arg.starts_with('\'') && arg.ends_with('\'') && arg.len() >= 2)
    {
        return arg[1..arg.len() - 1].to_string();
    }
    resolve_part_expr(arg, status_code, headers, body, duration_secs, vars)
}

/// Apply a DSL value function by name (Go `dsl.HelperFunctions` parity for
/// the high-impact subset). Returns `None` for unknown functions or when the
/// required arguments are missing.
fn apply_dsl_function(fname: &str, args: &[String]) -> Option<String> {
    let one = || args.first().map(String::as_str);
    match fname {
        // String transformations
        "to_lower" => Some(one()?.to_lowercase()),
        "to_upper" => Some(one()?.to_uppercase()),
        "to_title" => Some(title_case(one()?)),
        "trim" | "trim_space" => Some(match args.len() {
            n if n >= 2 => trim_cutset(&args[0], &args[1]),
            _ => one()?.trim().to_string(),
        }),
        "trim_left" => Some(trim_cutset_start(one()?, args.get(1)?.as_str())),
        "trim_right" => Some(trim_cutset_end(one()?, args.get(1)?.as_str())),
        "trim_prefix" => Some(args[0].strip_prefix(args.get(1)?.as_str()).unwrap_or(&args[0]).to_string()),
        "trim_suffix" => Some(args[0].strip_suffix(args.get(1)?.as_str()).unwrap_or(&args[0]).to_string()),
        "reverse" => Some(one()?.chars().rev().collect()),
        "len" => Some(one()?.len().to_string()),
        "repeat" => Some(one()?.repeat(args.get(1)?.parse::<usize>().ok()?)),
        "replace" => Some(args[0].replace(args.get(1)?.as_str(), args.get(2)?.as_str())),
        "replace_regex" => {
            let re = Regex::new(args.get(1)?).ok()?;
            Some(re.replace_all(&args[0], args.get(2)?.as_str()).to_string())
        }
        "remove_bad_chars" => {
            let bad: Vec<char> = args.get(1)?.chars().collect();
            Some(args[0].chars().filter(|c| !bad.contains(c)).collect())
        }
        "substr" => {
            let chars: Vec<char> = args[0].chars().collect();
            let start = args.get(1)?.parse::<usize>().ok()?.min(chars.len());
            let end = args
                .get(2)
                .and_then(|e| e.parse::<usize>().ok())
                .unwrap_or(chars.len())
                .min(chars.len());
            if end < start {
                return Some(String::new());
            }
            Some(chars[start..end].iter().collect())
        }
        "regex" => {
            let re = Regex::new(one()?).ok()?;
            Some(
                re.find(args.get(1)?.as_str())
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            )
        }
        "count" => Some(args[0].matches(args.get(1)?.as_str()).count().to_string()),
        "concat" => Some(args.join("")),
        "split" => Some(args[0].split(args.get(1)?.as_str()).collect::<Vec<_>>().join(",")),

        // Encodings / hashes
        "base64" => Some(general_purpose::STANDARD.encode(one()?.as_bytes())),
        "base64_py" => Some(format!(
            "b'{}'",
            general_purpose::STANDARD.encode(one()?.as_bytes())
        )),
        "base64_decode" => Some(
            general_purpose::STANDARD
                .decode(one()?.as_bytes())
                .map(|v| String::from_utf8_lossy(&v).to_string())
                .unwrap_or_else(|_| one().unwrap().to_string()),
        ),
        "hex_encode" => Some(hex::encode(one()?)),
        "hex_decode" => Some(
            hex::decode(one()?)
                .map(|v| String::from_utf8_lossy(&v).to_string())
                .unwrap_or_else(|_| one().unwrap().to_string()),
        ),
        "url_encode" => Some(urlencoding_encode(one()?)),
        "url_decode" => Some(urlencoding_decode(one()?).unwrap_or_else(|_| one().unwrap().to_string())),
        "html_escape" => Some(html_escape(one()?)),
        "html_unescape" => Some(html_unescape(one()?)),
        "md5" => Some(md5_hex(one()?)),
        "sha1" => Some(sha1_hex(one()?)),
        "sha256" => Some(sha256_hex(one()?)),
        "sha512" => Some(sha512_hex(one()?)),
        "mmh3" => Some(murmur3_hash_str(one()?)),
        "crc32" => Some(crc32_hex(one()?)),

        // Numeric conversions
        "dec_to_hex" => Some(format!("{:x}", one()?.parse::<i64>().ok()?)),
        "hex_to_dec" => Some(i64::from_str_radix(one()?, 16).ok()?.to_string()),
        "oct_to_dec" => Some(i64::from_str_radix(one()?, 8).ok()?.to_string()),
        "bin_to_dec" => Some(i64::from_str_radix(one()?, 2).ok()?.to_string()),
        "to_number" => Some(one()?.parse::<f64>().ok()?.to_string()),
        "to_string" => Some(one()?.to_string()),
        "to_bool" => Some(match one()?.to_lowercase().as_str() {
            "true" | "1" | "t" | "yes" => "true",
            _ => "false",
        }.to_string()),

        // Time
        "unix_time" => Some(chrono::Utc::now().timestamp().to_string()),
        "date_time" => Some(
            chrono::Utc::now()
                .format(args.first().map(String::as_str).unwrap_or("%Y-%m-%d %H:%M:%S"))
                .to_string(),
        ),
        "to_unix_time" => {
            let input = one()?;
            if args.len() >= 2 {
                let fmt = args.get(1)?.as_str();
                let naive = chrono::NaiveDateTime::parse_from_str(input, fmt).ok()?;
                Some(naive.and_utc().timestamp().to_string())
            } else {
                let dt = chrono::DateTime::parse_from_rfc3339(input).ok()?;
                Some(dt.timestamp().to_string())
            }
        }

        _ => None,
    }
}

fn title_case(input: &str) -> String {
    input
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn trim_cutset(input: &str, cutset: &str) -> String {
    let cut: Vec<char> = cutset.chars().collect();
    input.trim_matches(|c| cut.contains(&c)).to_string()
}

fn trim_cutset_start(input: &str, cutset: &str) -> String {
    let cut: Vec<char> = cutset.chars().collect();
    input.trim_start_matches(|c| cut.contains(&c)).to_string()
}

fn trim_cutset_end(input: &str, cutset: &str) -> String {
    let cut: Vec<char> = cutset.chars().collect();
    input.trim_end_matches(|c| cut.contains(&c)).to_string()
}

/// Resolve a part expression to its content string. Supports plain part
/// names, response variables, and nested DSL value functions like
/// `to_lower(header)` or `remove_bad_chars(body, "()")`.
pub fn resolve_part_expr(
    expr: &str,
    status_code: u16,
    headers: &str,
    body: &str,
    duration_secs: f64,
    vars: &HashMap<String, String>,
) -> String {
    let expr = expr.trim();

    // Function call: name(arg1, arg2, ...)
    if let Some((fname, args_raw)) = split_func_call(expr) {
        let args: Vec<String> = parse_comma_args(args_raw)
            .into_iter()
            .map(|arg| resolve_argument(&arg, status_code, headers, body, duration_secs, vars))
            .collect();
        if let Some(value) = apply_dsl_function(fname, &args) {
            return value;
        }
        // Unknown function: fall through to part/variable lookup.
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
        "content_length" => calculate_content_length(headers, body).to_string(),
        "duration" => duration_secs.to_string(),
        _ => {
            // Per-response variables (headers, cookies, extracted values).
            if let Some(value) = vars.get(expr).or_else(|| vars.get(&expr.to_lowercase())) {
                return value.clone();
            }
            body.to_string()
        }
    }
}

/// Evaluate comparison expression like `status_code == 200` or
/// `to_unix_time(body) == 1672531200`.
pub fn evaluate_comparison(
    expr: &str,
    status_code: u16,
    headers: &str,
    body: &str,
    content_length: usize,
    duration_secs: f64,
    vars: &HashMap<String, String>,
) -> Option<bool> {
    let operators = ["==", "!=", ">=", "<=", ">", "<"];

    for op in &operators {
        if let Some(pos) = expr.find(op) {
            let lhs = expr[..pos].trim();
            let rhs = expr[pos + op.len()..].trim();

            let lhs_val = resolve_numeric_var(lhs, status_code, content_length, duration_secs, vars)
                .or_else(|| {
                    // Function calls and variables on the left-hand side.
                    resolve_part_expr(lhs, status_code, headers, body, duration_secs, vars)
                        .parse::<f64>()
                        .ok()
                });
            let rhs_val: Option<f64> = rhs
                .parse()
                .ok()
                .or_else(|| vars.get(rhs)?.parse::<f64>().ok());

            if let (Some(lhs_val), Some(rhs_val)) = (lhs_val, rhs_val) {
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

            // String comparison fallback (Go DSL compares strings with
            // == / !=): used by protocol variables such as
            // `issuer_cn == "Let's Encrypt"`.
            if matches!(*op, "==" | "!=") {
                let lhs_str =
                    resolve_part_expr(lhs, status_code, headers, body, duration_secs, vars);
                let rhs_str = unquote(rhs);
                let rhs_str = if rhs_str != rhs || rhs.parse::<f64>().is_ok() {
                    rhs_str.to_string()
                } else {
                    resolve_part_expr(rhs, status_code, headers, body, duration_secs, vars)
                };
                return Some(match *op {
                    "==" => lhs_str == rhs_str,
                    _ => lhs_str != rhs_str,
                });
            }

            return None;
        }
    }

    None
}

pub fn resolve_numeric_var(
    name: &str,
    status_code: u16,
    content_length: usize,
    duration_secs: f64,
    vars: &HashMap<String, String>,
) -> Option<f64> {
    let name = name.trim();
    match name {
        "status_code" => Some(status_code as f64),
        "content_length" => Some(content_length as f64),
        "duration" => Some(duration_secs),
        _ => name
            .parse::<f64>()
            .ok()
            .or_else(|| vars.get(name)?.parse::<f64>().ok()),
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
