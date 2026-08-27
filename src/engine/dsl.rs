use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use crc32fast::Hasher as Crc32Hasher;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::Rng;
use regex::Regex;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::IpAddr;

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

    /// Replace dynamic random generators: `{{randstr}}`, `{{rand_int(min,max)}}`,
    /// `{{rand_text_alphanumeric(len)}}`, `{{rand_text_alpha(len)}}`,
    /// `{{rand_text_numeric(len)}}`, `{{rand_base(len, charset)}}`, `{{rand_ip()}}`.
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
                    let val = rand::thread_rng().gen_range(1000..9999);
                    result.replace_range(start..start + end + 3, &val.to_string());
                }
            } else {
                break;
            }
        }

        // Handle {{rand_text_alphanumeric(len)}}
        result = Self::resolve_func_with_args(&result, "rand_text_alphanumeric", |args| {
            let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(len)
                .map(char::from)
                .collect()
        });

        // Handle {{rand_text_alpha(len)}}
        result = Self::resolve_func_with_args(&result, "rand_text_alpha", |args| {
            let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let mut rng = rand::thread_rng();
            (0..len)
                .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
                .collect()
        });

        // Handle {{rand_text_numeric(len)}}
        result = Self::resolve_func_with_args(&result, "rand_text_numeric", |args| {
            let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            const CHARSET: &[u8] = b"0123456789";
            let mut rng = rand::thread_rng();
            (0..len)
                .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
                .collect()
        });

        // Handle {{rand_ip()}}
        result = Self::resolve_func_with_args(&result, "rand_ip", |_| {
            let mut rng = rand::thread_rng();
            format!(
                "{}.{}.{}.{}",
                rng.gen_range(1..254),
                rng.gen_range(1..254),
                rng.gen_range(1..254),
                rng.gen_range(1..254)
            )
        });

        // Handle {{rand_base(len, charset)}}
        result = Self::resolve_func_with_args(&result, "rand_base", |args| {
            let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            let charset = args.get(1).map(|s| s.as_str()).unwrap_or("0123456789abcdef");
            let bytes = charset.as_bytes();
            if bytes.is_empty() {
                return String::new();
            }
            let mut rng = rand::thread_rng();
            (0..len)
                .map(|_| bytes[rng.gen_range(0..bytes.len())] as char)
                .collect()
        });

        result
    }

    /// Resolve all 50+ inline helper functions in template strings.
    fn resolve_helper_functions(input: &str) -> String {
        let mut result = input.to_string();

        // 1. Hashes & Checksums
        result = Self::resolve_func(&result, "md5", |s| {
            let mut hasher = Md5::new();
            hasher.update(s.as_bytes());
            format!("{:x}", hasher.finalize())
        });
        result = Self::resolve_func(&result, "sha1", |s| {
            let mut hasher = Sha1::new();
            hasher.update(s.as_bytes());
            format!("{:x}", hasher.finalize())
        });
        result = Self::resolve_func(&result, "sha256", |s| {
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            format!("{:x}", hasher.finalize())
        });
        result = Self::resolve_func(&result, "sha512", |s| {
            let mut hasher = Sha512::new();
            hasher.update(s.as_bytes());
            format!("{:x}", hasher.finalize())
        });
        result = Self::resolve_func(&result, "mmh3", |s| {
            murmur3_hash_str(s)
        });
        result = Self::resolve_func(&result, "crc32", |s| {
            let mut hasher = Crc32Hasher::new();
            hasher.update(s.as_bytes());
            format!("{:x}", hasher.finalize())
        });

        // 2. Encodings / Decodings
        result = Self::resolve_func(&result, "base64", |s| {
            general_purpose::STANDARD.encode(s.as_bytes())
        });
        result = Self::resolve_func(&result, "base64_decode", |s| {
            general_purpose::STANDARD
                .decode(s.as_bytes())
                .map(|v| String::from_utf8_lossy(&v).to_string())
                .unwrap_or_else(|_| s.to_string())
        });
        result = Self::resolve_func(&result, "hex_encode", |s| hex::encode(s));
        result = Self::resolve_func(&result, "hex_decode", |s| {
            hex::decode(s)
                .map(|v| String::from_utf8_lossy(&v).to_string())
                .unwrap_or_else(|_| s.to_string())
        });
        result = Self::resolve_func(&result, "url_encode", |s| urlencoding_encode(s));
        result = Self::resolve_func(&result, "url_decode", |s| {
            urlencoding_decode(s).unwrap_or_else(|_| s.to_string())
        });
        result = Self::resolve_func(&result, "html_escape", |s| html_escape(s));
        result = Self::resolve_func(&result, "html_unescape", |s| html_unescape(s));
        result = Self::resolve_func(&result, "gzip", |s| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            let _ = encoder.write_all(s.as_bytes());
            let compressed = encoder.finish().unwrap_or_default();
            hex::encode(compressed)
        });
        result = Self::resolve_func(&result, "gzip_decode", |s| {
            let bytes = hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
            let mut decoder = GzDecoder::new(&bytes[..]);
            let mut decompressed = String::new();
            let _ = decoder.read_to_string(&mut decompressed);
            decompressed
        });
        result = Self::resolve_func(&result, "gunzip", |s| {
            let bytes = hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
            let mut decoder = GzDecoder::new(&bytes[..]);
            let mut decompressed = String::new();
            let _ = decoder.read_to_string(&mut decompressed);
            decompressed
        });
        result = Self::resolve_func(&result, "zlib", |s| {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            let _ = encoder.write_all(s.as_bytes());
            let compressed = encoder.finish().unwrap_or_default();
            hex::encode(compressed)
        });
        result = Self::resolve_func(&result, "zlib_decode", |s| {
            let bytes = hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
            let mut decoder = ZlibDecoder::new(&bytes[..]);
            let mut decompressed = String::new();
            let _ = decoder.read_to_string(&mut decompressed);
            decompressed
        });

        // 3. String Transformations
        result = Self::resolve_func(&result, "to_lower", |s| s.to_lowercase());
        result = Self::resolve_func(&result, "to_upper", |s| s.to_uppercase());
        result = Self::resolve_func(&result, "trim", |s| s.trim().to_string());
        result = Self::resolve_func(&result, "reverse", |s| s.chars().rev().collect());
        result = Self::resolve_func(&result, "len", |s| s.len().to_string());

        // Multi-arg string helpers
        result = Self::resolve_func_with_args(&result, "trim_prefix", |args| {
            if args.len() >= 2 {
                args[0].strip_prefix(&args[1]).unwrap_or(&args[0]).to_string()
            } else {
                args.first().cloned().unwrap_or_default()
            }
        });
        result = Self::resolve_func_with_args(&result, "trim_suffix", |args| {
            if args.len() >= 2 {
                args[0].strip_suffix(&args[1]).unwrap_or(&args[0]).to_string()
            } else {
                args.first().cloned().unwrap_or_default()
            }
        });
        result = Self::resolve_func_with_args(&result, "replace", |args| {
            if args.len() >= 3 {
                args[0].replace(&args[1], &args[2])
            } else {
                args.first().cloned().unwrap_or_default()
            }
        });
        result = Self::resolve_func_with_args(&result, "replace_regex", |args| {
            if args.len() >= 3 {
                if let Ok(re) = Regex::new(&args[1]) {
                    re.replace_all(&args[0], &args[2]).to_string()
                } else {
                    args[0].clone()
                }
            } else {
                args.first().cloned().unwrap_or_default()
            }
        });
        result = Self::resolve_func_with_args(&result, "substr", |args| {
            if args.len() >= 3 {
                let start: usize = args[1].parse().unwrap_or(0);
                let length: usize = args[2].parse().unwrap_or(args[0].len());
                args[0].chars().skip(start).take(length).collect()
            } else if args.len() == 2 {
                let start: usize = args[1].parse().unwrap_or(0);
                args[0].chars().skip(start).collect()
            } else {
                args.first().cloned().unwrap_or_default()
            }
        });
        result = Self::resolve_func_with_args(&result, "concat", |args| args.join(""));
        result = Self::resolve_func_with_args(&result, "join", |args| {
            if args.len() >= 2 {
                let delim = &args[0];
                args[1..].join(delim)
            } else {
                args.join("")
            }
        });

        // 4. Crypto & Auth
        result = Self::resolve_func_with_args(&result, "hmac_sha256", |args| {
            if args.len() >= 2 {
                let data = &args[0];
                let key = &args[1];
                let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
                mac.update(data.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            } else {
                String::new()
            }
        });
        result = Self::resolve_func_with_args(&result, "hmac", |args| {
            if args.len() >= 3 {
                let algo = args[0].to_lowercase();
                let data = &args[1];
                let key = &args[2];
                if algo == "sha1" {
                    let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).unwrap();
                    mac.update(data.as_bytes());
                    hex::encode(mac.finalize().into_bytes())
                } else if algo == "sha512" {
                    let mut mac = Hmac::<Sha512>::new_from_slice(key.as_bytes()).unwrap();
                    mac.update(data.as_bytes());
                    hex::encode(mac.finalize().into_bytes())
                } else {
                    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
                    mac.update(data.as_bytes());
                    hex::encode(mac.finalize().into_bytes())
                }
            } else {
                String::new()
            }
        });
        result = Self::resolve_func_with_args(&result, "generate_jwt", |args| {
            if args.len() >= 3 {
                let header = general_purpose::URL_SAFE_NO_PAD.encode(args[0].as_bytes());
                let payload = general_purpose::URL_SAFE_NO_PAD.encode(args[1].as_bytes());
                let secret = &args[2];
                let sign_input = format!("{}.{}", header, payload);
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(sign_input.as_bytes());
                let signature = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
                format!("{}.{}", sign_input, signature)
            } else {
                String::new()
            }
        });

        // 5. Date & Time
        result = Self::resolve_func_with_args(&result, "now", |_| Utc::now().to_rfc3339());
        result = Self::resolve_func_with_args(&result, "unix_time", |_| Utc::now().timestamp().to_string());
        result = Self::resolve_func_with_args(&result, "date_time", |args| {
            let fmt_str = args.first().map(|s| s.as_str()).unwrap_or("%Y-%m-%d %H:%M:%S");
            Utc::now().format(fmt_str).to_string()
        });

        // 6. JSON Formatting
        result = Self::resolve_func(&result, "json_minify", |s| {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                serde_json::to_string(&v).unwrap_or_else(|_| s.to_string())
            } else {
                s.to_string()
            }
        });
        result = Self::resolve_func(&result, "json_prettify", |s| {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| s.to_string())
            } else {
                s.to_string()
            }
        });

        // 7. Math & IP Helpers
        result = Self::resolve_func_with_args(&result, "is_ip", |args| {
            args.first().map_or("false".to_string(), |ip| {
                if ip.parse::<IpAddr>().is_ok() { "true".to_string() } else { "false".to_string() }
            })
        });
        result = Self::resolve_func_with_args(&result, "is_ipv4", |args| {
            args.first().map_or("false".to_string(), |ip| {
                if let Ok(IpAddr::V4(_)) = ip.parse::<IpAddr>() { "true".to_string() } else { "false".to_string() }
            })
        });
        result = Self::resolve_func_with_args(&result, "is_ipv6", |args| {
            args.first().map_or("false".to_string(), |ip| {
                if let Ok(IpAddr::V6(_)) = ip.parse::<IpAddr>() { "true".to_string() } else { "false".to_string() }
            })
        });
        result = Self::resolve_func_with_args(&result, "is_internal_ip", |args| {
            args.first().map_or("false".to_string(), |ip_str| {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(v4) => {
                            if v4.is_private() || v4.is_loopback() || v4.is_link_local() {
                                "true".to_string()
                            } else {
                                "false".to_string()
                            }
                        }
                        IpAddr::V6(v6) => {
                            if v6.is_loopback() { "true".to_string() } else { "false".to_string() }
                        }
                    }
                } else {
                    "false".to_string()
                }
            })
        });

        result
    }

    /// Resolve single-argument functions like `{{func('value')}}`.
    fn resolve_func<F>(input: &str, func_name: &str, transform: F) -> String
    where
        F: Fn(&str) -> String,
    {
        let mut result = input.to_string();
        let prefix = format!("{{{{{}(", func_name);

        while let Some(start) = result.find(&prefix) {
            if let Some(end) = result[start..].find(")}}") {
                let inner_raw = &result[start + prefix.len()..start + end];
                let inner = inner_raw.trim().trim_matches('\'').trim_matches('"');
                let transformed = transform(inner);
                result.replace_range(start..start + end + 3, &transformed);
            } else {
                break;
            }
        }

        result
    }

    /// Resolve multi-argument functions like `{{func('a', 'b', 'c')}}`.
    fn resolve_func_with_args<F>(input: &str, func_name: &str, transform: F) -> String
    where
        F: Fn(&[String]) -> String,
    {
        let mut result = input.to_string();
        let prefix = format!("{{{{{}(", func_name);

        while let Some(start) = result.find(&prefix) {
            if let Some(end) = result[start..].find(")}}") {
                let inner_raw = &result[start + prefix.len()..start + end];
                let args = parse_comma_args(inner_raw);
                let transformed = transform(&args);
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

    /// Evaluate a DSL expression against response data.
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
            let left = expr[..pos].trim();
            let right = expr[pos + 2..].trim();
            return Self::evaluate_dsl(left, status_code, headers, body, content_length)
                && Self::evaluate_dsl(right, status_code, headers, body, content_length);
        }

        // Handle boolean OR
        if let Some(pos) = find_top_level_operator(expr, "||") {
            let left = expr[..pos].trim();
            let right = expr[pos + 2..].trim();
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
            let parsed = parse_comma_args(&args);
            if parsed.len() >= 2 {
                let content = resolve_part_name(&parsed[0], status_code, headers, body);
                return content.contains(&parsed[1]);
            }
        }

        // contains_all(part, "val1", "val2", ...)
        if let Some(args) = extract_func_args(expr, "contains_all") {
            let parsed = parse_comma_args(&args);
            if parsed.len() >= 2 {
                let content = resolve_part_name(&parsed[0], status_code, headers, body);
                return parsed[1..].iter().all(|val| content.contains(val));
            }
        }

        // contains_any(part, "val1", "val2", ...)
        if let Some(args) = extract_func_args(expr, "contains_any") {
            let parsed = parse_comma_args(&args);
            if parsed.len() >= 2 {
                let content = resolve_part_name(&parsed[0], status_code, headers, body);
                return parsed[1..].iter().any(|val| content.contains(val));
            }
        }

        // starts_with(part, "value")
        if let Some(args) = extract_func_args(expr, "starts_with") {
            let parsed = parse_comma_args(&args);
            if parsed.len() >= 2 {
                let content = resolve_part_name(&parsed[0], status_code, headers, body);
                return content.starts_with(&parsed[1]);
            }
        }

        // ends_with(part, "value")
        if let Some(args) = extract_func_args(expr, "ends_with") {
            let parsed = parse_comma_args(&args);
            if parsed.len() >= 2 {
                let content = resolve_part_name(&parsed[0], status_code, headers, body);
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
        if let Some(result) = evaluate_comparison(expr, status_code, content_length) {
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
}

/// Helper function to calculate Murmur3 32-bit hash and format as string.
fn murmur3_hash_str(s: &str) -> String {
    let mut cursor = std::io::Cursor::new(s.as_bytes());
    let hash = murmur3::murmur3_32(&mut cursor, 0).unwrap_or(0);
    (hash as i32).to_string()
}

/// Parse comma-separated arguments, respecting quotes.
fn parse_comma_args(args: &str) -> Vec<String> {
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

/// Simple URL encoding.
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

/// Simple URL decoding.
fn urlencoding_decode(input: &str) -> Result<String, std::string::FromUtf8Error> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes();

    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let (Some(d1), Some(d2)) = (hex_digit(h1), hex_digit(h2)) {
                    bytes.push((d1 << 4) | d2);
                    continue;
                }
            }
            bytes.push(b'%');
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }

    String::from_utf8(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// HTML escaping.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// HTML unescaping.
fn html_unescape(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Find top level boolean operator outside of strings and parentheses.
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
fn extract_func_args(expr: &str, func_name: &str) -> Option<String> {
    let prefix = format!("{}(", func_name);
    if !expr.starts_with(&prefix) || !expr.ends_with(')') {
        return None;
    }
    Some(expr[prefix.len()..expr.len() - 1].to_string())
}

/// Resolve a part name to its content string.
fn resolve_part_name(name: &str, status_code: u16, headers: &str, body: &str) -> String {
    match name.trim().to_lowercase().as_str() {
        "body" | "response" | "all" => body.to_string(),
        "header" | "headers" | "all_headers" => headers.to_string(),
        "status_code" => status_code.to_string(),
        _ => body.to_string(),
    }
}

/// Evaluate comparison expression like `status_code == 200`.
fn evaluate_comparison(expr: &str, status_code: u16, content_length: usize) -> Option<bool> {
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

fn resolve_numeric_var(name: &str, status_code: u16, content_length: usize) -> Option<i64> {
    match name.trim() {
        "status_code" => Some(status_code as i64),
        "content_length" => Some(content_length as i64),
        _ => name.trim().parse::<i64>().ok(),
    }
}

/// Version comparator helper (e.g. `compare_versions("1.2.3", "<=", "2.0.0")`).
fn evaluate_version_comparison(v1: &str, op: &str, v2: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_crypto_and_hashes() {
        let vars = HashMap::new();
        assert_eq!(
            TemplateDsl::interpolate("{{md5('test')}}", "http://localhost", &vars),
            "098f6bcd4621d373cade4e832627b4f6"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{sha1('test')}}", "http://localhost", &vars),
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{sha256('test')}}", "http://localhost", &vars),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{hex_encode('admin')}}", "http://localhost", &vars),
            "61646d696e"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{base64('admin:admin')}}", "http://localhost", &vars),
            "YWRtaW46YWRtaW4="
        );
        assert_eq!(
            TemplateDsl::interpolate("{{base64_decode('YWRtaW46YWRtaW4=')}}", "http://localhost", &vars),
            "admin:admin"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{url_encode('hello world&foo=bar')}}", "http://localhost", &vars),
            "hello%20world%26foo%3Dbar"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{url_decode('hello%20world%26foo%3Dbar')}}", "http://localhost", &vars),
            "hello world&foo=bar"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{html_escape('<script>alert(1)</script>')}}", "http://localhost", &vars),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{reverse('nuclei')}}", "http://localhost", &vars),
            "ielcun"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{trim_prefix('Bearer token123', 'Bearer ')}}", "http://localhost", &vars),
            "token123"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{replace('foo-bar-baz', 'bar', 'qux')}}", "http://localhost", &vars),
            "foo-qux-baz"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{substr('abcdef', '1', '3')}}", "http://localhost", &vars),
            "bcd"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{is_internal_ip('192.168.1.1')}}", "http://localhost", &vars),
            "true"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{is_internal_ip('8.8.8.8')}}", "http://localhost", &vars),
            "false"
        );
    }

    #[test]
    fn test_dsl_advanced_matching() {
        assert!(TemplateDsl::evaluate_dsl(
            "contains_all(body, \"admin\", \"dashboard\")",
            200,
            "",
            "admin dashboard v1.0",
            0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "contains_any(body, \"not_found\", \"dashboard\")",
            200,
            "",
            "admin dashboard v1.0",
            0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(header, \"HTTP/1.1\")",
            200,
            "HTTP/1.1 200 OK",
            "",
            0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "ends_with(body, \"</html>\")",
            200,
            "",
            "<html><body>test</body></html>",
            0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "compare_versions(\"1.4.2\", \"<\", \"2.0.0\")",
            200,
            "",
            "",
            0
        ));
    }
}

