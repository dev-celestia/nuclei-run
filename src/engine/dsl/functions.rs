use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use crc32fast::Hasher as Crc32Hasher;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use regex::Regex;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::io::{Read, Write};
use std::net::IpAddr;

/// Replace helper functions like `{{to_lower("...")}}`, `{{base64("...")}}`,
/// `{{md5("...")}}`, `{{sha256("...")}}`, `{{hex_encode("...")}}`,
/// `{{url_encode("...")}}`, `{{html_escape("...")}}`, etc.
pub fn resolve_helper_functions(input: &str) -> String {
    let mut result = input.to_string();

    // 1. Hashes & Checksums
    result = resolve_func(&result, "md5", md5_hex);
    result = resolve_func(&result, "sha1", sha1_hex);
    result = resolve_func(&result, "sha256", sha256_hex);
    result = resolve_func(&result, "sha512", sha512_hex);
    result = resolve_func(&result, "mmh3", murmur3_hash_str);
    result = resolve_func(&result, "crc32", crc32_hex);

    // 2. Encodings / Decodings
    result = resolve_func(&result, "base64", |s| {
        general_purpose::STANDARD.encode(s.as_bytes())
    });
    result = resolve_func(&result, "base64_decode", |s| {
        general_purpose::STANDARD
            .decode(s.as_bytes())
            .map(|v| String::from_utf8_lossy(&v).to_string())
            .unwrap_or_else(|_| s.to_string())
    });
    result = resolve_func(&result, "hex_encode", |s| hex::encode(s));
    result = resolve_func(&result, "hex_decode", |s| {
        hex::decode(s)
            .map(|v| String::from_utf8_lossy(&v).to_string())
            .unwrap_or_else(|_| s.to_string())
    });
    result = resolve_func(&result, "url_encode", urlencoding_encode);
    result = resolve_func(&result, "url_decode", |s| {
        urlencoding_decode(s).unwrap_or_else(|_| s.to_string())
    });
    result = resolve_func(&result, "html_escape", html_escape);
    result = resolve_func(&result, "html_unescape", html_unescape);
    result = resolve_func(&result, "gzip", |s| {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        let _ = encoder.write_all(s.as_bytes());
        let compressed = encoder.finish().unwrap_or_default();
        hex::encode(compressed)
    });
    result = resolve_func(&result, "gzip_decode", |s| {
        let bytes = hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut decompressed = String::new();
        let _ = decoder.read_to_string(&mut decompressed);
        decompressed
    });
    result = resolve_func(&result, "gunzip", |s| {
        let bytes = hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut decompressed = String::new();
        let _ = decoder.read_to_string(&mut decompressed);
        decompressed
    });
    result = resolve_func(&result, "zlib", |s| {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        let _ = encoder.write_all(s.as_bytes());
        let compressed = encoder.finish().unwrap_or_default();
        hex::encode(compressed)
    });
    result = resolve_func(&result, "zlib_decode", |s| {
        let bytes = hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
        let mut decoder = ZlibDecoder::new(&bytes[..]);
        let mut decompressed = String::new();
        let _ = decoder.read_to_string(&mut decompressed);
        decompressed
    });

    // 3. String Transformations
    result = resolve_func(&result, "to_lower", |s| s.to_lowercase());
    result = resolve_func(&result, "to_upper", |s| s.to_uppercase());
    result = resolve_func(&result, "trim", |s| s.trim().to_string());
    result = resolve_func(&result, "reverse", |s| s.chars().rev().collect());
    result = resolve_func(&result, "len", |s| s.len().to_string());

    // Multi-arg string helpers
    result = resolve_func_with_args(&result, "trim_prefix", |args| {
        if args.len() >= 2 {
            args[0].strip_prefix(&args[1]).unwrap_or(&args[0]).to_string()
        } else {
            args.first().cloned().unwrap_or_default()
        }
    });
    result = resolve_func_with_args(&result, "trim_suffix", |args| {
        if args.len() >= 2 {
            args[0].strip_suffix(&args[1]).unwrap_or(&args[0]).to_string()
        } else {
            args.first().cloned().unwrap_or_default()
        }
    });
    result = resolve_func_with_args(&result, "replace", |args| {
        if args.len() >= 3 {
            args[0].replace(&args[1], &args[2])
        } else {
            args.first().cloned().unwrap_or_default()
        }
    });
    result = resolve_func_with_args(&result, "replace_regex", |args| {
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
    result = resolve_func_with_args(&result, "substr", |args| {
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
    result = resolve_func_with_args(&result, "concat", |args| args.join(""));
    result = resolve_func_with_args(&result, "join", |args| {
        if args.len() >= 2 {
            let delim = &args[0];
            args[1..].join(delim)
        } else {
            args.join("")
        }
    });

    // 4. Crypto & Auth
    result = resolve_func_with_args(&result, "hmac_sha256", |args| {
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
    result = resolve_func_with_args(&result, "hmac", |args| {
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
    result = resolve_func_with_args(&result, "generate_jwt", |args| {
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
    result = resolve_func_with_args(&result, "now", |_| Utc::now().to_rfc3339());
    result = resolve_func_with_args(&result, "unix_time", |_| Utc::now().timestamp().to_string());
    result = resolve_func_with_args(&result, "date_time", |args| {
        let fmt_str = args.first().map(|s| s.as_str()).unwrap_or("%Y-%m-%d %H:%M:%S");
        Utc::now().format(fmt_str).to_string()
    });

    // 6. JSON Formatting
    result = resolve_func(&result, "json_minify", |s| {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            serde_json::to_string(&v).unwrap_or_else(|_| s.to_string())
        } else {
            s.to_string()
        }
    });
    result = resolve_func(&result, "json_prettify", |s| {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            serde_json::to_string_pretty(&v).unwrap_or_else(|_| s.to_string())
        } else {
            s.to_string()
        }
    });

    // 7. Math & IP Helpers
    result = resolve_func_with_args(&result, "is_ip", |args| {
        args.first().map_or("false".to_string(), |ip| {
            if ip.parse::<IpAddr>().is_ok() { "true".to_string() } else { "false".to_string() }
        })
    });
    result = resolve_func_with_args(&result, "is_ipv4", |args| {
        args.first().map_or("false".to_string(), |ip| {
            if let Ok(IpAddr::V4(_)) = ip.parse::<IpAddr>() { "true".to_string() } else { "false".to_string() }
        })
    });
    result = resolve_func_with_args(&result, "is_ipv6", |args| {
        args.first().map_or("false".to_string(), |ip| {
            if let Ok(IpAddr::V6(_)) = ip.parse::<IpAddr>() { "true".to_string() } else { "false".to_string() }
        })
    });
    result = resolve_func_with_args(&result, "is_internal_ip", |args| {
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
pub fn resolve_func<F>(input: &str, func_name: &str, transform: F) -> String
where
    F: Fn(&str) -> String,
{
    let mut result = input.to_string();
    let prefix = format!("{{{{{}(", func_name);

    while let Some(start) = result.find(&prefix) {
        if let Some(end) = result[start..].find(")}}") {
            let inner = &result[start + prefix.len()..start + end];
            let arg = inner.trim().trim_matches('\'').trim_matches('"');
            let replacement = transform(arg);
            result.replace_range(start..start + end + 3, &replacement);
        } else {
            break;
        }
    }

    result
}

/// Resolve multi-argument functions like `{{func('arg1', 'arg2')}}`.
pub fn resolve_func_with_args<F>(input: &str, func_name: &str, transform: F) -> String
where
    F: Fn(&[String]) -> String,
{
    let mut result = input.to_string();
    let prefix = format!("{{{{{}(", func_name);

    while let Some(start) = result.find(&prefix) {
        if let Some(end) = result[start..].find(")}}") {
            let inner = &result[start + prefix.len()..start + end];
            let args: Vec<String> = inner
                .split(',')
                .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
                .collect();
            let replacement = transform(&args);
            result.replace_range(start..start + end + 3, &replacement);
        } else {
            break;
        }
    }

    result
}

/// Helper function to calculate Murmur3 32-bit hash and format as string.
pub fn murmur3_hash_str(s: &str) -> String {
    let mut cursor = std::io::Cursor::new(s.as_bytes());
    let hash = murmur3::murmur3_32(&mut cursor, 0).unwrap_or(0);
    (hash as i32).to_string()
}

pub fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn sha1_hex(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn sha512_hex(input: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn crc32_hex(input: &str) -> String {
    let mut hasher = Crc32Hasher::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Simple URL encoding.
pub fn urlencoding_encode(input: &str) -> String {
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
pub fn urlencoding_decode(input: &str) -> Result<String, std::string::FromUtf8Error> {
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
pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// HTML unescaping.
pub fn html_unescape(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}
