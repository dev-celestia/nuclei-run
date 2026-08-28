use crate::engine::dsl::functions::resolve_func_with_args;
use rand::Rng;

/// Replace dynamic random generators: `{{randstr}}`, `{{rand_int(min,max)}}`,
/// `{{rand_text_alphanumeric(len)}}`, `{{rand_text_alpha(len)}}`,
/// `{{rand_text_numeric(len)}}`, `{{rand_base(len, charset)}}`, `{{rand_ip()}}`.
pub fn resolve_random_generators(input: &str) -> String {
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
    result = resolve_func_with_args(&result, "rand_text_alphanumeric", |args| {
        let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    });

    // Handle {{rand_text_alpha(len)}}
    result = resolve_func_with_args(&result, "rand_text_alpha", |args| {
        let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect()
    });

    // Handle {{rand_text_numeric(len)}}
    result = resolve_func_with_args(&result, "rand_text_numeric", |args| {
        let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| rng.gen_range(b'0'..=b'9') as char)
            .collect()
    });

    // Handle {{rand_base(len, charset)}}
    result = resolve_func_with_args(&result, "rand_base", |args| {
        let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(10);
        let charset = args.get(1).map(|s| s.as_bytes()).unwrap_or(b"0123456789abcdef");
        if charset.is_empty() {
            return String::new();
        }
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| charset[rng.gen_range(0..charset.len())] as char)
            .collect()
    });

    // Handle {{rand_ip()}}
    while result.contains("{{rand_ip()}}") {
        let mut rng = rand::thread_rng();
        let ip = format!("{}.{}.{}.{}", rng.gen_range(1..=254), rng.gen_range(0..=254), rng.gen_range(0..=254), rng.gen_range(1..=254));
        result = result.replacen("{{rand_ip()}}", &ip, 1);
    }

    result
}
