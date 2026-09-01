pub mod evaluator;
pub mod functions;
pub mod random;

#[allow(unused_imports)]
pub use evaluator::{evaluate_dsl, evaluate_dsl_value};
#[allow(unused_imports)]
pub use functions::{
    html_escape, html_unescape, murmur3_hash_str, resolve_func, resolve_func_with_args,
    resolve_helper_functions, urlencoding_decode, urlencoding_encode,
};
#[allow(unused_imports)]
pub use random::resolve_random_generators;

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
        resolved = resolve_random_generators(&resolved);

        // Step 4: Helper functions.
        resolved = resolve_helper_functions(&resolved);

        resolved
    }

    /// Evaluate a DSL expression against response data.
    pub fn evaluate_dsl(
        expr: &str,
        status_code: u16,
        headers: &str,
        body: &str,
        content_length: usize,
        duration_secs: f64,
    ) -> bool {
        evaluate_dsl(
            expr,
            status_code,
            headers,
            body,
            content_length,
            duration_secs,
            &HashMap::new(),
        )
    }

    /// Evaluate a DSL expression with a per-response variable map (headers,
    /// cookies, extracted values), as Go nuclei exposes to every expression.
    pub fn evaluate_dsl_with_vars(
        expr: &str,
        status_code: u16,
        headers: &str,
        body: &str,
        content_length: usize,
        duration_secs: f64,
        vars: &HashMap<String, String>,
    ) -> bool {
        evaluate_dsl(
            expr,
            status_code,
            headers,
            body,
            content_length,
            duration_secs,
            vars,
        )
    }

    /// Evaluate a DSL expression and return its value (Go `ExtractDSL`
    /// semantics): boolean expressions render as "true"/"false".
    pub fn evaluate_dsl_value(
        expr: &str,
        status_code: u16,
        headers: &str,
        body: &str,
        content_length: usize,
        duration_secs: f64,
        vars: &HashMap<String, String>,
    ) -> Option<String> {
        evaluate_dsl_value(
            expr,
            status_code,
            headers,
            body,
            content_length,
            duration_secs,
            vars,
        )
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
            TemplateDsl::interpolate(
                "{{base64_decode('YWRtaW46YWRtaW4=')}}",
                "http://localhost",
                &vars
            ),
            "admin:admin"
        );
        assert_eq!(
            TemplateDsl::interpolate(
                "{{url_encode('hello world&foo=bar')}}",
                "http://localhost",
                &vars
            ),
            "hello%20world%26foo%3Dbar"
        );
        assert_eq!(
            TemplateDsl::interpolate(
                "{{url_decode('hello%20world%26foo%3Dbar')}}",
                "http://localhost",
                &vars
            ),
            "hello world&foo=bar"
        );
        assert_eq!(
            TemplateDsl::interpolate(
                "{{html_escape('<script>alert(1)</script>')}}",
                "http://localhost",
                &vars
            ),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{reverse('nuclei')}}", "http://localhost", &vars),
            "ielcun"
        );
        assert_eq!(
            TemplateDsl::interpolate(
                "{{trim_prefix('Bearer token123', 'Bearer ')}}",
                "http://localhost",
                &vars
            ),
            "token123"
        );
        assert_eq!(
            TemplateDsl::interpolate(
                "{{replace('foo-bar-baz', 'bar', 'qux')}}",
                "http://localhost",
                &vars
            ),
            "foo-qux-baz"
        );
        assert_eq!(
            TemplateDsl::interpolate("{{substr('abcdef', '1', '3')}}", "http://localhost", &vars),
            "bcd"
        );
        assert_eq!(
            TemplateDsl::interpolate(
                "{{is_internal_ip('192.168.1.1')}}",
                "http://localhost",
                &vars
            ),
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
            0,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "contains_any(body, \"not_found\", \"dashboard\")",
            200,
            "",
            "admin dashboard v1.0",
            0,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(header, \"HTTP/1.1\")",
            200,
            "HTTP/1.1 200 OK",
            "",
            0,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "ends_with(body, \"</html>\")",
            200,
            "",
            "<html><body>test</body></html>",
            0,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "compare_versions(\"1.4.2\", \"<\", \"2.0.0\")",
            200,
            "",
            "",
            0,
            0.0
        ));
    }

    #[test]
    fn test_dsl_duration_variable() {
        assert!(TemplateDsl::evaluate_dsl(
            "duration>=6",
            200,
            "",
            "",
            0,
            6.4
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "duration >= 8",
            200,
            "",
            "",
            0,
            9.1
        ));
        assert!(!TemplateDsl::evaluate_dsl(
            "duration>=6",
            200,
            "",
            "",
            0,
            5.2
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "duration > 2",
            200,
            "",
            "",
            0,
            2.5
        ));
        assert!(!TemplateDsl::evaluate_dsl(
            "duration > 2",
            200,
            "",
            "",
            0,
            1.9
        ));
    }

    #[test]
    fn test_dsl_nested_part_functions() {
        assert!(TemplateDsl::evaluate_dsl(
            "contains(to_lower(header), 'text/html')",
            200,
            "Content-Type: TEXT/HTML",
            "",
            0,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(to_lower(header), 'http/1.1')",
            200,
            "HTTP/1.1 200 OK",
            "",
            0,
            0.0
        ));
        assert!(!TemplateDsl::evaluate_dsl(
            "contains(to_lower(body), 'admin')",
            200,
            "",
            "user page",
            0,
            0.0
        ));
    }

    #[test]
    fn test_dsl_part_expressions() {
        // contains(response, "HTTP/1.1") - header present in headers + body
        assert!(TemplateDsl::evaluate_dsl(
            "contains(response, \"HTTP/1.1\")",
            200,
            "HTTP/1.1 200 OK\r\nServer: test",
            "hello world",
            11,
            0.0
        ));

        // contains(all, "<html>") - body present in headers + body
        assert!(TemplateDsl::evaluate_dsl(
            "contains(all, \"<html>\")",
            200,
            "HTTP/1.1 200 OK\r\nServer: test",
            "<html><body>test</body></html>",
            30,
            0.0
        ));

        // contains(all, "custom-header-value") - headers folded in
        assert!(TemplateDsl::evaluate_dsl(
            "contains(all, \"custom-header-value\")",
            200,
            "X-Custom: custom-header-value\r\n",
            "body text",
            9,
            0.0
        ));

        // starts_with(content_length, "11") for an 11-byte body ("hello world")
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(content_length, \"11\")",
            200,
            "",
            "hello world",
            11,
            0.0
        ));

        // The Content-Length header wins over the body size (Go nuclei's
        // CalculateContentLength).
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(content_length, \"100\")",
            200,
            "Content-Length: 1000\r\n",
            "small",
            5,
            0.0
        ));

        // contains(duration, "6") with duration_secs = 6.4
        assert!(TemplateDsl::evaluate_dsl(
            "contains(duration, \"6\")",
            200,
            "",
            "",
            0,
            6.4
        ));

        // contains('HELLO', 'ELL') - quoted literal as part arg
        assert!(TemplateDsl::evaluate_dsl(
            "contains('HELLO', 'ELL')",
            200,
            "",
            "",
            0,
            0.0
        ));
    }

    #[test]
    fn test_dsl_nested_part_functions_extended() {
        // to_upper(body)
        assert!(TemplateDsl::evaluate_dsl(
            "contains(to_upper(body), \"ADMIN\")",
            200,
            "",
            "admin dashboard",
            15,
            0.0
        ));

        // trim(body)
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(trim(body), \"lead\")",
            200,
            "",
            "   leading space",
            16,
            0.0
        ));

        // reverse(body)
        assert!(TemplateDsl::evaluate_dsl(
            "contains(reverse(body), \"dcba\")",
            200,
            "",
            "abcd",
            4,
            0.0
        ));

        // base64_decode('aGVsbG8=')
        assert!(TemplateDsl::evaluate_dsl(
            "contains(base64_decode('aGVsbG8='), \"hello\")",
            200,
            "",
            "",
            0,
            0.0
        ));

        // hex_decode('68656c6c6f')
        assert!(TemplateDsl::evaluate_dsl(
            "contains(hex_decode('68656c6c6f'), \"hello\")",
            200,
            "",
            "",
            0,
            0.0
        ));

        // url_decode('hello%20world')
        assert!(TemplateDsl::evaluate_dsl(
            "contains(url_decode('hello%20world'), \"hello world\")",
            200,
            "",
            "",
            0,
            0.0
        ));

        // html_unescape('&lt;b&gt;')
        assert!(TemplateDsl::evaluate_dsl(
            "contains(html_unescape('&lt;b&gt;'), \"<b>\")",
            200,
            "",
            "",
            0,
            0.0
        ));

        // starts_with(len(body), "5")
        assert!(TemplateDsl::evaluate_dsl(
            "starts_with(len(body), \"5\")",
            200,
            "",
            "hello",
            5,
            0.0
        ));

        // contains(to_lower(base64_decode('QURNSU4=')), "admin")
        assert!(TemplateDsl::evaluate_dsl(
            "contains(to_lower(base64_decode('QURNSU4=')), \"admin\")",
            200,
            "",
            "",
            0,
            0.0
        ));
    }

    #[test]
    fn test_dsl_float_comparisons() {
        // status_code & content_length checks
        assert!(TemplateDsl::evaluate_dsl(
            "status_code == 200",
            200,
            "",
            "",
            10,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "status_code != 404",
            200,
            "",
            "",
            10,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "content_length >= 5",
            200,
            "",
            "",
            10,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "content_length < 100",
            200,
            "",
            "",
            10,
            0.0
        ));

        // duration comparisons
        assert!(TemplateDsl::evaluate_dsl(
            "duration < 1",
            200,
            "",
            "",
            0,
            0.5
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "duration >= 1.5",
            200,
            "",
            "",
            0,
            1.5
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "duration <= 2.5",
            200,
            "",
            "",
            0,
            2.0
        ));

        // compound expressions
        assert!(TemplateDsl::evaluate_dsl(
            "duration >= 1 && status_code == 200",
            200,
            "",
            "",
            0,
            1.2
        ));
        assert!(!TemplateDsl::evaluate_dsl(
            "duration >= 9 || status_code == 404",
            200,
            "",
            "",
            0,
            1.2
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "!(status_code == 404)",
            200,
            "",
            "",
            0,
            0.0
        ));

        // RHS float literal
        assert!(TemplateDsl::evaluate_dsl(
            "duration >= 1.5",
            200,
            "",
            "",
            0,
            1.5
        ));
    }

    #[test]
    fn test_dsl_response_variables() {
        let vars = crate::engine::matcher::parts::response_variables(
            "X-Powered-By: PHP/8.1\nContent-Type: application/json\nSet-Cookie: session=abc123; Path=/\n",
        );

        assert!(TemplateDsl::evaluate_dsl_with_vars(
            "contains(x_powered_by, \"PHP\")",
            200,
            "",
            "body",
            4,
            0.0,
            &vars
        ));
        assert!(TemplateDsl::evaluate_dsl_with_vars(
            "contains(content_type, \"application/json\")",
            200,
            "",
            "body",
            4,
            0.0,
            &vars
        ));
        // Cookie variables are exposed under their lowercased names.
        assert!(TemplateDsl::evaluate_dsl_with_vars(
            "contains(session, \"abc123\")",
            200,
            "",
            "body",
            4,
            0.0,
            &vars
        ));
        // Without the vars map these expressions cannot match (body fallback).
        assert!(!TemplateDsl::evaluate_dsl(
            "contains(x_powered_by, \"PHP\")",
            200,
            "",
            "body",
            4,
            0.0
        ));
    }

    #[test]
    fn test_dsl_numeric_variable_comparison() {
        let mut vars = HashMap::new();
        vars.insert("x_count".to_string(), "42".to_string());
        assert!(TemplateDsl::evaluate_dsl_with_vars(
            "x_count == 42",
            200,
            "",
            "",
            0,
            0.0,
            &vars
        ));
        assert!(!TemplateDsl::evaluate_dsl_with_vars(
            "x_count > 100",
            200,
            "",
            "",
            0,
            0.0,
            &vars
        ));
    }

    #[test]
    fn test_dsl_value_functions() {
        // remove_bad_chars / replace / nested transforms over parts
        assert!(TemplateDsl::evaluate_dsl(
            "contains(remove_bad_chars(body, \"()\"), \"hello world\")",
            200,
            "",
            "h(e)l(l)o w(o)r(l)d",
            17,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "contains(replace(body, \"foo\", \"bar\"), \"bar baz\")",
            200,
            "",
            "foo baz",
            7,
            0.0
        ));
        // substr uses Go range semantics: substr(body, 0, 5) = first 5 chars.
        assert!(TemplateDsl::evaluate_dsl(
            "contains(substr(body, 0, 5), \"hello\")",
            200,
            "",
            "hello world",
            11,
            0.0
        ));
        // Numeric conversions
        assert!(TemplateDsl::evaluate_dsl(
            "contains(dec_to_hex(\"255\"), \"ff\")",
            200,
            "",
            "",
            0,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "contains(hex_to_dec(\"ff\"), \"255\")",
            200,
            "",
            "",
            0,
            0.0
        ));
        // regex returns the first whole match
        assert!(TemplateDsl::evaluate_dsl(
            "contains(regex(\"token=[a-z]+\", body), \"token=abc\")",
            200,
            "",
            "token=abc end",
            13,
            0.0
        ));
        // Hash / encoding functions over parts
        assert!(TemplateDsl::evaluate_dsl(
            "contains(md5(body), \"5eb63bbbe01eeed093cb22bb8f5acdc3\")",
            200,
            "",
            "hello world",
            11,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "contains(base64(body), \"aGVsbG8gd29ybGQ=\")",
            200,
            "",
            "hello world",
            11,
            0.0
        ));
    }

    #[test]
    fn test_dsl_predicate_functions() {
        assert!(TemplateDsl::evaluate_dsl(
            "equals_any(body, \"nope\", \"hello world\")",
            200,
            "",
            "hello world",
            11,
            0.0
        ));
        assert!(!TemplateDsl::evaluate_dsl(
            "equals_any(body, \"nope\")",
            200,
            "",
            "hello world",
            11,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "line_starts_with(body, \"second\")",
            200,
            "",
            "first line\nsecond line",
            22,
            0.0
        ));
        assert!(TemplateDsl::evaluate_dsl(
            "line_ends_with(body, \"line\")",
            200,
            "",
            "first line\nsecond row",
            21,
            0.0
        ));
    }

    #[test]
    fn test_evaluate_dsl_value() {
        let vars = crate::engine::matcher::parts::response_variables(
            "Content-Type: application/json\n",
        );

        // Variable lookup returns the header value.
        assert_eq!(
            TemplateDsl::evaluate_dsl_value(
                "content_type",
                200,
                "Content-Type: application/json\n",
                "body",
                4,
                0.0,
                &vars
            ),
            Some("application/json".to_string())
        );
        // Nested function over a part.
        assert_eq!(
            TemplateDsl::evaluate_dsl_value(
                "to_upper(body)",
                200,
                "",
                "body",
                4,
                0.0,
                &vars
            ),
            Some("BODY".to_string())
        );
        // Boolean expressions render as true/false.
        assert_eq!(
            TemplateDsl::evaluate_dsl_value(
                "status_code == 200",
                200,
                "",
                "body",
                4,
                0.0,
                &vars
            ),
            Some("true".to_string())
        );
    }

    #[test]
    fn test_to_unix_time() {
        assert!(TemplateDsl::evaluate_dsl(
            "to_unix_time(\"2023-01-01T00:00:00Z\") == 1672531200",
            200,
            "",
            "",
            0,
            0.0
        ));
    }
}
