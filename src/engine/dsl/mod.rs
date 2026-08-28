pub mod evaluator;
pub mod functions;
pub mod random;

#[allow(unused_imports)]
pub use evaluator::evaluate_dsl;
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
        evaluate_dsl(expr, status_code, headers, body, content_length, duration_secs)
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
        assert!(TemplateDsl::evaluate_dsl("duration>=6", 200, "", "", 0, 6.4));
        assert!(TemplateDsl::evaluate_dsl("duration >= 8", 200, "", "", 0, 9.1));
        assert!(!TemplateDsl::evaluate_dsl("duration>=6", 200, "", "", 0, 5.2));
        assert!(TemplateDsl::evaluate_dsl("duration > 2", 200, "", "", 0, 2.5));
        assert!(!TemplateDsl::evaluate_dsl("duration > 2", 200, "", "", 0, 1.9));
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
}
