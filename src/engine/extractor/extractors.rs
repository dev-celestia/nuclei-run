use regex::Regex;
use std::collections::HashSet;

/// Regex extraction: all matches across all patterns, deduplicated, in
/// document order (mirrors Go's `FindAllStringSubmatch` + result map).
/// `group` selects the capture group (0 = full match). Matches without the
/// requested group are skipped, as Go does with its length check.
pub fn extract_regex(patterns: &[String], text: &str, group: usize) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for pat in patterns {
        let Ok(re) = Regex::new(pat) else {
            continue;
        };
        for caps in re.captures_iter(text) {
            // Go: skip matches where the requested group did not participate.
            let Some(m) = caps.get(group) else {
                continue;
            };
            let value = m.as_str().to_string();
            if seen.insert(value.clone()) {
                results.push(value);
            }
        }
    }

    results
}

/// JSON extraction using jq queries (mirrors Go's gojq-based extractor).
/// Each query yields a stream of results; scalars are rendered directly and
/// compound values are rendered as compact JSON text.
pub fn extract_json(json_text: &str, query: &str) -> Vec<String> {
    let corpus: serde_json::Value = match serde_json::from_str(json_text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let input: jaq_json::Val = match serde_json::from_value(corpus) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut results: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for rendered in run_jq(query, input) {
        if seen.insert(rendered.clone()) {
            results.push(rendered);
        }
    }

    results
}

type JqData = jaq_core::data::JustLut<jaq_json::Val>;

/// Render a jq output value the way Go nuclei does: scalar strings are
/// returned raw (`types.JSONScalarToString`), everything else is serialized
/// as compact JSON text (`json.Marshal`).
fn val_to_output(val: &jaq_json::Val) -> Option<String> {
    match val {
        jaq_json::Val::TStr(b) | jaq_json::Val::BStr(b) => {
            Some(String::from_utf8_lossy(b).into_owned())
        }
        _ => {
            let mut buf = Vec::new();
            jaq_json::write::write(&mut buf, &jaq_json::write::Pp::default(), 0, val).ok()?;
            Some(String::from_utf8_lossy(&buf).into_owned())
        }
    }
}

/// Compile and run a jq program over a single input value, returning each
/// output rendered per `val_to_output`.
fn run_jq(query: &str, input: jaq_json::Val) -> Vec<String> {
    use jaq_core::load::{Arena, File, Loader};

    let arena = Arena::default();
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let loader = Loader::new(defs);
    let modules = match loader.load(
        &arena,
        File {
            path: (),
            code: query,
        },
    ) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    let funs = jaq_core::funs::<JqData>()
        .chain(jaq_std::funs::<JqData>())
        .chain(jaq_json::funs::<JqData>());
    let compiler: jaq_core::Compiler<_, JqData> = jaq_core::Compiler::default();
    let filter = match compiler.with_funs(funs).compile(modules) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let ctx = jaq_core::Ctx::<JqData>::new(&filter.lut, jaq_core::Vars::new([]));
    let mut out = Vec::new();
    for r in filter.id.run((ctx, input)) {
        // Go stops at the first runtime error; keep what was produced so far.
        let Ok(val) = r else {
            break;
        };
        if let Some(rendered) = val_to_output(&val) {
            out.push(rendered);
        }
    }
    out
}

/// XPath extraction with Go-compatible parsing: `<?xml` prefix uses strict XML,
/// otherwise lenient HTML. All matched nodes are returned; when `attribute` is
/// set, the attribute value of each element is extracted instead of its text.
pub fn extract_xpath(corpus: &str, paths: &[String], attribute: Option<&str>) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for path in paths {
        let Some(values) = crate::engine::dom::query_xpath_values(corpus, path, attribute) else {
            continue;
        };
        for value in values {
            if seen.insert(value.clone()) {
                results.push(value);
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn test_regex_all_matches_deduped() {
        let corpus = "token=AAA middle token=BBB and token=AAA again";
        let out = extract_regex(&[s(r"token=([A-Z]+)")], corpus, 1);
        assert_eq!(out, vec!["AAA".to_string(), "BBB".to_string()]);
    }

    #[test]
    fn test_regex_full_match_group_zero() {
        let corpus = "v1.2.3 and v2.0.0";
        let out = extract_regex(&[s(r"v\d+\.\d+\.\d+")], corpus, 0);
        assert_eq!(out, vec!["v1.2.3".to_string(), "v2.0.0".to_string()]);
    }

    #[test]
    fn test_regex_optional_group_skips_non_participating() {
        // Group 1 does not participate in the second match -> skipped.
        let corpus = "a:1 b";
        let out = extract_regex(&[s(r"[ab](?::(\d+))?")], corpus, 1);
        assert_eq!(out, vec!["1".to_string()]);
    }

    #[test]
    fn test_json_scalar_query() {
        let corpus = r#"{"user": "admin", "role": "superuser"}"#;
        assert_eq!(extract_json(corpus, ".role"), vec!["superuser".to_string()]);
    }

    #[test]
    fn test_json_array_iteration() {
        let corpus = r#"{"users": [{"id": "a1"}, {"id": "b2"}]}"#;
        let out = extract_json(corpus, ".users[].id");
        assert_eq!(out, vec!["a1".to_string(), "b2".to_string()]);
    }

    #[test]
    fn test_json_pipe_and_select() {
        let corpus =
            r#"{"items": [{"name": "x", "active": true}, {"name": "y", "active": false}]}"#;
        let out = extract_json(corpus, ".items[] | select(.active) | .name");
        assert_eq!(out, vec!["x".to_string()]);
    }

    #[test]
    fn test_json_numeric_and_compound() {
        let corpus = r#"{"count": 3, "nested": {"a": 1}}"#;
        assert_eq!(extract_json(corpus, ".count"), vec!["3".to_string()]);
        assert_eq!(
            extract_json(corpus, ".nested"),
            vec![r#"{"a":1}"#.to_string()]
        );
    }

    #[test]
    fn test_json_invalid_query_or_corpus() {
        assert!(extract_json("not json", ".a").is_empty());
        assert!(extract_json(r#"{"a":1}"#, ".[invalid").is_empty());
    }

    #[test]
    fn test_xpath_html_attribute() {
        let html = r#"<form><input name="csrf" value="tok123"></form>"#;
        let out = extract_xpath(html, &[s("//input[@name='csrf']")], Some("value"));
        assert_eq!(out, vec!["tok123".to_string()]);
    }

    #[test]
    fn test_xpath_xml_text_and_dedup() {
        let xml = "<r><u>Alice</u><u>Alice</u><u>Bob</u></r>";
        let out = extract_xpath(xml, &[s("//u")], None);
        assert_eq!(out, vec!["Alice".to_string(), "Bob".to_string()]);
    }
}
