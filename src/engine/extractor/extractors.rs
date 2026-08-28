use regex::Regex;

/// Regex Extraction
pub fn extract_regex(patterns: &[String], text: &str, group: usize) -> Option<String> {
    for pat in patterns {
        if let Ok(re) = Regex::new(pat) {
            if let Some(caps) = re.captures(text) {
                // Try to get the specified capture group, fall back to full match.
                if let Some(m) = caps.get(group) {
                    return Some(m.as_str().to_string());
                } else if let Some(m) = caps.get(0) {
                    return Some(m.as_str().to_string());
                }
            }
        }
    }
    None
}

/// JSON Path Extraction (basic dot-notation)
pub fn extract_json_path(json_text: &str, path: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(json_text).ok()?;

    let mut current = &parsed;
    for key in path.trim_start_matches('.').split('.') {
        // Handle array indexing: key[0]
        if let Some(bracket_pos) = key.find('[') {
            let field = &key[..bracket_pos];
            let index_str = &key[bracket_pos + 1..key.len() - 1];
            let index: usize = index_str.parse().ok()?;

            if !field.is_empty() {
                current = current.get(field)?;
            }
            current = current.get(index)?;
        } else {
            current = current.get(key)?;
        }
    }

    Some(match current {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    })
}

/// XPath Extraction
pub fn extract_xpath(xml_text: &str, path: &str, _attribute: Option<&str>) -> Option<String> {
    let package = sxd_document::parser::parse(xml_text).ok()?;
    let document = package.as_document();
    let factory = sxd_xpath::Factory::new();
    let xpath = factory.build(path).ok()??;
    let context = sxd_xpath::Context::new();
    let value = xpath.evaluate(&context, document.root()).ok()?;
    Some(match value {
        sxd_xpath::Value::Nodeset(nodes) => {
            let first = nodes.document_order().into_iter().next()?;
            first.string_value()
        }
        sxd_xpath::Value::String(s) => s,
        sxd_xpath::Value::Number(n) => n.to_string(),
        sxd_xpath::Value::Boolean(b) => b.to_string(),
    })
}
