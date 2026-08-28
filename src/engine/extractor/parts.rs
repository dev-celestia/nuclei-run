use crate::engine::http_client::HttpResponse;
use crate::models::template::TemplateExtractor;

/// Select the content to extract from based on the extractor's `part` field.
pub fn get_content(extractor: &TemplateExtractor, response: &HttpResponse) -> String {
    match extractor.part.as_deref().unwrap_or("body") {
        "header" | "all_headers" => response.headers_raw.clone(),
        "response" => format!("{}\n{}", response.headers_raw, response.body),
        _ => response.body.clone(),
    }
}
