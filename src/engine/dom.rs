//! HTML/XML document querying shared by the XPath matcher and extractor.
//!
//! Go nuclei dispatches on corpus prefix: a leading `<?xml` uses a strict XML
//! parser, otherwise a lenient HTML parser (see `pkg/operators/extractors/extract.go`
//! and `pkg/operators/matchers/match.go`). We mirror that here: strict XML via
//! `sxd_document`, HTML via `html5ever` converted into an `sxd_document` so that
//! the same `sxd_xpath` engine evaluates both. All results are returned as owned
//! values so the parsed document never escapes this module.

use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use sxd_document::dom::{Document, Element, Root};
use sxd_document::Package;
use sxd_xpath::nodeset::Node;

/// Parse the corpus using Go nuclei's dispatch rules and return the sxd package.
fn parse_corpus(corpus: &str) -> Option<Package> {
    if corpus.trim_start().starts_with("<?xml") {
        return sxd_document::parser::parse(corpus).ok();
    }
    parse_html(corpus)
}

/// Parse HTML with html5ever and build an equivalent sxd_document package.
fn parse_html(corpus: &str) -> Option<Package> {
    let mut bytes = corpus.as_bytes();
    let dom = html5ever::parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut bytes)
        .ok()?;

    let package = Package::new();
    let doc = package.as_document();
    let root = doc.root();
    convert_children(doc, Parent::Root(root), &dom.document);
    Some(package)
}

enum Parent<'d> {
    Root(Root<'d>),
    Element(Element<'d>),
}

impl<'d> Parent<'d> {
    fn append_element(&self, el: Element<'d>) {
        match self {
            Parent::Root(r) => r.append_child(el),
            Parent::Element(e) => e.append_child(el),
        }
    }

    fn append_comment(&self, doc: Document<'d>, text: &str) {
        let comment = doc.create_comment(text);
        match self {
            Parent::Root(r) => r.append_child(comment),
            Parent::Element(e) => e.append_child(comment),
        }
    }

    fn append_text(&self, doc: Document<'d>, text: &str) {
        // Text is not a valid child of the document root.
        if let Parent::Element(e) = self {
            e.append_child(doc.create_text(text));
        }
    }
}

/// Recursively convert html5ever nodes into the sxd document. Namespaces are
/// dropped so unprefixed XPath queries match as they do against Go's
/// antchfx/htmlquery trees.
fn convert_children(doc: Document, parent: Parent, handle: &Handle) {
    for child in handle.children.borrow().iter() {
        match &child.data {
            NodeData::Text { contents } => {
                parent.append_text(doc, &contents.borrow());
            }
            NodeData::Comment { contents } => {
                parent.append_comment(doc, contents);
            }
            NodeData::Element { name, attrs, .. } => {
                let element = doc.create_element(name.local.as_ref());
                for attr in attrs.borrow().iter() {
                    element.set_attribute_value(attr.name.local.as_ref(), &attr.value);
                }
                parent.append_element(element);
                convert_children(doc, Parent::Element(element), child);
            }
            // Doctype / ProcessingInstruction have no sxd equivalent we need.
            _ => {}
        }
    }
}

/// Evaluate an XPath expression against a parsed document.
fn evaluate_xpath<'d>(doc: &Document<'d>, path: &str) -> Option<Vec<Node<'d>>> {
    let factory = sxd_xpath::Factory::new();
    let xpath = factory.build(path).ok()??;
    let context = sxd_xpath::Context::new();
    let value = xpath.evaluate(&context, doc.root()).ok()?;

    match value {
        sxd_xpath::Value::Nodeset(nodes) => Some(nodes.document_order()),
        _ => Some(Vec::new()),
    }
}

/// String value of a matched node: the named attribute when `attribute` is set
/// (element nodes only), otherwise the node's string value (inner text).
fn node_value(node: &Node, attribute: Option<&str>) -> String {
    if let Some(attr) = attribute {
        if let Node::Element(el) = node {
            return el.attribute_value(attr).unwrap_or("").to_string();
        }
        return String::new();
    }
    node.string_value()
}

/// Count of nodes matched by `path` against `corpus`.
/// `None` when parsing or the XPath expression itself fails.
pub fn query_xpath_count(corpus: &str, path: &str) -> Option<usize> {
    let package = parse_corpus(corpus)?;
    let doc = package.as_document();
    let nodes = evaluate_xpath(&doc, path)?;
    Some(nodes.len())
}

/// Values of all nodes matched by `path` against `corpus`, in document order.
/// When `attribute` is set, each element's attribute value is returned instead
/// of its inner text (mirrors Go's `htmlquery.SelectAttr`).
pub fn query_xpath_values(
    corpus: &str,
    path: &str,
    attribute: Option<&str>,
) -> Option<Vec<String>> {
    let package = parse_corpus(corpus)?;
    let doc = package.as_document();
    let nodes = evaluate_xpath(&doc, path)?;
    Some(nodes.iter().map(|n| node_value(n, attribute)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_query() {
        let xml = "<users><user role=\"admin\">Alice</user><user role=\"guest\">Bob</user></users>";
        let values = query_xpath_values(xml, "//user[@role='admin']", None).unwrap();
        assert_eq!(values, vec!["Alice".to_string()]);
        assert_eq!(query_xpath_count(xml, "//user").unwrap(), 2);
    }

    #[test]
    fn test_html_query_with_implicit_structure() {
        // Malformed HTML: unclosed tags, implicit html/body.
        let html = r#"<html><body><input name="csrf" value="tok123"><div id="msg">hello <b>world</b></div></body>"#;
        let values = query_xpath_values(html, "//input[@name='csrf']", Some("value")).unwrap();
        assert_eq!(values, vec!["tok123".to_string()]);
    }

    #[test]
    fn test_html_inner_text() {
        let html = "<html><body><div id=\"msg\">hello <b>world</b></div></body></html>";
        let values = query_xpath_values(html, "//div[@id='msg']", None).unwrap();
        assert_eq!(values, vec!["hello world".to_string()]);
    }

    #[test]
    fn test_attribute_extraction_multiple_nodes() {
        let html = r#"<a href="/login">Login</a><a href="/admin">Admin</a>"#;
        let values = query_xpath_values(html, "//a", Some("href")).unwrap();
        assert_eq!(values, vec!["/login".to_string(), "/admin".to_string()]);
    }

    #[test]
    fn test_xml_dispatch_on_declaration() {
        let xml = r#"<?xml version="1.0"?><root><item>1</item></root>"#;
        assert_eq!(query_xpath_count(xml, "//item").unwrap(), 1);
    }

    #[test]
    fn test_no_match() {
        let html = "<html><body><p>text</p></body></html>";
        assert_eq!(query_xpath_count(html, "//div").unwrap(), 0);
    }

    #[test]
    fn test_invalid_xpath() {
        let html = "<html><body></body></html>";
        assert!(query_xpath_count(html, "//[invalid").is_none());
    }
}
