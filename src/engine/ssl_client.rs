use crate::engine::dsl::TemplateDsl;
use crate::engine::variables::VariableResolver;
use crate::models::template::SslBlock;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::*;

/// SSL / TLS inspection response.
///
/// Field naming and semantics mirror Go nuclei's tlsx `Response` +
/// `CertificateResponse` structs (`github.com/projectdiscovery/tlsx`), which
/// are flattened by json tag into the operator data map in
/// `pkg/protocols/ssl/ssl.go`. The `response` variable carries the full JSON
/// string and is the protocol's default match part.
#[derive(Debug, Clone, Default)]
pub struct SslResponse {
    /// Original target input (Go `host` variable).
    pub host: String,
    /// Rendered address that was dialed (Go `matched` variable).
    pub matched: String,
    /// Dialed peer IP (Go `ip` variable).
    pub ip: String,
    /// Dialed port (Go `port` / `Port` variables).
    pub port: String,
    /// Whether the TLS probe succeeded (Go `probe_status`).
    pub probe_status: bool,
    /// Negotiated version in tlsx naming: tls10/tls11/tls12/tls13.
    pub tls_version: String,
    /// Negotiated cipher in Go crypto/tls naming (e.g. TLS_AES_128_GCM_SHA256).
    pub cipher: String,
    /// Server name presented during the handshake (Go `sni`).
    pub sni: String,
    pub subject_cn: String,
    /// Subject alternative names (DNS entries only, as Go `cert.DNSNames`).
    pub subject_an: Vec<String>,
    pub subject_dn: String,
    pub issuer_cn: String,
    pub issuer_dn: String,
    /// Serial as colon-separated uppercase hex (tlsx FormatToSerialNumber).
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_md5: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    /// Deduplicated SANs + subject CN with the `*.` prefix stripped.
    pub domains: Vec<String>,
    pub self_signed: bool,
    pub expired: bool,
    pub mismatched: bool,
    pub wildcard_certificate: bool,
    /// Full response as a JSON string (Go default match part).
    pub response: String,
}

impl SslResponse {
    /// Go-parity variable map for matchers/extractors: every non-zero tlsx
    /// field flattened by json tag, plus host/matched/ip/port/Port/response.
    pub fn variables(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("host".to_string(), self.host.clone());
        vars.insert("matched".to_string(), self.matched.clone());
        if !self.ip.is_empty() {
            vars.insert("ip".to_string(), self.ip.clone());
        }
        vars.insert("port".to_string(), self.port.clone());
        vars.insert("Port".to_string(), self.port.clone());
        if self.probe_status {
            vars.insert("probe_status".to_string(), "true".to_string());
        }

        insert_str(&mut vars, "tls_version", &self.tls_version);
        insert_str(&mut vars, "cipher", &self.cipher);
        insert_str(&mut vars, "sni", &self.sni);
        insert_str(&mut vars, "subject_cn", &self.subject_cn);
        if !self.subject_an.is_empty() {
            vars.insert("subject_an".to_string(), go_slice(&self.subject_an));
        }
        insert_str(&mut vars, "subject_dn", &self.subject_dn);
        insert_str(&mut vars, "issuer_cn", &self.issuer_cn);
        insert_str(&mut vars, "issuer_dn", &self.issuer_dn);
        insert_str(&mut vars, "serial", &self.serial);
        insert_str(&mut vars, "not_before", &self.not_before);
        insert_str(&mut vars, "not_after", &self.not_after);
        if !self.domains.is_empty() {
            vars.insert("domains".to_string(), go_slice(&self.domains));
        }
        if self.expired {
            vars.insert("expired".to_string(), "true".to_string());
        }
        if self.self_signed {
            vars.insert("self_signed".to_string(), "true".to_string());
        }
        if self.mismatched {
            vars.insert("mismatched".to_string(), "true".to_string());
        }
        if self.wildcard_certificate {
            vars.insert("wildcard_certificate".to_string(), "true".to_string());
        }

        let fp = fingerprint_json(self);
        if !fp.is_empty() {
            vars.insert("fingerprint_hash".to_string(), fp);
        }

        vars.insert("response".to_string(), self.response.clone());
        vars
    }
}

pub struct SslClient;

impl SslClient {
    /// Execute SSL inspection against the target. `vars` carries template and
    /// previously extracted values used to render the address (Go renders
    /// `request.Address` through the variable scope).
    pub async fn execute(
        block: &SslBlock,
        target: &str,
        vars: &HashMap<String, String>,
        timeout_secs: u64,
    ) -> Result<SslResponse, String> {
        let raw_addr = block.address.as_deref().unwrap_or(target);
        let rendered = TemplateDsl::interpolate(
            &VariableResolver::resolve(raw_addr, target),
            target,
            vars,
        );
        let addr_str = rendered
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');

        let (host, port) = if let Some(idx) = addr_str.rfind(':') {
            (
                addr_str[..idx].to_string(),
                addr_str[idx + 1..].parse::<u16>().unwrap_or(443),
            )
        } else {
            (addr_str.to_string(), 443)
        };

        let connect_addr = format!("{}:{}", host, port);
        let timeout = Duration::from_secs(timeout_secs.max(1));

        let stream = tokio::time::timeout(timeout, TcpStream::connect(&connect_addr))
            .await
            .map_err(|_| format!("Connection timeout to {}", connect_addr))?
            .map_err(|e| format!("Failed to connect to {}: {}", connect_addr, e))?;

        let ip = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();

        let mut response = SslResponse {
            host: target.to_string(),
            matched: connect_addr.clone(),
            ip,
            port: port.to_string(),
            ..Default::default()
        };

        // Inspect any certificate, including self-signed/expired ones.
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifyCert))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
            .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost").unwrap())
            .to_owned();
        response.sni = server_name.to_str().to_string();

        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| format!("TLS handshake timeout to {}", connect_addr))?
            .map_err(|e| format!("TLS handshake error with {}: {}", connect_addr, e))?;

        response.probe_status = true;

        let (_, session) = tls_stream.get_ref();
        if let Some(version) = session.protocol_version() {
            response.tls_version = go_tls_version(version).to_string();
        }
        if let Some(suite) = session.negotiated_cipher_suite() {
            response.cipher = go_cipher_name(suite.suite());
        }

        if let Some(certs) = session.peer_certificates() {
            if let Some(leaf_cert) = certs.first() {
                fill_certificate(&mut response, leaf_cert.as_ref(), &host);
            }
        }

        response.response = build_response_json(&response);
        Ok(response)
    }
}

/// Populate certificate fields from the leaf certificate DER.
fn fill_certificate(response: &mut SslResponse, cert_der: &[u8], host: &str) {
    let mut md5 = Md5::new();
    md5.update(cert_der);
    response.fingerprint_md5 = hex::encode(md5.finalize());

    let mut sha1 = Sha1::new();
    sha1.update(cert_der);
    response.fingerprint_sha1 = hex::encode(sha1.finalize());

    let mut sha256 = Sha256::new();
    sha256.update(cert_der);
    response.fingerprint_sha256 = hex::encode(sha256.finalize());

    let Ok((_, x509)) = X509Certificate::from_der(cert_der) else {
        return;
    };

    response.subject_cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();
    response.issuer_cn = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();
    response.subject_dn = format_dn(x509.subject());
    response.issuer_dn = format_dn(x509.issuer());

    // tlsx FormatToSerialNumber: colon-separated uppercase hex of the bytes.
    let serial_bytes = x509.raw_serial();
    if !serial_bytes.is_empty() {
        response.serial = serial_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");
    }

    response.not_before = rfc3339(x509.validity().not_before.timestamp());
    response.not_after = rfc3339(x509.validity().not_after.timestamp());
    response.expired = x509.validity().not_after.timestamp()
        < chrono::Utc::now().timestamp();

    if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                response.subject_an.push(dns.to_string());
            }
        }
    }

    // domains: deduplicated SANs + subject CN, wildcard prefix stripped
    // (tlsx GetUniqueDomainsFromCert).
    let mut seen = std::collections::HashSet::new();
    let mut domains = Vec::new();
    for name in response.subject_an.iter().chain(std::iter::once(&response.subject_cn)) {
        if name.is_empty() {
            continue;
        }
        let trimmed = name.trim_start_matches("*.");
        if seen.insert(trimmed.to_string()) {
            domains.push(trimmed.to_string());
        }
    }
    response.domains = domains;

    let mut domain_names = vec![response.subject_cn.clone()];
    domain_names.extend(response.subject_an.iter().cloned());
    response.mismatched = is_mismatched_cert(host, &domain_names);
    response.wildcard_certificate = domain_names.iter().any(|n| n.contains("*."));

    // tlsx IsSelfSigned: no authority key ID, or authority == subject key ID.
    let mut subject_key_id: Option<&[u8]> = None;
    let mut authority_key_id: Option<&[u8]> = None;
    for ext in x509.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(key_id) => {
                subject_key_id = Some(key_id.0);
            }
            ParsedExtension::AuthorityKeyIdentifier(akid) => {
                authority_key_id = akid.key_identifier.as_ref().map(|k| k.0);
            }
            _ => {}
        }
    }
    response.self_signed = match authority_key_id {
        None => true,
        Some(akid) => subject_key_id == Some(akid),
    };
}

/// RFC 4514-style DN formatting in Go pkix `Name.String()` order (most
/// specific attribute first) with Go's short attribute names.
fn format_dn(name: &X509Name) -> String {
    let mut rdns: Vec<String> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|atv| {
                    let value = atv.as_str().unwrap_or_default();
                    format!(
                        "{}={}",
                        oid_short_name(&atv.attr_type().to_id_string()),
                        escape_dn_value(value)
                    )
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.reverse();
    rdns.join(",")
}

/// Go pkix `attributeTypeNames` map; unknown OIDs render dotted.
fn oid_short_name(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".to_string(),
        "2.5.4.5" => "SERIALNUMBER".to_string(),
        "2.5.4.6" => "C".to_string(),
        "2.5.4.7" => "L".to_string(),
        "2.5.4.8" => "ST".to_string(),
        "2.5.4.9" => "STREET".to_string(),
        "2.5.4.10" => "O".to_string(),
        "2.5.4.11" => "OU".to_string(),
        "2.5.4.17" => "POSTALCODE".to_string(),
        other => other.to_string(),
    }
}

/// Minimal RFC 4514 escaping: quote values containing specials or with
/// leading/trailing spaces.
fn escape_dn_value(value: &str) -> String {
    let needs_quote = value.contains(['"', '+', ',', ';', '<', '>', '\\'])
        || value.starts_with([' ', '#'])
        || value.ends_with(' ');
    if !needs_quote {
        return value.to_string();
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

/// tlsx IsMisMatchedCert parity: no certificate name matches the host
/// (wildcard names matched token by token).
fn is_mismatched_cert(host: &str, names: &[String]) -> bool {
    let host_tokens: Vec<&str> = host.split('.').collect();
    for name in names {
        if name.is_empty() {
            continue;
        }
        if !name.contains('*') {
            if name.eq_ignore_ascii_case(host) {
                return false;
            }
        } else {
            let name_tokens: Vec<&str> = name.split('.').collect();
            if name_tokens.len() != host_tokens.len() {
                continue;
            }
            let mut matched = true;
            for (i, token) in name_tokens.iter().enumerate() {
                let ok = if i == 0 {
                    wildcard_token_match(token, host_tokens[i])
                } else {
                    token.eq_ignore_ascii_case(host_tokens[i])
                };
                if !ok {
                    matched = false;
                    break;
                }
            }
            if matched {
                return false;
            }
        }
    }
    true
}

/// tlsx matchWildCardToken: `*` matches any single token; other `*`
/// occurrences act as prefix/suffix wildcards.
fn wildcard_token_match(token: &str, host_token: &str) -> bool {
    if token == "*" {
        return true;
    }
    if let Some(rest) = token.strip_prefix('*') {
        if let Some((prefix, suffix)) = rest.split_once('*') {
            return host_token.starts_with(prefix) && host_token.ends_with(suffix);
        }
        return host_token.ends_with(rest);
    }
    if let Some(prefix) = token.strip_suffix('*') {
        return host_token.starts_with(prefix);
    }
    token.eq_ignore_ascii_case(host_token)
}

fn rfc3339(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

fn insert_str(vars: &mut HashMap<String, String>, key: &str, value: &str) {
    if !value.is_empty() {
        vars.insert(key.to_string(), value.to_string());
    }
}

/// Go slice %v rendering: `[a b c]`.
fn go_slice(items: &[String]) -> String {
    format!("[{}]", items.join(" "))
}

fn fingerprint_json(response: &SslResponse) -> String {
    let mut fp = serde_json::Map::new();
    if !response.fingerprint_md5.is_empty() {
        fp.insert("md5".to_string(), serde_json::json!(response.fingerprint_md5));
    }
    if !response.fingerprint_sha1.is_empty() {
        fp.insert("sha1".to_string(), serde_json::json!(response.fingerprint_sha1));
    }
    if !response.fingerprint_sha256.is_empty() {
        fp.insert(
            "sha256".to_string(),
            serde_json::json!(response.fingerprint_sha256),
        );
    }
    if fp.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&serde_json::Value::Object(fp)).unwrap_or_default()
    }
}

/// Full response JSON with Go tlsx field names (omitempty respected).
fn build_response_json(response: &SslResponse) -> String {
    let mut map = serde_json::Map::new();
    map.insert("host".to_string(), serde_json::json!(response.host));
    if !response.ip.is_empty() {
        map.insert("ip".to_string(), serde_json::json!(response.ip));
    }
    map.insert("port".to_string(), serde_json::json!(response.port));
    map.insert("probe_status".to_string(), serde_json::json!(response.probe_status));
    if !response.tls_version.is_empty() {
        map.insert("tls_version".to_string(), serde_json::json!(response.tls_version));
    }
    if !response.cipher.is_empty() {
        map.insert("cipher".to_string(), serde_json::json!(response.cipher));
    }
    if response.expired {
        map.insert("expired".to_string(), serde_json::json!(true));
    }
    if response.self_signed {
        map.insert("self_signed".to_string(), serde_json::json!(true));
    }
    if response.mismatched {
        map.insert("mismatched".to_string(), serde_json::json!(true));
    }
    if !response.not_before.is_empty() {
        map.insert("not_before".to_string(), serde_json::json!(response.not_before));
    }
    if !response.not_after.is_empty() {
        map.insert("not_after".to_string(), serde_json::json!(response.not_after));
    }
    if !response.subject_dn.is_empty() {
        map.insert("subject_dn".to_string(), serde_json::json!(response.subject_dn));
    }
    if !response.subject_cn.is_empty() {
        map.insert("subject_cn".to_string(), serde_json::json!(response.subject_cn));
    }
    if !response.subject_an.is_empty() {
        map.insert("subject_an".to_string(), serde_json::json!(response.subject_an));
    }
    if !response.domains.is_empty() {
        map.insert("domains".to_string(), serde_json::json!(response.domains));
    }
    if !response.serial.is_empty() {
        map.insert("serial".to_string(), serde_json::json!(response.serial));
    }
    if !response.issuer_dn.is_empty() {
        map.insert("issuer_dn".to_string(), serde_json::json!(response.issuer_dn));
    }
    if !response.issuer_cn.is_empty() {
        map.insert("issuer_cn".to_string(), serde_json::json!(response.issuer_cn));
    }
    let fp = fingerprint_json(response);
    if !fp.is_empty() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&fp) {
            map.insert("fingerprint_hash".to_string(), value);
        }
    }
    if response.wildcard_certificate {
        map.insert("wildcard_certificate".to_string(), serde_json::json!(true));
    }
    if !response.sni.is_empty() {
        map.insert("sni".to_string(), serde_json::json!(response.sni));
    }
    serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_default()
}

/// tlsx version naming parity (crypto/tls numeric constant → "tls12" style).
fn go_tls_version(version: rustls::ProtocolVersion) -> &'static str {
    match version {
        rustls::ProtocolVersion::TLSv1_0 => "tls10",
        rustls::ProtocolVersion::TLSv1_1 => "tls11",
        rustls::ProtocolVersion::TLSv1_2 => "tls12",
        rustls::ProtocolVersion::TLSv1_3 => "tls13",
        _ => "",
    }
}

/// Go crypto/tls `CipherSuiteName` parity: rustls Debug prints TLS 1.3
/// suites as TLS13_AES_...; Go prints TLS_AES_...
fn go_cipher_name(suite: rustls::CipherSuite) -> String {
    let name = format!("{:?}", suite);
    match name.strip_prefix("TLS13_") {
        Some(rest) => format!("TLS_{}", rest),
        None => name,
    }
}

#[derive(Debug)]
struct NoVerifyCert;

impl rustls::client::danger::ServerCertVerifier for NoVerifyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_cipher_name_tls13() {
        assert_eq!(
            go_cipher_name(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
            "TLS_AES_128_GCM_SHA256"
        );
        assert_eq!(
            go_cipher_name(rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn test_go_tls_version_names() {
        assert_eq!(go_tls_version(rustls::ProtocolVersion::TLSv1_2), "tls12");
        assert_eq!(go_tls_version(rustls::ProtocolVersion::TLSv1_3), "tls13");
    }

    #[test]
    fn test_mismatched_cert_matching() {
        let names = vec!["example.com".to_string(), "*.example.com".to_string()];
        assert!(!is_mismatched_cert("example.com", &names));
        assert!(!is_mismatched_cert("sub.example.com", &names));
        assert!(is_mismatched_cert("other.org", &names));
        // Wildcard matches exactly one label.
        assert!(is_mismatched_cert("a.b.example.com", &names));
    }

    #[test]
    fn test_variables_skip_zero_values() {
        let resp = SslResponse {
            host: "https://example.com".to_string(),
            matched: "example.com:443".to_string(),
            port: "443".to_string(),
            probe_status: true,
            subject_cn: "example.com".to_string(),
            self_signed: true,
            response: "{}".to_string(),
            ..Default::default()
        };
        let vars = resp.variables();
        assert_eq!(vars.get("subject_cn").map(String::as_str), Some("example.com"));
        assert_eq!(vars.get("self_signed").map(String::as_str), Some("true"));
        assert_eq!(vars.get("Port").map(String::as_str), Some("443"));
        // Zero-value fields are not exposed.
        assert!(!vars.contains_key("cipher"));
        assert!(!vars.contains_key("expired"));
        assert!(!vars.contains_key("issuer_cn"));
    }
}
