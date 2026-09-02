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

/// A single certificate shaped like Go tlsx's `CertificateResponse`
/// (`github.com/projectdiscovery/tlsx/pkg/tlsx/clients`), flattened by json tag
/// into the SSL operator data map. One instance is produced per peer
/// certificate: the leaf is the embedded `certificate` field of `SslResponse`,
/// and the remaining intermediates form `chain`.
#[derive(Debug, Clone, Default)]
pub struct SslCertificateResponse {
    /// Whether the certificate has expired (Go `expired`).
    pub expired: bool,
    /// Whether the certificate is self-signed (Go `self_signed`).
    pub self_signed: bool,
    /// Whether the certificate does not match the dialed host (Go `mismatched`).
    pub mismatched: bool,
    /// Not-before timestamp (RFC 3339, Go `not_before`).
    pub not_before: String,
    /// Not-after timestamp (RFC 3339, Go `not_after`).
    pub not_after: String,
    /// Distinguished name of the subject (Go `subject_dn`).
    pub subject_dn: String,
    /// Common name of the subject (Go `subject_cn`).
    pub subject_cn: String,
    /// Organization names of the subject, in RDN order (Go `subject_org`).
    pub subject_org: Vec<String>,
    /// Subject alternative names, DNS entries only (Go `subject_an`).
    pub subject_an: Vec<String>,
    /// Deduplicated SANs + subject CN with the `*.` prefix stripped (Go `domains`).
    pub domains: Vec<String>,
    /// Serial as colon-separated uppercase hex (Go `serial`).
    pub serial: String,
    /// Distinguished name of the issuer (Go `issuer_dn`).
    pub issuer_dn: String,
    /// Common name of the issuer (Go `issuer_cn`).
    pub issuer_cn: String,
    /// Organization names of the issuer, in RDN order (Go `issuer_org`).
    pub issuer_org: Vec<String>,
    /// Email address SAN entries (Go `emails`).
    pub emails: Vec<String>,
    pub fingerprint_md5: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    /// The raw certificate in PEM format (Go `certificate`).
    pub certificate: String,
    /// Whether the certificate is a wildcard certificate (Go `wildcard_certificate`).
    pub wildcard_certificate: bool,
}

impl SslCertificateResponse {
    /// Go `%v` rendering of the fingerprint struct (`{md5 sha1 sha256}`), used
    /// for the top-level `fingerprint_hash` data-map variable. Empty only when
    /// every fingerprint is zero (i.e. no certificate was parsed).
    fn fingerprint_go(&self) -> String {
        if self.fingerprint_md5.is_empty()
            && self.fingerprint_sha1.is_empty()
            && self.fingerprint_sha256.is_empty()
        {
            return String::new();
        }
        format!(
            "{{{} {} {}}}",
            self.fingerprint_md5, self.fingerprint_sha1, self.fingerprint_sha256
        )
    }

    /// JSON rendering of the nested `fingerprint_hash` object used inside the
    /// `response` JSON string.
    fn fingerprint_json(&self) -> serde_json::Value {
        let mut fp = serde_json::Map::new();
        if !self.fingerprint_md5.is_empty() {
            fp.insert("md5".to_string(), serde_json::json!(self.fingerprint_md5));
        }
        if !self.fingerprint_sha1.is_empty() {
            fp.insert("sha1".to_string(), serde_json::json!(self.fingerprint_sha1));
        }
        if !self.fingerprint_sha256.is_empty() {
            fp.insert(
                "sha256".to_string(),
                serde_json::json!(self.fingerprint_sha256),
            );
        }
        serde_json::Value::Object(fp)
    }

    /// JSON rendering of this certificate as a `CertificateResponse` object,
    /// matching tlsx field names and `omitempty` semantics.
    fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        if self.expired {
            map.insert("expired".to_string(), serde_json::json!(true));
        }
        if self.self_signed {
            map.insert("self_signed".to_string(), serde_json::json!(true));
        }
        if self.mismatched {
            map.insert("mismatched".to_string(), serde_json::json!(true));
        }
        if !self.not_before.is_empty() {
            map.insert("not_before".to_string(), serde_json::json!(self.not_before));
        }
        if !self.not_after.is_empty() {
            map.insert("not_after".to_string(), serde_json::json!(self.not_after));
        }
        if !self.subject_dn.is_empty() {
            map.insert("subject_dn".to_string(), serde_json::json!(self.subject_dn));
        }
        if !self.subject_cn.is_empty() {
            map.insert("subject_cn".to_string(), serde_json::json!(self.subject_cn));
        }
        if !self.subject_org.is_empty() {
            map.insert(
                "subject_org".to_string(),
                serde_json::json!(self.subject_org),
            );
        }
        if !self.subject_an.is_empty() {
            map.insert("subject_an".to_string(), serde_json::json!(self.subject_an));
        }
        if !self.domains.is_empty() {
            map.insert("domains".to_string(), serde_json::json!(self.domains));
        }
        if !self.serial.is_empty() {
            map.insert("serial".to_string(), serde_json::json!(self.serial));
        }
        if !self.issuer_dn.is_empty() {
            map.insert("issuer_dn".to_string(), serde_json::json!(self.issuer_dn));
        }
        if !self.issuer_cn.is_empty() {
            map.insert("issuer_cn".to_string(), serde_json::json!(self.issuer_cn));
        }
        if !self.issuer_org.is_empty() {
            map.insert("issuer_org".to_string(), serde_json::json!(self.issuer_org));
        }
        if !self.emails.is_empty() {
            map.insert("emails".to_string(), serde_json::json!(self.emails));
        }
        if !self.certificate.is_empty() {
            map.insert(
                "certificate".to_string(),
                serde_json::json!(self.certificate),
            );
        }
        if self.wildcard_certificate {
            map.insert("wildcard_certificate".to_string(), serde_json::json!(true));
        }
        let fp = self.fingerprint_json();
        if !fp.is_null() {
            map.insert("fingerprint_hash".to_string(), fp);
        }
        serde_json::Value::Object(map)
    }
}

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
    /// Negotiated key-exchange group in Go `CurveID` naming (Go `key_exchange`).
    pub key_exchange: String,
    /// Server name presented during the handshake (Go `sni`).
    pub sni: String,
    /// TLS client implementation used (Go `tls_connection`).
    pub tls_connection: String,
    /// The leaf certificate (tlsx embedded `*CertificateResponse`).
    pub certificate: SslCertificateResponse,
    /// Peer certificates after the leaf, in wire order (Go `chain`).
    pub chain: Vec<SslCertificateResponse>,
    /// Protocol type (Go `type` data-map variable, always `"ssl"`).
    pub protocol_type: String,
    /// Full response as a JSON string (Go default match part).
    pub response: String,
}

impl SslResponse {
    /// Go-parity variable map for matchers/extractors: every non-zero tlsx
    /// field flattened by json tag, plus host/matched/ip/port/Port/type/response.
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
        let protocol_type = if self.protocol_type.is_empty() {
            "ssl"
        } else {
            self.protocol_type.as_str()
        };
        vars.insert("type".to_string(), protocol_type.to_string());

        insert_str(&mut vars, "tls_version", &self.tls_version);
        insert_str(&mut vars, "cipher", &self.cipher);
        insert_str(&mut vars, "key_exchange", &self.key_exchange);
        insert_str(&mut vars, "sni", &self.sni);
        insert_str(&mut vars, "tls_connection", &self.tls_connection);

        let cert = &self.certificate;
        insert_str(&mut vars, "subject_cn", &cert.subject_cn);
        if !cert.subject_org.is_empty() {
            vars.insert("subject_org".to_string(), go_slice(&cert.subject_org));
        }
        if !cert.subject_an.is_empty() {
            vars.insert("subject_an".to_string(), go_slice(&cert.subject_an));
        }
        insert_str(&mut vars, "subject_dn", &cert.subject_dn);
        insert_str(&mut vars, "issuer_cn", &cert.issuer_cn);
        if !cert.issuer_org.is_empty() {
            vars.insert("issuer_org".to_string(), go_slice(&cert.issuer_org));
        }
        insert_str(&mut vars, "issuer_dn", &cert.issuer_dn);
        if !cert.emails.is_empty() {
            vars.insert("emails".to_string(), go_slice(&cert.emails));
        }
        insert_str(&mut vars, "serial", &cert.serial);
        insert_str(&mut vars, "not_before", &cert.not_before);
        insert_str(&mut vars, "not_after", &cert.not_after);
        if !cert.domains.is_empty() {
            vars.insert("domains".to_string(), go_slice(&cert.domains));
        }
        if cert.expired {
            vars.insert("expired".to_string(), "true".to_string());
        }
        if cert.self_signed {
            vars.insert("self_signed".to_string(), "true".to_string());
        }
        if cert.mismatched {
            vars.insert("mismatched".to_string(), "true".to_string());
        }
        if cert.wildcard_certificate {
            vars.insert("wildcard_certificate".to_string(), "true".to_string());
        }
        insert_str(&mut vars, "certificate", &cert.certificate);

        let fp = cert.fingerprint_go();
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
        let rendered =
            TemplateDsl::interpolate(&VariableResolver::resolve(raw_addr, target), target, vars);
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
            protocol_type: "ssl".to_string(),
            tls_connection: "rustls".to_string(),
            ..Default::default()
        };

        // Inspect any certificate, including self-signed/expired ones.
        // Honor the template's min/max TLS version and cipher-suite filters
        // (Go passes these to tlsx; a handshake that cannot satisfy them fails,
        // yielding no result — same as Go returning an error).
        let mut provider = rustls::crypto::ring::default_provider();
        if !block.cipher_suites.is_empty() {
            // Restrict the provider to the template's requested suites. Filtering
            // the default provider list keeps kx groups / RNG / signature algs
            // intact while only limiting which suites may be negotiated.
            provider.cipher_suites.retain(|suite| {
                let name = go_cipher_name(suite.suite());
                block
                    .cipher_suites
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&name))
            });
        }

        let versions = resolve_tls_versions(
            block.min_version.as_deref(),
            block.max_version.as_deref(),
        )
        .ok_or_else(|| "no supported TLS version in configured range".to_string())?;

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)
            .map_err(|e| format!("invalid TLS version configuration: {}", e))?
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
        if let Some(group) = session.negotiated_key_exchange_group() {
            response.key_exchange = go_key_exchange_name(group.name());
        }

        if let Some(certs) = session.peer_certificates() {
            let parsed: Vec<SslCertificateResponse> = certs
                .iter()
                .map(|c| parse_certificate(c.as_ref(), &host))
                .collect();
            if let Some(leaf) = parsed.first() {
                response.certificate = leaf.clone();
            }
            // tlsx stores only the non-leaf certificates in `chain`.
            response.chain = parsed.into_iter().skip(1).collect();
        }

        response.response = build_response_json(&response);
        Ok(response)
    }
}

/// Parse a single certificate DER into an owned `CertificateResponse`, exactly
/// matching tlsx's per-certificate field computation (fingerprints, DN, serial,
/// validity, SANs/domains, orgs, emails, self-signed detection).
fn parse_certificate(cert_der: &[u8], host: &str) -> SslCertificateResponse {
    let mut cert = SslCertificateResponse::default();

    let mut md5 = Md5::new();
    md5.update(cert_der);
    cert.fingerprint_md5 = hex::encode(md5.finalize());

    let mut sha1 = Sha1::new();
    sha1.update(cert_der);
    cert.fingerprint_sha1 = hex::encode(sha1.finalize());

    let mut sha256 = Sha256::new();
    sha256.update(cert_der);
    cert.fingerprint_sha256 = hex::encode(sha256.finalize());

    cert.certificate = pem_encode_certificate(cert_der);

    let Ok((_, x509)) = X509Certificate::from_der(cert_der) else {
        return cert;
    };

    cert.subject_cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();
    cert.issuer_cn = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();
    cert.subject_dn = format_dn(x509.subject());
    cert.issuer_dn = format_dn(x509.issuer());
    // tlsx parses `Organization []string` from every O (2.5.4.10) attribute.
    cert.subject_org = collect_org(x509.subject());
    cert.issuer_org = collect_org(x509.issuer());

    // tlsx FormatToSerialNumber: colon-separated uppercase hex of the bytes.
    let serial_bytes = x509.raw_serial();
    if !serial_bytes.is_empty() {
        cert.serial = serial_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");
    }

    cert.not_before = rfc3339(x509.validity().not_before.timestamp());
    cert.not_after = rfc3339(x509.validity().not_after.timestamp());
    cert.expired = x509.validity().not_after.timestamp() < chrono::Utc::now().timestamp();

    if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => cert.subject_an.push(dns.to_string()),
                // tlsx `Emails []string` collects RFC822 SAN entries.
                GeneralName::RFC822Name(email) => cert.emails.push(email.to_string()),
                _ => {}
            }
        }
    }

    // domains: deduplicated SANs + subject CN, wildcard prefix stripped
    // (tlsx GetUniqueDomainsFromCert).
    let mut seen = std::collections::HashSet::new();
    let mut domains = Vec::new();
    for name in cert
        .subject_an
        .iter()
        .chain(std::iter::once(&cert.subject_cn))
    {
        if name.is_empty() {
            continue;
        }
        let trimmed = name.trim_start_matches("*.");
        if seen.insert(trimmed.to_string()) {
            domains.push(trimmed.to_string());
        }
    }
    cert.domains = domains;

    let mut domain_names = vec![cert.subject_cn.clone()];
    domain_names.extend(cert.subject_an.iter().cloned());
    cert.mismatched = is_mismatched_cert(host, &domain_names);
    cert.wildcard_certificate = domain_names.iter().any(|n| n.contains("*."));

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
    cert.self_signed = match authority_key_id {
        None => true,
        Some(akid) => subject_key_id == Some(akid),
    };

    cert
}

/// Collect every organization attribute (OID 2.5.4.10) from a DN, in RDN
/// order, matching Go pkix `Name.Organization`.
fn collect_org(name: &X509Name) -> Vec<String> {
    let mut orgs = Vec::new();
    for rdn in name.iter() {
        for atv in rdn.iter() {
            if atv.attr_type().to_id_string() == "2.5.4.10" {
                if let Ok(value) = atv.as_str() {
                    orgs.push(value.to_string());
                }
            }
        }
    }
    orgs
}

/// PEM-encode a DER certificate exactly like Go `pem.Encode`: a BEGIN line,
/// base64 wrapped at 64 characters per line, and an END line, each terminated
/// by a newline.
fn pem_encode_certificate(der: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    let b64 = general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
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

/// Full response JSON with Go tlsx field names (omitempty respected). The leaf
/// certificate's fields are inlined (tlsx embeds `*CertificateResponse`), the
/// negotiated TLS metadata is added at the top level, and any intermediates
/// are serialized under `chain`.
fn build_response_json(response: &SslResponse) -> String {
    let mut map = serde_json::Map::new();
    map.insert("host".to_string(), serde_json::json!(response.host));
    if !response.ip.is_empty() {
        map.insert("ip".to_string(), serde_json::json!(response.ip));
    }
    map.insert("port".to_string(), serde_json::json!(response.port));
    map.insert(
        "probe_status".to_string(),
        serde_json::json!(response.probe_status),
    );
    if !response.tls_version.is_empty() {
        map.insert(
            "tls_version".to_string(),
            serde_json::json!(response.tls_version),
        );
    }
    if !response.cipher.is_empty() {
        map.insert("cipher".to_string(), serde_json::json!(response.cipher));
    }
    if !response.key_exchange.is_empty() {
        map.insert(
            "key_exchange".to_string(),
            serde_json::json!(response.key_exchange),
        );
    }
    if !response.sni.is_empty() {
        map.insert("sni".to_string(), serde_json::json!(response.sni));
    }
    if !response.tls_connection.is_empty() {
        map.insert(
            "tls_connection".to_string(),
            serde_json::json!(response.tls_connection),
        );
    }

    if let serde_json::Value::Object(cert_map) = response.certificate.to_json() {
        for (k, v) in cert_map {
            map.insert(k, v);
        }
    }

    if !response.chain.is_empty() {
        let chain: Vec<serde_json::Value> =
            response.chain.iter().map(|cert| cert.to_json()).collect();
        map.insert("chain".to_string(), serde_json::json!(chain));
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

/// Map a tlsx/TLS version name ("tls13", "tls12", ...) to the rustls
/// static `SupportedProtocolVersion`. rustls only ships TLS 1.2/1.3, so older
/// versions map to `None` (they cannot be negotiated and are filtered out).
fn tls_version_static(name: &str) -> Option<&'static rustls::SupportedProtocolVersion> {
    match name.trim().to_ascii_lowercase().as_str() {
        "tls13" | "1.3" => Some(&rustls::version::TLS13),
        "tls12" | "1.2" => Some(&rustls::version::TLS12),
        _ => None,
    }
}

/// Resolve the effective rustls protocol-version list from the template's
/// `min_version`/`max_version` fields (Go passes these straight to tlsx).
/// Returns `None` when every configured version is unsupported by rustls
/// (e.g. only tls10/sslv3), which the caller treats as "probe cannot run".
fn resolve_tls_versions(
    min: Option<&str>,
    max: Option<&str>,
) -> Option<Vec<&'static rustls::SupportedProtocolVersion>> {
    // Rank supported versions (higher is newer).
    let all: [&'static rustls::SupportedProtocolVersion; 2] =
        [&rustls::version::TLS12, &rustls::version::TLS13];
    let rank = |v: &'static rustls::SupportedProtocolVersion| match v.version {
        rustls::ProtocolVersion::TLSv1_3 => 3u8,
        rustls::ProtocolVersion::TLSv1_2 => 2,
        _ => 0,
    };

    // min is a lower bound: unspecified or an old/unknown version ranks 0.
    let min_rank = min
        .map(|m| tls_version_static(m).map(rank).unwrap_or(0))
        .unwrap_or(0);
    // max is an upper bound: unspecified ranks 3 (TLS 1.3); an old/unknown
    // explicit max ranks 0 (can only be satisfied by versions rustls lacks).
    let max_rank = max
        .map(|m| tls_version_static(m).map(rank).unwrap_or(0))
        .unwrap_or(3);

    // Inverted or impossible bounds yield no runnable range.
    if min_rank > max_rank {
        return None;
    }

    let filtered: Vec<_> = all
        .iter()
        .copied()
        .filter(|v| {
            let r = rank(v);
            r >= min_rank && r <= max_rank
        })
        .collect();
    if filtered.is_empty() {
        None
    } else {
        Some(filtered)
    }
}

/// Go crypto/tls `CurveID.String()` parity: rustls `NamedGroup` names differ
/// for NIST curves, so map to the Go `CurveP*` spellings.
fn go_key_exchange_name(group: rustls::NamedGroup) -> String {
    match group {
        rustls::NamedGroup::secp256r1 => "CurveP256".to_string(),
        rustls::NamedGroup::secp384r1 => "CurveP384".to_string(),
        rustls::NamedGroup::secp521r1 => "CurveP521".to_string(),
        rustls::NamedGroup::X25519 => "X25519".to_string(),
        rustls::NamedGroup::X25519MLKEM768 => "X25519MLKEM768".to_string(),
        rustls::NamedGroup::secp256r1MLKEM768 => "SecP256r1MLKEM768".to_string(),
        _ => format!("CurveID({})", u16::from(group)),
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
    fn test_go_key_exchange_names() {
        assert_eq!(go_key_exchange_name(rustls::NamedGroup::X25519), "X25519");
        assert_eq!(
            go_key_exchange_name(rustls::NamedGroup::secp256r1),
            "CurveP256"
        );
        assert_eq!(
            go_key_exchange_name(rustls::NamedGroup::secp384r1),
            "CurveP384"
        );
        assert_eq!(
            go_key_exchange_name(rustls::NamedGroup::secp521r1),
            "CurveP521"
        );
        assert_eq!(
            go_key_exchange_name(rustls::NamedGroup::X25519MLKEM768),
            "X25519MLKEM768"
        );
    }

    #[test]
    fn test_variables_skip_zero_values() {
        let resp = SslResponse {
            host: "https://example.com".to_string(),
            matched: "example.com:443".to_string(),
            port: "443".to_string(),
            probe_status: true,
            protocol_type: "ssl".to_string(),
            certificate: SslCertificateResponse {
                subject_cn: "example.com".to_string(),
                self_signed: true,
                ..Default::default()
            },
            response: "{}".to_string(),
            ..Default::default()
        };
        let vars = resp.variables();
        assert_eq!(
            vars.get("subject_cn").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(vars.get("self_signed").map(String::as_str), Some("true"));
        assert_eq!(vars.get("Port").map(String::as_str), Some("443"));
        assert_eq!(vars.get("type").map(String::as_str), Some("ssl"));
        // Zero-value fields are not exposed.
        assert!(!vars.contains_key("cipher"));
        assert!(!vars.contains_key("expired"));
        assert!(!vars.contains_key("issuer_cn"));
        assert!(!vars.contains_key("subject_org"));
        assert!(!vars.contains_key("emails"));
        assert!(!vars.contains_key("certificate"));
        assert!(!vars.contains_key("key_exchange"));
        assert!(!vars.contains_key("tls_connection"));
    }

    #[test]
    fn test_fingerprint_hash_go_rendering() {
        let cert = SslCertificateResponse {
            fingerprint_md5: "md5hash".to_string(),
            fingerprint_sha1: "sha1hash".to_string(),
            fingerprint_sha256: "sha256hash".to_string(),
            ..Default::default()
        };
        let resp = SslResponse {
            protocol_type: "ssl".to_string(),
            certificate: cert,
            ..Default::default()
        };
        let vars = resp.variables();
        // Top-level variable is Go `%v` struct rendering (space-separated, no
        // field names), NOT JSON.
        assert_eq!(
            vars.get("fingerprint_hash").map(String::as_str),
            Some("{md5hash sha1hash sha256hash}")
        );
    }

    #[test]
    fn test_pem_encode_certificate() {
        // A small arbitrary DER payload.
        let der: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
        let pem = pem_encode_certificate(der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        // Body must be standard base64 wrapped at 64 columns.
        let body: String = pem
            .lines()
            .skip(1)
            .take_while(|l| *l != "-----END CERTIFICATE-----")
            .collect::<Vec<_>>()
            .join("\n");
        for line in pem
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
        {
            assert!(line.len() <= 64, "PEM line exceeds 64 chars: {line}");
        }
        use base64::{engine::general_purpose, Engine as _};
        let decoded = general_purpose::STANDARD.decode(body.trim()).unwrap();
        assert_eq!(decoded, der);
    }

    #[test]
    fn test_resolve_tls_versions_none() {
        // No constraints → both TLS 1.2 and 1.3.
        let v = resolve_tls_versions(None, None).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_resolve_tls_versions_min() {
        // min tls13 → only TLS 1.3.
        let v = resolve_tls_versions(Some("tls13"), None).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].version, rustls::ProtocolVersion::TLSv1_3);
        // min tls12 → both.
        let v = resolve_tls_versions(Some("tls12"), None).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_resolve_tls_versions_max() {
        // max tls12 → only TLS 1.2.
        let v = resolve_tls_versions(None, Some("tls12")).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_resolve_tls_versions_unsupported() {
        // tlsx supports sslv3/tls10/tls11 but rustls does not. A min bound of
        // tls10 alone is satisfiable (1.2/1.3 are newer); capping the max
        // below TLS 1.2 is not.
        assert!(resolve_tls_versions(Some("sslv3"), Some("tls11")).is_none());
        assert!(resolve_tls_versions(Some("tls10"), Some("tls11")).is_none());
        assert_eq!(
            resolve_tls_versions(Some("tls10"), None).map(|v| v.len()),
            Some(2)
        );
        // Inverted bounds are an impossible range.
        assert!(resolve_tls_versions(Some("tls13"), Some("tls12")).is_none());
        // sslv3→tls13 is the full range: both 1.2 and 1.3 satisfy it.
        assert_eq!(
            resolve_tls_versions(Some("sslv3"), Some("tls13")).map(|v| v.len()),
            Some(2)
        );
    }

    #[test]
    fn test_cipher_restriction_filters_provider() {
        // Filtering the default ring provider by a specific suite must retain
        // exactly that suite.
        let default = rustls::crypto::ring::default_provider();
        assert!(!default.cipher_suites.is_empty());
        let requested = "TLS_AES_128_GCM_SHA256";
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites.retain(|suite| {
            go_cipher_name(suite.suite()).eq_ignore_ascii_case(requested)
        });
        assert_eq!(provider.cipher_suites.len(), 1);
        assert_eq!(
            go_cipher_name(provider.cipher_suites[0].suite()),
            requested
        );
    }
}
