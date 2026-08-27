use crate::models::template::SslBlock;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// SSL / TLS inspection response with extracted certificate attributes.
#[derive(Debug, Clone, Default)]
pub struct SslResponse {
    pub address: String,
    pub subject_cn: String,
    pub issuer_cn: String,
    pub subject_an: Vec<String>,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub not_before: String,
    pub not_after: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub raw: String,
}

pub struct SslClient;

impl SslClient {
    /// Execute SSL inspection against target.
    pub async fn execute(
        block: &SslBlock,
        target: &str,
        timeout_secs: u64,
    ) -> Result<SslResponse, String> {
        let addr_str = block
            .address
            .as_deref()
            .unwrap_or(target)
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');

        let (host, port) = if let Some(idx) = addr_str.rfind(':') {
            (addr_str[..idx].to_string(), addr_str[idx + 1..].parse::<u16>().unwrap_or(443))
        } else {
            (addr_str.to_string(), 443)
        };

        let connect_addr = format!("{}:{}", host, port);
        let timeout = Duration::from_secs(timeout_secs.max(1));

        // Connect with dangerous certificate verification to inspect invalid/self-signed certs too
        let stream = tokio::time::timeout(timeout, TcpStream::connect(&connect_addr))
            .await
            .map_err(|_| format!("Connection timeout to {}", connect_addr))?
            .map_err(|e| format!("Failed to connect to {}: {}", connect_addr, e))?;

        let mut response = SslResponse {
            address: connect_addr.clone(),
            ..Default::default()
        };

        // Use custom rustls client config with custom certificate verifier
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifyCert))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
            .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost").unwrap())
            .to_owned();

        if let Ok(Ok(tls_stream)) = tokio::time::timeout(timeout, connector.connect(server_name, stream)).await {
            let (_, session) = tls_stream.get_ref();
            if let Some(protocol) = session.protocol_version() {
                response.tls_version = format!("{:?}", protocol);
            }
            if let Some(cipher) = session.negotiated_cipher_suite() {
                response.cipher_suite = format!("{:?}", cipher.suite());
            }

            if let Some(certs) = session.peer_certificates() {
                if let Some(leaf_cert) = certs.first() {
                    let cert_der = leaf_cert.as_ref();
                    
                    // SHA256 Fingerprint
                    let mut sha256 = Sha256::new();
                    sha256.update(cert_der);
                    response.fingerprint_sha256 = hex::encode(sha256.finalize());

                    // SHA1 Fingerprint
                    let mut sha1 = Sha1::new();
                    sha1.update(cert_der);
                    response.fingerprint_sha1 = hex::encode(sha1.finalize());

                    // Parse X.509 Certificate
                    if let Ok((_, x509)) = X509Certificate::from_der(cert_der) {
                        response.subject_cn = x509.subject().iter_common_name().next().and_then(|cn| cn.as_str().ok()).unwrap_or_default().to_string();
                        response.issuer_cn = x509.issuer().iter_common_name().next().and_then(|cn| cn.as_str().ok()).unwrap_or_default().to_string();
                        response.serial_number = x509.raw_serial_as_string();
                        response.not_before = x509.validity().not_before.to_rfc2822().unwrap_or_default();
                        response.not_after = x509.validity().not_after.to_rfc2822().unwrap_or_default();

                        if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
                            for name in &san_ext.value.general_names {
                                response.subject_an.push(format!("{:?}", name));
                            }
                        }
                    }
                }
            }
        }

        // Build raw text report for matchers
        response.raw = format!(
            "Subject CN: {}\nIssuer CN: {}\nSANs: {}\nFingerprint SHA256: {}\nTLS Version: {}\nCipher: {}\nValid: {} - {}\n",
            response.subject_cn,
            response.issuer_cn,
            response.subject_an.join(", "),
            response.fingerprint_sha256,
            response.tls_version,
            response.cipher_suite,
            response.not_before,
            response.not_after
        );

        Ok(response)
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
