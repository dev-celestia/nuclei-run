use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub struct TemplateSigner;

impl TemplateSigner {
    /// Generate a new Ed25519 keypair for signing templates.
    pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    /// Sign a template's content and return hex-encoded signature.
    pub fn sign_content(content: &str, signing_key: &SigningKey) -> String {
        // Strip existing digest line before hashing
        let clean_content = Self::strip_signature(content);
        let mut hasher = Sha256::new();
        hasher.update(clean_content.as_bytes());
        let digest = hasher.finalize();

        let signature = signing_key.sign(&digest);
        hex::encode(signature.to_bytes())
    }

    /// Verify template content against a public key and signature.
    pub fn verify_content(content: &str, verifying_key: &VerifyingKey, sig_hex: &str) -> bool {
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let clean_content = Self::strip_signature(content);
        let mut hasher = Sha256::new();
        hasher.update(clean_content.as_bytes());
        let digest = hasher.finalize();

        verifying_key.verify(&digest, &signature).is_ok()
    }

    /// Sign a template file in place.
    pub fn sign_file(path: &Path, signing_key: &SigningKey) -> std::io::Result<()> {
        let content = fs::read_to_string(path)?;
        let signature = Self::sign_content(&content, signing_key);
        let clean = Self::strip_signature(&content);
        let new_content = format!("{}\n# digest: {}\n", clean.trim_end(), signature);
        fs::write(path, new_content)?;
        Ok(())
    }

    fn strip_signature(content: &str) -> String {
        content
            .lines()
            .filter(|line| !line.trim_start().starts_with("# digest:") && !line.trim_start().starts_with("digest:"))
            .collect::<Vec<&str>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_and_verify() {
        let (signing_key, verifying_key) = TemplateSigner::generate_keypair();
        let content = "id: test-template\ninfo:\n  name: Test\n  severity: high\n";

        let signature = TemplateSigner::sign_content(content, &signing_key);
        assert!(!signature.is_empty());

        let is_valid = TemplateSigner::verify_content(content, &verifying_key, &signature);
        assert!(is_valid);

        let tampered = "id: test-template\ninfo:\n  name: Tampered\n  severity: high\n";
        let is_tampered_valid = TemplateSigner::verify_content(tampered, &verifying_key, &signature);
        assert!(!is_tampered_valid);
    }
}
