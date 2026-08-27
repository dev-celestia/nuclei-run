use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct TemplateSigner;

impl TemplateSigner {
    /// Default location for the persisted signing key.
    pub fn default_key_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".nuclei-run").join("signing-key.hex")
    }

    /// Load a signing key from `path`, or create one at the default location
    /// (reused across runs so signatures stay verifiable).
    pub fn load_or_create(custom_path: Option<&Path>) -> std::io::Result<(SigningKey, PathBuf)> {
        let path = custom_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(Self::default_key_path);

        if path.exists() {
            let hex_str = fs::read_to_string(&path)?;
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad key length"))?;
            return Ok((SigningKey::from_bytes(&arr), path));
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, hex::encode(signing_key.to_bytes()))?;
        Ok((signing_key, path))
    }

    /// Load only the verifying half of a persisted key.
    pub fn load_verifying_key(path: &Path) -> std::io::Result<VerifyingKey> {
        let hex_str = fs::read_to_string(path)?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad key length"))?;
        Ok(SigningKey::from_bytes(&arr).verifying_key())
    }

    /// Extract the hex digest from a template's `# digest:` line, if present.
    pub fn extract_digest_hex(content: &str) -> Option<String> {
        content.lines().find_map(|line| {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("# digest:")
                .or_else(|| trimmed.strip_prefix("digest:"))
                .map(|s| s.trim().to_string())
        })
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

    /// Remove digest lines from template content (public for the loader).
    pub fn strip_signature(content: &str) -> String {
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
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test-key.hex");
        let (signing_key, _) = TemplateSigner::load_or_create(Some(&key_path)).unwrap();
        let verifying_key = signing_key.verifying_key();
        let content = "id: test-template\ninfo:\n  name: Test\n  severity: high\n";

        let signature = TemplateSigner::sign_content(content, &signing_key);
        assert!(!signature.is_empty());

        let is_valid = TemplateSigner::verify_content(content, &verifying_key, &signature);
        assert!(is_valid);

        let tampered = "id: test-template\ninfo:\n  name: Tampered\n  severity: high\n";
        let is_tampered_valid = TemplateSigner::verify_content(tampered, &verifying_key, &signature);
        assert!(!is_tampered_valid);
    }

    #[test]
    fn test_key_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("persist.hex");

        let (key1, path1) = TemplateSigner::load_or_create(Some(&key_path)).unwrap();
        assert_eq!(path1, key_path);
        // Second load must return the same key, not a new one.
        let (key2, _) = TemplateSigner::load_or_create(Some(&key_path)).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let vk = TemplateSigner::load_verifying_key(&key_path).unwrap();
        let content = "id: x\n";
        let sig = TemplateSigner::sign_content(content, &key1);
        assert!(TemplateSigner::verify_content(content, &vk, &sig));
    }

    #[test]
    fn test_digest_extraction() {
        let content = "id: t\nhttp: []\n# digest: abcd1234\n";
        assert_eq!(
            TemplateSigner::extract_digest_hex(content),
            Some("abcd1234".to_string())
        );
        assert_eq!(TemplateSigner::extract_digest_hex("id: t\n"), None);
    }
}
