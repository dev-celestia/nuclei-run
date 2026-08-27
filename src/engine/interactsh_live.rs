use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use rand::rngs::OsRng;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct LiveInteractshClient {
    pub server_url: String,
    pub token: String,
    pub session_id: String,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl LiveInteractshClient {
    /// Initialize a new live Interactsh RSA session.
    pub fn new(server_url: Option<&str>, token: Option<&str>) -> Result<Self, String> {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|e| e.to_string())?;
        let public_key = RsaPublicKey::from(&private_key);

        let session_id = format!("{:x}", rand::random::<u64>());

        Ok(Self {
            server_url: server_url.unwrap_or("oast.pro").to_string(),
            token: token.unwrap_or_default().to_string(),
            session_id,
            private_key,
            public_key,
        })
    }

    /// Export RSA public key in PKIX format for server registration.
    pub fn public_key_pem(&self) -> Result<String, String> {
        self.public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| e.to_string())
    }

    /// Decrypt RSA-encrypted symmetric AES key sent by the Interactsh server.
    pub fn decrypt_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
        let padding = Oaep::new::<Sha256>();
        self.private_key
            .decrypt(padding, encrypted_key)
            .map_err(|e| e.to_string())
    }

    /// Decrypt AES-128-CBC encrypted interaction event data.
    pub fn decrypt_data(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<String, String> {
        if key.len() < 16 || iv.len() < 16 {
            return Err("Invalid key/iv length for AES-128-CBC".to_string());
        }

        let mut buf = encrypted_data.to_vec();
        let decryptor = Aes128CbcDec::new_from_slices(&key[..16], &iv[..16])
            .map_err(|e| format!("Cipher init error: {}", e))?;

        let decrypted = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| format!("Padding/decrypt error: {:?}", e))?;

        String::from_utf8(decrypted.to_vec()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_interactsh_rsa_keys() {
        let client = LiveInteractshClient::new(None, None).unwrap();
        let pem = client.public_key_pem().unwrap();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }
}
