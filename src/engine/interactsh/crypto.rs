use base64::{engine::general_purpose, Engine as _};
use ctr::cipher::{KeyIvInit, StreamCipher};

pub type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
pub type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Decrypt one poll `data` entry: base64 → AES-CTR with prefixed 16-byte IV.
pub fn decrypt_message(key: &[u8], secure_message: &str) -> Result<Vec<u8>, String> {
    let mut cipher_text = general_purpose::STANDARD
        .decode(secure_message)
        .map_err(|e| e.to_string())?;
    if cipher_text.len() < 16 {
        return Err("ciphertext shorter than IV".to_string());
    }

    let iv: [u8; 16] = cipher_text[..16].try_into().unwrap();
    let mut out = cipher_text.split_off(16);

    match key.len() {
        32 => {
            let mut stream = Aes256Ctr::new_from_slices(key, &iv).map_err(|e| e.to_string())?;
            stream.apply_keystream(&mut out);
        }
        16 => {
            let mut stream = Aes128Ctr::new_from_slices(key, &iv).map_err(|e| e.to_string())?;
            stream.apply_keystream(&mut out);
        }
        n => return Err(format!("unsupported AES key length: {}", n)),
    }
    Ok(out)
}
