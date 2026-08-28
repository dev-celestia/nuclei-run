use rand::Rng;
use std::time::Duration;

/// Default public Interactsh servers (mirrors the Go client default list).
pub const DEFAULT_SERVERS: &[&str] = &[
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
];

pub const CORRELATION_ID_LEN: usize = 20;
pub const NONCE_LEN: usize = 13;
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
pub const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Random lowercase-alphanumeric string (correlation ID / secret key).
pub fn random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// z-base-32 encoded random nonce for correlation URLs.
pub fn zbase32_nonce(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ZBASE32_ALPHABET[rng.gen_range(0..32)] as char)
        .collect()
}
