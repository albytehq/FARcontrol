use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// 32 bytes of OS CSPRNG entropy, base58-encoded (no 0/O/I/l — safe to copy by eye).
/// This is the *identity* secret (agent token / admin token). Authorization is a
/// separate concept (session grants) — invariant 5: secret ≠ session token.
pub fn gen_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    bs58::encode(b).into_string()
}

/// Typed random id: `req_...` / `ses_...` — 16 bytes of entropy, prefix prevents
/// ids from being swapped between roles (see ADR-0012).
pub fn gen_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{}_{}", prefix, bs58::encode(b).into_string())
}

/// 16 random bytes, hex — one-time nonce for request signing.
pub fn gen_nonce() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn hmac_hex(key: &str, msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("hmac accepts any key length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time equality — never short-circuits on the first differing byte.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Canonical string that is signed by the agent: everything that must be
/// integrity-protected. Note: `path` excludes the query string (documented contract).
pub fn signing_payload(ts: &str, nonce: &str, method: &str, path: &str, body_sha256_hex: &str) -> String {
    format!("{ts}\n{nonce}\n{method}\n{path}\n{body_sha256_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // RFC 6234 / FIPS 180-2 test vector
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 2
        assert_eq!(
            hmac_hex("key", "The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"same", b"same"));
        assert!(!ct_eq(b"same", b"samf"));
        assert!(!ct_eq(b"same", b"longer"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn token_format_and_uniqueness() {
        let t1 = gen_token();
        let t2 = gen_token();
        assert_eq!(t1.len(), t1.chars().count());
        assert!(t1.len() >= 40 && t1.len() <= 46, "base58(32B) ≈ 44 chars: {}", t1.len());
        assert_ne!(t1, t2);
        for c in t1.chars() {
            assert!(!"0OIl".contains(c), "base58 alphabet excludes 0/O/I/l");
        }
    }

    #[test]
    fn id_prefix() {
        let id = gen_id("req");
        assert!(id.starts_with("req_"));
        assert!(id.len() > 10);
    }

    #[test]
    fn signing_payload_shape() {
        let p = signing_payload("100", "n", "POST", "/v1/exec", "aa");
        assert_eq!(p, "100\nn\nPOST\n/v1/exec\naa");
    }
}
