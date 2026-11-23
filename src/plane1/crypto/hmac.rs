//! Domain-separated HMAC-SHA256 and constant-time tag comparison.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Compute domain-separated HMAC-SHA256 returning 32 raw bytes.
pub fn hmac_sha256(key: &[u8], domain: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return [0u8; 32],
    };
    mac.update(domain);
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Compute lowercase hex HMAC-SHA256.
pub fn hmac_sha256_hex(key: &[u8], domain: &[u8], msg: &[u8]) -> String {
    hex::encode(hmac_sha256(key, domain, msg))
}

/// Constant-time equality check over byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).unwrap_u8() == 1
}
