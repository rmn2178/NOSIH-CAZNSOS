//! RFC 5869 HKDF-SHA256 key derivation.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte key using RFC 5869 HKDF-SHA256.
pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    let _ = hk.expand(info, &mut okm);
    okm
}
