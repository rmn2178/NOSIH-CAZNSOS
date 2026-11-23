//! Zeroizing 256-bit cryptographic key material.

use crate::plane1::crypto::hkdf::hkdf_sha256_32;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit secret key that automatically zeroes memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial([u8; 32]);

impl KeyMaterial {
    /// Wrap 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate fresh 256-bit key material via OS CSPRNG, returning an error if entropy fails.
    pub fn try_generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Generate fresh 256-bit key material via OS CSPRNG (aborts on CSPRNG failure; never zero-falls back).
    pub fn generate() -> Self {
        Self::try_generate().expect("OS CSPRNG failure while generating KeyMaterial")
    }

    /// Derive domain-separated 256-bit key material via HKDF-SHA256.
    pub fn derive_from_seed(ikm: &[u8], info: &[u8]) -> Self {
        Self(hkdf_sha256_32(ikm, b"NOSIH-CAZNSOS-SALT-V1", info))
    }

    /// Borrow key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
