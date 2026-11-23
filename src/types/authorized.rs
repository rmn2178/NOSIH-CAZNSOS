//! Compile-time non-bypassable capability gate (`Authorized<T>`).
//!
//! # Security Invariant
//! `Authorized<T>` has a **private** inner field and **NO** public constructor.
//! - `Authorized<ProviderCall>` can ONLY be minted by `crate::plane1::macaroon::chain::MacaroonAuthority::verify_and_authorize`.
//! - `Authorized<ProviderWarmup>` can ONLY be minted by `crate::plane3::power::pa_pcs_pmc::authorize_warmup`.
//!
//! ```compile_fail
//! use nosih_caznsos::types::authorized::{Authorized, ProviderCall};
//! let forged = Authorized(ProviderCall { provider: "openai".into(), model: "gpt-4o".into(), request_id: "r1".into() });
//! ```

use std::marker::PhantomData;

/// Marker payload proving a provider call passed Plane I Macaroon + JTI + Budget verification.
#[derive(Debug, Clone)]
pub struct ProviderCall {
    /// Authorized upstream provider name.
    pub provider: String,
    /// Authorized concrete model identifier.
    pub model: String,
    /// Request identifier bound to this authorization.
    pub request_id: String,
}

/// Marker payload proving a provider warmup passed PA-PCS-PMC pre-authorization.
#[derive(Debug, Clone)]
pub struct ProviderWarmup {
    /// Provider name approved for TCP/TLS warmup.
    pub provider: String,
}

/// Unforgeable compile-time authorization token.
///
/// The inner payload is private; external modules cannot construct `Authorized<T>`.
#[derive(Debug)]
pub struct Authorized<T> {
    inner: T,
    _seal: PhantomData<()>,
}

impl<T> Authorized<T> {
    /// Crate-private minting helper; restricted to Plane I verification and PA-PCS-PMC.
    pub(crate) fn mint_verified(inner: T) -> Self {
        Self {
            inner,
            _seal: PhantomData,
        }
    }

    /// Inspect the verified payload.
    pub fn payload(&self) -> &T {
        &self.inner
    }
}
