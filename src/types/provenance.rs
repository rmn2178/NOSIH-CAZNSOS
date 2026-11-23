//! Compile-time typed `ProvenanceValue<T, I, C>` carrying Integrity x Confidentiality markers.

use crate::types::confidentiality::{ConfidentialityLevel, ConfidentialityRank};
use crate::types::integrity::{IntegrityLevel, IntegrityRank, SignedErp};
use std::collections::BTreeSet;
use std::marker::PhantomData;

/// A value tagged at compile time with its Integrity `I` and Confidentiality `C` lattice levels.
///
/// Privileged sinks (such as [`erp_like_sink`]) constrain `I = SignedErp`, making it a
/// **compile-time type error** to pass a `ProvenanceValue<_, Untrusted, _>`.
///
/// ```compile_fail
/// use nosih_caznsos::types::provenance::{ProvenanceValue, erp_like_sink};
/// use nosih_caznsos::types::integrity::Untrusted;
/// use nosih_caznsos::types::confidentiality::Public;
///
/// let tainted: ProvenanceValue<String, Untrusted, Public> =
///     ProvenanceValue::new("malicious".into(), ["*".into()].into());
/// erp_like_sink(&tainted); // Must NOT compile!
/// ```
#[derive(Debug, Clone)]
pub struct ProvenanceValue<T, I: IntegrityLevel, C: ConfidentialityLevel> {
    value: T,
    readers: BTreeSet<String>,
    _integrity: PhantomData<I>,
    _conf: PhantomData<C>,
}

impl<T, I: IntegrityLevel, C: ConfidentialityLevel> ProvenanceValue<T, I, C> {
    /// Construct a typed provenance-tagged value.
    pub fn new(value: T, readers: BTreeSet<String>) -> Self {
        Self {
            value,
            readers,
            _integrity: PhantomData,
            _conf: PhantomData,
        }
    }

    /// Borrow inner value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Runtime integrity rank.
    pub fn integrity_rank(&self) -> IntegrityRank {
        I::RUNTIME
    }

    /// Runtime confidentiality rank.
    pub fn confidentiality_rank(&self) -> ConfidentialityRank {
        C::RUNTIME
    }

    /// Borrow authorized readers.
    pub fn readers(&self) -> &BTreeSet<String> {
        &self.readers
    }
}

/// Example compile-time-protected ERP sink that accepts ONLY `SignedErp` integrity values.
pub fn erp_like_sink<T, C: ConfidentialityLevel>(val: &ProvenanceValue<T, SignedErp, C>) -> &T {
    val.value()
}
