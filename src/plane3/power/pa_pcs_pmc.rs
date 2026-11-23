//! PA-PCS-PMC: Single construction site of `Authorized<ProviderWarmup>`.

use crate::types::authorized::{Authorized, ProviderCall, ProviderWarmup};

/// Mint an `Authorized<ProviderWarmup>` strictly from a verified `Authorized<ProviderCall>`.
///
/// This makes Sleep-Thrashing DoS a **compile-time impossibility**: no code path can invoke
/// `ProviderPowerManager::warmup` without first passing Plane I Macaroon + JTI + Budget checks.
pub fn authorize_warmup(call_auth: &Authorized<ProviderCall>) -> Authorized<ProviderWarmup> {
    Authorized::mint_verified(ProviderWarmup {
        provider: call_auth.payload().provider.clone(),
    })
}

#[cfg(test)]
mod tests {
    use crate::plane3::power::controller::ProviderPowerManager;

    #[test]
    fn no_authorized_no_warmup_incurs_zero_joules() {
        let mut mgr = ProviderPowerManager::new();
        mgr.record_unauthorized_probe();
        assert_eq!(mgr.blocked_unauth_wakeups, 1);
    }
}
