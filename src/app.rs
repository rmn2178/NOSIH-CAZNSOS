//! Shared application state (`AppState`) using async-safe `tokio::sync::RwLock`.

use crate::config::secrets::SecretVault;
use crate::config::settings::Settings;
use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::plane1::budget::BudgetLedger;
use crate::plane1::carbon_cert::CarbonCertificateAuthority;
use crate::plane1::crypto::secrets::KeyMaterial;
use crate::plane1::macaroon::chain::MacaroonAuthority;
use crate::plane1::manifest::ManifestGuard;
use crate::plane1::merkle::MerkleLog;
use crate::plane1::replay::JtiReplayStore;
use crate::plane2::bandit::linucb::CaDpdLinUcb;
use crate::plane2::cache::store::ProvenanceCache;
use crate::plane2::carbon::forecaster::DiurnalCarbonForecaster;
use crate::plane2::conformal::pid::ConformalPidGate;
use crate::plane2::pcsp::PcspPricer;
use crate::plane3::power::controller::ProviderPowerManager;
use crate::plane3::providers::chain::ProviderChain;
use crate::security::local_key::LocalSecretToken;
use crate::security::RateLimiter;
use crate::storage::SqliteStorage;
use crate::telemetry::log_ring::LogRing;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared immutable-outer, async-locked-inner application state.
pub struct AppState {
    /// Active runtime settings.
    pub settings: RwLock<Settings>,
    /// Local `/v1` API key.
    pub local_key: LocalSecretToken,
    /// Separate `/admin` token.
    pub admin_token: LocalSecretToken,
    /// SQLite WAL pooled storage.
    pub storage: Arc<SqliteStorage>,
    /// AES-256-GCM encrypted upstream provider key vault.
    pub vault: Arc<SecretVault>,
    /// Unified 7-stage NOSIH kernel.
    pub kernel: Arc<NosihKernel>,
    /// Upstream provider chain gated by `Authorized<ProviderCall>`.
    pub providers: Arc<ProviderChain>,
    /// In-memory ring buffer + SSE broadcast channel for live logs.
    pub log_ring: Arc<LogRing>,
    /// Per-local-key token bucket rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    /// Construct and wire all three NOSIH planes and storage pools.
    pub fn new(
        settings: Settings,
        local_key: LocalSecretToken,
        admin_token: LocalSecretToken,
    ) -> AppResult<Self> {
        let storage = Arc::new(SqliteStorage::open(&settings.db_path())?);
        let vault_key = KeyMaterial::derive_from_seed(local_key.as_str().as_bytes(), b"NOSIH-VAULT-V1");
        let vault = Arc::new(SecretVault::new(Arc::clone(&storage), vault_key));

        let mac_root = KeyMaterial::derive_from_seed(local_key.as_str().as_bytes(), b"NOSIH-MAC-V1");
        let sth_key = KeyMaterial::derive_from_seed(local_key.as_str().as_bytes(), b"NOSIH-STH-V1");
        let manifest_key = KeyMaterial::derive_from_seed(local_key.as_str().as_bytes(), b"NOSIH-MAN-V1");

        let replay = Arc::new(JtiReplayStore::new(Arc::clone(&storage)));
        let budget = Arc::new(BudgetLedger::new(Arc::clone(&storage)));
        let macaroon = Arc::new(MacaroonAuthority::new(mac_root, Arc::clone(&replay), Arc::clone(&budget)));
        let merkle = Arc::new(MerkleLog::new(Arc::clone(&storage), sth_key));
        let ccec = Arc::new(CarbonCertificateAuthority::new(Arc::clone(&merkle)));
        let manifest = Arc::new(ManifestGuard::new_default(manifest_key));

        let cache = Arc::new(RwLock::new(ProvenanceCache::new(settings.cache_max_entries)));
        let bandit = Arc::new(RwLock::new(CaDpdLinUcb::new_default()));
        let conformal = Arc::new(RwLock::new(ConformalPidGate::new_default()));
        let forecaster = Arc::new(RwLock::new(DiurnalCarbonForecaster::new_default()));
        let pcsp = Arc::new(RwLock::new(PcspPricer::new_default()));
        let power = Arc::new(RwLock::new(ProviderPowerManager::new()));
        let log_ring = Arc::new(LogRing::new(settings.log_ring_capacity, Arc::clone(&storage)));

        let kernel = Arc::new(NosihKernel {
            macaroon,
            merkle,
            ccec,
            manifest,
            budget,
            cache,
            bandit,
            conformal,
            forecaster,
            pcsp,
            power,
            log_ring: Arc::clone(&log_ring),
        });

        let providers = Arc::new(ProviderChain::new(
            Arc::clone(&vault),
            settings.stub_provider,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(settings.rate_limit_rpm));

        Ok(Self {
            settings: RwLock::new(settings),
            local_key,
            admin_token,
            storage,
            vault,
            kernel,
            providers,
            log_ring,
            rate_limiter,
        })
    }
}
