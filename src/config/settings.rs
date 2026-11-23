//! Serializable runtime settings for `nosih-caznsos`.

use crate::config::paths::default_data_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Complete runtime configuration loaded from `~/.nosih/config.toml` or defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Listen host (loopback `127.0.0.1` by default).
    pub host: String,
    /// Listen port (default `8787`).
    pub port: u16,
    /// Local data directory for SQLite WAL DB and keys.
    pub data_dir: PathBuf,
    /// Maximum SQLite database size in megabytes before background pruning.
    pub max_db_mb: u64,
    /// In-memory SSE log ring buffer capacity.
    pub log_ring_capacity: usize,
    /// Per-local-key requests-per-minute rate limit.
    pub rate_limit_rpm: u32,
    /// Maximum entries in PS-RCSC provenance semantic cache.
    pub cache_max_entries: usize,
    /// Optional ElectricityMaps zone code (e.g. `IN-SO`, `US-CAL-CISO`).
    pub carbon_zone: String,
    /// Optional ElectricityMaps API key for live grid intensity.
    pub carbon_api_key: Option<String>,
    /// Allowed admin remote IPs beyond loopback.
    pub admin_allowlist: Vec<String>,
    /// Model alias mapping for virtual tiers (`nosih-small`, `nosih-medium`, `nosih-large`).
    pub tier_models: TierModelMap,
    /// Extra passthrough model -> provider mappings.
    pub model_routes: HashMap<String, String>,
    /// Deterministic stub provider mode for CI and self-tests.
    pub stub_provider: bool,
}

/// Concrete provider/model targets for the three neural router classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TierModelMap {
    /// Small tier target (`nosih-small`).
    pub small: String,
    /// Medium tier target (`nosih-medium`).
    pub medium: String,
    /// Large tier target (`nosih-large`).
    pub large: String,
}

impl Default for TierModelMap {
    fn default() -> Self {
        Self {
            small: "gpt-4o-mini".to_string(),
            medium: "gpt-4o-mini".to_string(),
            large: "gpt-4o".to_string(),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8787,
            data_dir: default_data_dir(),
            max_db_mb: 200,
            log_ring_capacity: 10_000,
            rate_limit_rpm: 120,
            cache_max_entries: 2048,
            carbon_zone: "IN-SO".to_string(),
            carbon_api_key: None,
            admin_allowlist: Vec::new(),
            tier_models: TierModelMap::default(),
            model_routes: HashMap::new(),
            stub_provider: false,
        }
    }
}

impl Settings {
    /// Load settings from a TOML file if present, otherwise return defaults.
    pub fn load_or_default(path: Option<&Path>) -> Self {
        let candidate = path
            .map(PathBuf::from)
            .unwrap_or_else(|| default_data_dir().join("config.toml"));
        if let Ok(raw) = std::fs::read_to_string(&candidate) {
            if let Ok(cfg) = toml::from_str::<Settings>(&raw) {
                return cfg;
            }
        }
        Self::default()
    }

    /// Config TOML file path inside `data_dir`.
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.toml")
    }

    /// Persist current settings to `config.toml` inside `data_dir`.
    pub fn save(&self) -> Result<PathBuf, String> {
        let path = self.config_path();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let encoded = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, encoded).map_err(|e| e.to_string())?;
        Ok(path)
    }

    /// SQLite database file path.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("nosih.db")
    }
}
