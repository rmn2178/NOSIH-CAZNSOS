//! CLI argument parsing and structured tracing bootstrap.

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt};

/// Command-line options for `nosih-caznsos`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "nosih-caznsos",
    version,
    about = "NOSIH-CAZNSOS: Zero-trust, carbon-aware multi-provider OpenAI-compatible LLM proxy"
)]
pub struct CliArgs {
    /// Optional path to `config.toml`.
    #[arg(short, long, env = "NOSIH_CONFIG")]
    pub config: Option<PathBuf>,
    /// Override listening port (default: 8787).
    #[arg(short, long, env = "NOSIH_PORT")]
    pub port: Option<u16>,
    /// Explicitly bind 0.0.0.0 instead of loopback 127.0.0.1.
    #[arg(long, default_value_t = false)]
    pub public: bool,
    /// Enable deterministic stub provider for CI and offline testing.
    #[arg(long, default_value_t = false)]
    pub stub_provider: bool,
    /// Run built-in self-test suite and exit.
    #[arg(long, default_value_t = false)]
    pub self_test: bool,
    /// Do not open the default browser on startup.
    #[arg(long, default_value_t = false)]
    pub no_browser: bool,
    /// Log level filter (`trace`, `debug`, `info`, `warn`, `error`).
    #[arg(long, default_value = "info", env = "NOSIH_LOG")]
    pub log_level: String,
}

/// Initialize tracing subscriber.
pub fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("nosih_caznsos={level},tower_http=info")));
    let _ = fmt().with_env_filter(filter).try_init();
}
