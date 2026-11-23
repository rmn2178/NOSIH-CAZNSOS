//! Compile-time embedded static UI assets via `rust-embed`.

use rust_embed::RustEmbed;

/// Embedded SPA files from `src/ui/embedded/`.
#[derive(RustEmbed)]
#[folder = "src/ui/embedded/"]
pub struct UiAssets;
