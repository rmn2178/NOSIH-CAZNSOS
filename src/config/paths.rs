//! Platform-safe `~/.nosih` directory resolution.

use directories::BaseDirs;
use std::path::PathBuf;

/// Resolve the default NOSIH data directory (`~/.nosih`).
pub fn default_data_dir() -> PathBuf {
    if let Some(base) = BaseDirs::new() {
        base.home_dir().join(".nosih")
    } else {
        PathBuf::from(".nosih")
    }
}

/// Resolve the default Downloads directory for log exports.
pub fn default_export_dir() -> PathBuf {
    if let Some(dirs) = directories::UserDirs::new() {
        if let Some(dl) = dirs.download_dir() {
            return dl.to_path_buf();
        }
    }
    default_data_dir().join("exports")
}
