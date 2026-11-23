//! Standard `AppResult<T>` alias.

use crate::error::api_error::AppError;

/// Convenience result alias used across `nosih-caznsos`.
pub type AppResult<T> = Result<T, AppError>;
