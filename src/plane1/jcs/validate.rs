//! RFC 8785 value validation (IEEE-754 safe integer bounds and finite floats).

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use serde_json::Value;

/// Maximum exact IEEE-754 safe integer (`2^53 - 1`).
pub const MAX_SAFE_INT: i64 = (1_i64 << 53) - 1;

/// Recursively validate a JSON value for RFC 8785 compliance.
pub fn validate_jcs_value(v: &Value) -> AppResult<()> {
    match v {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i.abs() > MAX_SAFE_INT {
                    return Err(AppError::BadRequest(format!("unsafe_int:{i}")));
                }
            } else if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INT as u64 {
                    return Err(AppError::BadRequest(format!("unsafe_uint:{u}")));
                }
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(AppError::BadRequest("non_finite_float".into()));
                }
            } else {
                return Err(AppError::BadRequest("invalid_json_number".into()));
            }
            Ok(())
        }
        Value::Array(arr) => {
            for item in arr {
                validate_jcs_value(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for val in map.values() {
                validate_jcs_value(val)?;
            }
            Ok(())
        }
    }
}
