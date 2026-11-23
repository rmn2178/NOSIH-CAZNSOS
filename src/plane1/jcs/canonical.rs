//! RFC 8785 canonical serializer with UTF-16 key ordering and `ryu` shortest float formatting.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane1::jcs::validate::{MAX_SAFE_INT, validate_jcs_value};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize a JSON value into canonical RFC 8785 string form.
pub fn jcs_dumps(val: &Value) -> AppResult<String> {
    validate_jcs_value(val)?;
    let mut out = String::new();
    write_val(val, &mut out)?;
    Ok(out)
}

/// Serialize to canonical UTF-8 bytes.
pub fn jcs_bytes(val: &Value) -> AppResult<Vec<u8>> {
    Ok(jcs_dumps(val)?.into_bytes())
}

/// Compute lowercase hex SHA-256 over the RFC 8785 canonical encoding.
pub fn jcs_sha256(val: &Value) -> AppResult<String> {
    Ok(hex::encode(Sha256::digest(jcs_bytes(val)?)))
}

fn write_val(val: &Value, out: &mut String) -> AppResult<()> {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                if f == 0.0 {
                    out.push('0');
                } else if f.fract() == 0.0 && f.abs() <= MAX_SAFE_INT as f64 {
                    out.push_str(&(f as i64).to_string());
                } else {
                    let mut buf = ryu::Buffer::new();
                    out.push_str(buf.format(f));
                }
            }
        }
        Value::String(s) => {
            let esc = serde_json::to_string(s)
                .map_err(|e| AppError::BadRequest(e.to_string()))?;
            out.push_str(&esc);
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_val(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| {
                a.encode_utf16().cmp(b.encode_utf16())
            });
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let esc_k = serde_json::to_string(k)
                    .map_err(|e| AppError::BadRequest(e.to_string()))?;
                out.push_str(&esc_k);
                out.push(':');
                write_val(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalizes_keys_and_neg_zero() {
        let v = json!({"z": 1, "a": -0.0, "b": true});
        assert_eq!(jcs_dumps(&v).unwrap(), r#"{"a":0,"b":true,"z":1}"#);
    }
}
