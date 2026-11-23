//! Anti-differential strict JSON parser rejecting duplicate keys, NaN/Inf, and out-of-range integers.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane1::jcs::validate::validate_jcs_value;
use serde_json::Value;
use std::collections::HashSet;

/// Parse raw JSON bytes strictly, rejecting duplicate object keys and RFC 8785 violations.
pub fn parse_json_strict(raw: &[u8]) -> AppResult<Value> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| AppError::BadRequest("invalid_utf8_json".into()))?;
    scan_no_duplicates(text)?;
    let val: Value = serde_json::from_str(text)
        .map_err(|e| AppError::BadRequest(format!("malformed_json: {e}")))?;
    validate_jcs_value(&val)?;
    Ok(val)
}

fn scan_no_duplicates(input: &str) -> AppResult<()> {
    let b = input.as_bytes();
    let mut pos = 0usize;
    skip_ws(b, &mut pos);
    scan_val(b, &mut pos)?;
    skip_ws(b, &mut pos);
    if pos != b.len() {
        return Err(AppError::BadRequest("trailing_json_bytes".into()));
    }
    Ok(())
}

fn skip_ws(b: &[u8], pos: &mut usize) {
    while *pos < b.len() && matches!(b[*pos], b' ' | b'\t' | b'\r' | b'\n') {
        *pos += 1;
    }
}

fn scan_val(b: &[u8], pos: &mut usize) -> AppResult<()> {
    skip_ws(b, pos);
    if *pos >= b.len() {
        return Err(AppError::BadRequest("unexpected_eof".into()));
    }
    match b[*pos] {
        b'{' => scan_obj(b, pos),
        b'[' => scan_arr(b, pos),
        b'"' => {
            let _ = scan_str(b, pos)?;
            Ok(())
        }
        b't' => expect_lit(b, pos, b"true"),
        b'f' => expect_lit(b, pos, b"false"),
        b'n' => expect_lit(b, pos, b"null"),
        b'-' | b'0'..=b'9' => scan_num(b, pos),
        _ => Err(AppError::BadRequest("unexpected_json_token".into())),
    }
}

fn expect_lit(b: &[u8], pos: &mut usize, lit: &[u8]) -> AppResult<()> {
    if b[*pos..].starts_with(lit) {
        *pos += lit.len();
        Ok(())
    } else {
        Err(AppError::BadRequest("invalid_json_literal".into()))
    }
}

fn scan_obj(b: &[u8], pos: &mut usize) -> AppResult<()> {
    *pos += 1;
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b'}' {
        *pos += 1;
        return Ok(());
    }
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        skip_ws(b, pos);
        if *pos >= b.len() || b[*pos] != b'"' {
            return Err(AppError::BadRequest("expected_object_key".into()));
        }
        let k = scan_str(b, pos)?;
        if !seen.insert(k.clone()) {
            return Err(AppError::BadRequest(format!("duplicate_json_key:{k}")));
        }
        skip_ws(b, pos);
        if *pos >= b.len() || b[*pos] != b':' {
            return Err(AppError::BadRequest("expected_colon".into()));
        }
        *pos += 1;
        scan_val(b, pos)?;
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err(AppError::BadRequest("unterminated_object".into()));
        }
        match b[*pos] {
            b',' => *pos += 1,
            b'}' => {
                *pos += 1;
                return Ok(());
            }
            _ => return Err(AppError::BadRequest("invalid_object_separator".into())),
        }
    }
}

fn scan_arr(b: &[u8], pos: &mut usize) -> AppResult<()> {
    *pos += 1;
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b']' {
        *pos += 1;
        return Ok(());
    }
    loop {
        scan_val(b, pos)?;
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err(AppError::BadRequest("unterminated_array".into()));
        }
        match b[*pos] {
            b',' => *pos += 1,
            b']' => {
                *pos += 1;
                return Ok(());
            }
            _ => return Err(AppError::BadRequest("invalid_array_separator".into())),
        }
    }
}

fn scan_str(b: &[u8], pos: &mut usize) -> AppResult<String> {
    let start = *pos;
    *pos += 1;
    while *pos < b.len() {
        match b[*pos] {
            b'\\' => *pos += 2,
            b'"' => {
                *pos += 1;
                let s = std::str::from_utf8(&b[start..*pos])
                    .map_err(|_| AppError::BadRequest("invalid_utf8_str".into()))?;
                return serde_json::from_str::<String>(s)
                    .map_err(|e| AppError::BadRequest(format!("bad_string_escape: {e}")));
            }
            _ => *pos += 1,
        }
    }
    Err(AppError::BadRequest("unterminated_string".into()))
}

fn scan_num(b: &[u8], pos: &mut usize) -> AppResult<()> {
    if *pos < b.len() && b[*pos] == b'-' {
        *pos += 1;
    }
    while *pos < b.len() && b[*pos].is_ascii_digit() {
        *pos += 1;
    }
    if *pos < b.len() && b[*pos] == b'.' {
        *pos += 1;
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
    }
    if *pos < b.len() && matches!(b[*pos], b'e' | b'E') {
        *pos += 1;
        if *pos < b.len() && matches!(b[*pos], b'+' | b'-') {
            *pos += 1;
        }
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys() {
        assert!(parse_json_strict(br#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn accepts_clean_json() {
        let v = parse_json_strict(br#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(v["a"], 1);
    }
}
