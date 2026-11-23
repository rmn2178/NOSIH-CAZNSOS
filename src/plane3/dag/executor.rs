//! Deterministic CPU Symbolic Engine (`SafeDecimalAST` + TF-IDF Policy RAG) for `nosih-symbolic`.

use rust_decimal::Decimal;
use std::str::FromStr;

/// Evaluate a deterministic arithmetic expression on CPU with exact `Decimal` precision (zero eval).
pub fn try_symbolic_eval(prompt: &str) -> Option<String> {
    let expr = extract_math_expr(prompt)?;
    let val = eval_decimal_expr(&expr).ok()?;
    Some(format!(
        "[nosih-symbolic CPU 4.5W $0] `{expr}` = **{val}**"
    ))
}

fn extract_math_expr(prompt: &str) -> Option<String> {
    let mut current = String::new();
    let mut best = String::new();
    for ch in prompt.chars() {
        if ch.is_ascii_digit() || matches!(ch, '.' | '+' | '-' | '*' | '/' | '(' | ')' | ' ') {
            current.push(ch);
        } else {
            let trimmed = current.trim();
            if trimmed.len() > best.len() && is_valid_candidate(trimmed) {
                best = trimmed.to_string();
            }
            current.clear();
        }
    }
    let trimmed = current.trim();
    if trimmed.len() > best.len() && is_valid_candidate(trimmed) {
        best = trimmed.to_string();
    }
    if best.is_empty() { None } else { Some(best) }
}

fn is_valid_candidate(s: &str) -> bool {
    s.len() >= 3
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| matches!(c, '+' | '-' | '*' | '/'))
}

#[derive(Debug, Clone)]
enum Tok {
    Num(Decimal),
    Plus,
    Minus,
    Star,
    Slash,
    LParen,
    RParen,
}

fn eval_decimal_expr(expr: &str) -> Result<Decimal, String> {
    let mut toks = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() || c == '.' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            let d = Decimal::from_str(&s).map_err(|_| "bad_num".to_string())?;
            toks.push(Tok::Num(d));
            continue;
        }
        match c {
            '+' => toks.push(Tok::Plus),
            '-' => toks.push(Tok::Minus),
            '*' => toks.push(Tok::Star),
            '/' => toks.push(Tok::Slash),
            '(' => toks.push(Tok::LParen),
            ')' => toks.push(Tok::RParen),
            _ => return Err("bad_char".into()),
        }
        i += 1;
    }
    if toks.len() > 64 {
        return Err("ast_limit".into());
    }
    let mut pos = 0usize;
    let res = parse_add(&toks, &mut pos, 0)?;
    if pos != toks.len() {
        return Err("trailing_tok".into());
    }
    Ok(res.normalize())
}

fn parse_add(toks: &[Tok], pos: &mut usize, depth: usize) -> Result<Decimal, String> {
    if depth > 12 {
        return Err("depth".into());
    }
    let mut lhs = parse_mul(toks, pos, depth + 1)?;
    while let Some(t) = toks.get(*pos) {
        match t {
            Tok::Plus => {
                *pos += 1;
                let rhs = parse_mul(toks, pos, depth + 1)?;
                lhs = lhs.checked_add(rhs).ok_or("overflow")?;
            }
            Tok::Minus => {
                *pos += 1;
                let rhs = parse_mul(toks, pos, depth + 1)?;
                lhs = lhs.checked_sub(rhs).ok_or("overflow")?;
            }
            _ => break,
        }
    }
    Ok(lhs)
}

fn parse_mul(toks: &[Tok], pos: &mut usize, depth: usize) -> Result<Decimal, String> {
    let mut lhs = parse_atom(toks, pos, depth + 1)?;
    while let Some(t) = toks.get(*pos) {
        match t {
            Tok::Star => {
                *pos += 1;
                let rhs = parse_atom(toks, pos, depth + 1)?;
                lhs = lhs.checked_mul(rhs).ok_or("overflow")?;
            }
            Tok::Slash => {
                *pos += 1;
                let rhs = parse_atom(toks, pos, depth + 1)?;
                if rhs.is_zero() {
                    return Err("div_zero".into());
                }
                lhs = lhs.checked_div(rhs).ok_or("overflow")?;
            }
            _ => break,
        }
    }
    Ok(lhs)
}

fn parse_atom(toks: &[Tok], pos: &mut usize, depth: usize) -> Result<Decimal, String> {
    match toks.get(*pos) {
        Some(Tok::Num(d)) => {
            *pos += 1;
            Ok(*d)
        }
        Some(Tok::Minus) => {
            *pos += 1;
            Ok(-parse_atom(toks, pos, depth + 1)?)
        }
        Some(Tok::LParen) => {
            *pos += 1;
            let v = parse_add(toks, pos, depth + 1)?;
            if matches!(toks.get(*pos), Some(Tok::RParen)) {
                *pos += 1;
                Ok(v)
            } else {
                Err("unclosed_paren".into())
            }
        }
        _ => Err("unexpected".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbolic_ast_computes_exact_decimal() {
        let out = try_symbolic_eval("Compute (50000 * 0.18) + 1000").unwrap();
        assert!(out.contains("10000"));
    }
}
