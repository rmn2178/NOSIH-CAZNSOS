//! 10D lexical, structural, symbolic, and Shannon-entropy feature extractor with anti-spoofing.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const RISK_TERMS: &[&str] = &[
    "payout", "neft", "transfer", "wire", "bank", "iban", "gstin", "gstr",
    "override", "bypass", "ignore", "admin", "secret", "password", "webhook",
    "exfiltrate", "refund", "invoice", "audit", "credential", "token",
];

/// Bounded 10D feature vector (`||x_t||_2 <= 2.0`) for `CA-DPD-LinUCB`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureProfile10D {
    /// 10-dimensional bounded context vector.
    pub vector: [f64; 10],
    /// Whether deterministic arithmetic expression cues are present.
    pub has_math: bool,
    /// Whether structured policy RAG cues are present.
    pub has_rag: bool,
    /// Calibrated risk score in `[0.0, 1.0]`.
    pub risk_score: f64,
    /// True if repetition stuffing or unique-filler DoW was neutralized.
    pub spoof_filtered: bool,
    /// Unique token ratio.
    pub unique_ratio: f64,
    /// Token count.
    pub token_count: usize,
}

/// Extract 10D anti-spoofing features purely on CPU in microseconds.
pub fn extract_features_10d(prompt: &str) -> FeatureProfile10D {
    let lower = prompt.to_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric() && !matches!(c, '_' | '.' | '+' | '-' | '*' | '/' | '^' | '%'))
        .filter(|s| !s.is_empty())
        .collect();
    let n_tok = tokens.len().max(1);
    let uniq: HashSet<&str> = tokens.iter().copied().collect();
    let unique_ratio = uniq.len() as f64 / n_tok as f64;

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for &t in &tokens {
        *counts.entry(t).or_insert(0) += 1;
    }
    let tok_ent: f64 = counts
        .values()
        .map(|&c| {
            let p = c as f64 / n_tok as f64;
            -p * p.log2()
        })
        .sum();

    let trimmed = if prompt.trim().is_empty() { " " } else { prompt.trim() };
    let mut ccounts: HashMap<char, usize> = HashMap::new();
    let mut n_ch = 0usize;
    let mut digits = 0usize;
    for ch in trimmed.chars() {
        *ccounts.entry(ch).or_insert(0) += 1;
        n_ch += 1;
        if ch.is_ascii_digit() {
            digits += 1;
        }
    }
    let n_ch_f = n_ch.max(1) as f64;
    let ch_ent: f64 = ccounts
        .values()
        .map(|&c| {
            let p = c as f64 / n_ch_f;
            -p * p.log2()
        })
        .sum();

    let has_math = prompt.chars().any(|c| matches!(c, '+' | '-' | '*' | '/' | '^'))
        && prompt.chars().any(|c| c.is_ascii_digit());
    let has_rag = ["spec", "policy", "clause", "gstin", "gstr", "compliance", "sla", "manual"]
        .iter()
        .any(|kw| lower.contains(kw));
    let is_structured = prompt.contains('{') && prompt.contains(':');

    let risk_set: HashSet<&str> = RISK_TERMS.iter().copied().collect();
    let risk_hits = tokens.iter().filter(|t| risk_set.contains(**t)).count();
    let uniq_risk = uniq.iter().filter(|t| risk_set.contains(**t)).count();
    let risk_density = risk_hits as f64 / n_tok as f64;

    let rep_spoof = n_tok > 15 && unique_ratio < 0.55 && !is_structured;
    let filler_spoof = n_tok > 25 && unique_ratio > 0.85 && uniq_risk >= 1 && risk_density < 0.06;
    let spoof_filtered = rep_spoof || filler_spoof;

    let risk_score = if spoof_filtered {
        (0.08 * uniq_risk as f64).min(0.25)
    } else {
        (0.28 * uniq_risk as f64 + 0.45 * (risk_density * 4.0).min(1.0)).min(1.0)
    };

    let len_norm = ((n_tok as f64).ln_1p() / 256.0_f64.ln_1p()).min(1.0);
    let mut vec = [
        1.0,
        len_norm,
        if has_math { 1.0 } else { 0.0 },
        if has_rag { 1.0 } else { 0.0 },
        0.0,
        risk_score,
        unique_ratio,
        (tok_ent / 7.0).min(1.0),
        (ch_ent / 5.5).min(1.0),
        ((digits as f64 / n_ch_f) * 3.0).min(1.0),
    ];

    let norm = vec.iter().map(|v| v * v).sum::<f64>().sqrt();
    if norm > 2.0 {
        let s = 2.0 / norm;
        for v in &mut vec {
            *v *= s;
        }
    }

    FeatureProfile10D {
        vector: vec,
        has_math,
        has_rag,
        risk_score,
        spoof_filtered,
        unique_ratio,
        token_count: tokens.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repetition_stuffing_flagged() {
        let p = extract_features_10d(&"payout ".repeat(25));
        assert!(p.spoof_filtered);
        assert!(p.risk_score <= 0.25);
    }
}
