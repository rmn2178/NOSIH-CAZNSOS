//! 320D signed n-gram feature hashing with 2.5x negation boost and polarity/numeric guard.

use std::collections::HashSet;

const NEGATIONS: &[&str] = &[
    "not", "no", "never", "without", "cannot", "can't", "don't", "doesn't", "exempt", "exclude",
];

/// Compute a 320D L2-normalized float32 signed feature-hash embedding.
pub fn embed_320d(prompt: &str) -> [f32; 320] {
    let mut vec = [0.0_f32; 320];
    let lower = prompt.to_lowercase();
    let negs: HashSet<&str> = NEGATIONS.iter().copied().collect();
    let toks: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();
    if toks.is_empty() {
        return vec;
    }
    let mut apply = |feat: &str, weight: f32| {
        let h = blake3::hash(feat.as_bytes());
        let b = h.as_bytes();
        let idx = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize % 320;
        let sign = if (b[4] & 1) == 0 { 1.0_f32 } else { -1.0_f32 };
        vec[idx] += sign * weight;
    };
    for (i, &t) in toks.iter().enumerate() {
        let w = if negs.contains(t) { 2.5 } else { 1.0 };
        apply(t, w);
        if i + 1 < toks.len() {
            let bg = format!("{}_{}", t, toks[i + 1]);
            apply(&bg, if negs.contains(t) { 1.5 } else { 1.0 });
        }
    }
    let norm = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 1e-8 {
        for v in &mut vec {
            *v /= norm;
        }
    }
    vec
}

/// Cosine similarity between two L2-normalized 320D vectors.
pub fn cosine_320d(a: &[f32; 320], b: &[f32; 320]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum::<f32>() as f64
}

/// Guard signature isolating polarity negations and exact numbers.
pub fn guard_signature(prompt: &str) -> String {
    let lower = prompt.to_lowercase();
    let negs: HashSet<&str> = NEGATIONS.iter().copied().collect();
    let mut parts: Vec<String> = lower
        .split_whitespace()
        .filter(|w| negs.contains(*w) || w.chars().any(|c| c.is_ascii_digit()))
        .map(String::from)
        .collect();
    parts.sort();
    blake3::hash(parts.join("|").as_bytes()).to_hex().to_string()
}
