//! Pre-persistence secret redaction replacing known API key patterns with `<REDACTED:sha256-prefix>`.

use sha2::{Digest, Sha256};

const KEY_PREFIXES: &[&str] = &["sk-ant-", "sk-proj-", "sk-nosih-", "sk-", "AIza", "gsk_", "adm-"];

/// Redact any known secret or Bearer token pattern before logging, SQLite persistence, or export.
pub fn redact_secrets(input: &str) -> String {
    let mut out_words = Vec::new();
    let mut skip_next_bearer = false;
    for word in input.split_whitespace() {
        if skip_next_bearer {
            skip_next_bearer = false;
            out_words.push(redacted_tag(word));
            continue;
        }
        if word.eq_ignore_ascii_case("bearer") {
            out_words.push("Bearer".to_string());
            skip_next_bearer = true;
            continue;
        }
        let cleaned = word.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '}'));
        if KEY_PREFIXES.iter().any(|p| cleaned.starts_with(p)) && cleaned.len() >= 10 {
            out_words.push(redacted_tag(cleaned));
        } else {
            out_words.push(word.to_string());
        }
    }
    out_words.join(" ")
}

fn redacted_tag(secret: &str) -> String {
    let digest = hex::encode(Sha256::digest(secret.as_bytes()));
    let prefix: String = digest.chars().take(8).collect();
    format!("<REDACTED:{prefix}>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_all_provider_key_prefixes() {
        let s = "leak sk-1234567890abcdef and sk-ant-9999999999 and AIzaSyD1234567890 and gsk_abcdefgh1234";
        let r = redact_secrets(s);
        assert!(!r.contains("sk-1234"));
        assert!(!r.contains("sk-ant-"));
        assert!(!r.contains("AIza"));
        assert!(!r.contains("gsk_"));
        assert!(r.contains("<REDACTED:"));
    }
}
