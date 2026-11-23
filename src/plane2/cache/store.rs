//! Bounded LRU Provenance-Scoped Semantic Cache (`PS-RCSC`).

use crate::plane2::cache::key::ProvenanceScopeKey;
use crate::plane2::cache::search::{cosine_320d, embed_320d, guard_signature};
use crate::plane2::conformal::pid::ConformalPidGate;
use crate::types::integrity::IntegrityRank;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
struct CacheEntry {
    embedding: [f32; 320],
    response: String,
    model: String,
}

/// Cache lookup result.
#[derive(Debug, Clone)]
pub struct CacheLookup {
    /// True if cache hit was admitted.
    pub hit: bool,
    /// Status tag (`exact_hit`, `semantic_hit`, `bypass_untrusted`, `miss`, etc.).
    pub status: String,
    /// Cached assistant response text.
    pub response: Option<String>,
    /// Model that produced the cached answer.
    pub model: Option<String>,
    /// Cosine similarity (`1.0` for exact match).
    pub similarity: f64,
}

/// Provenance-partitioned semantic cache.
pub struct ProvenanceCache {
    max_entries: usize,
    exact: HashMap<(String, String), (String, String)>,
    exact_order: VecDeque<(String, String)>,
    buckets: HashMap<(String, String), VecDeque<CacheEntry>>,
}

impl ProvenanceCache {
    /// Create a bounded cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(32),
            exact: HashMap::new(),
            exact_order: VecDeque::new(),
            buckets: HashMap::new(),
        }
    }

    /// Lookup a prompt under a strict `ProvenanceScopeKey` and Channel-2 Conformal gate.
    pub fn lookup(
        &self,
        prompt: &str,
        scope: &ProvenanceScopeKey,
        risk_score: f64,
        conformal: &ConformalPidGate,
    ) -> CacheLookup {
        if scope.origin_integrity == IntegrityRank::Untrusted {
            return CacheLookup {
                hit: false,
                status: "bypass_untrusted".into(),
                response: None,
                model: None,
                similarity: 0.0,
            };
        }
        if risk_score >= 0.50 {
            return CacheLookup {
                hit: false,
                status: "bypass_high_risk".into(),
                response: None,
                model: None,
                similarity: 0.0,
            };
        }

        let skey = scope.digest_hex();
        let phash = blake3::hash(prompt.trim().as_bytes()).to_hex().to_string();
        if let Some((resp, model)) = self.exact.get(&(skey.clone(), phash)) {
            return CacheLookup {
                hit: true,
                status: "exact_hit".into(),
                response: Some(resp.clone()),
                model: Some(model.clone()),
                similarity: 1.0,
            };
        }

        let gsig = guard_signature(prompt);
        let Some(bucket) = self.buckets.get(&(skey, gsig)) else {
            return CacheLookup {
                hit: false,
                status: "miss".into(),
                response: None,
                model: None,
                similarity: 0.0,
            };
        };

        let q = embed_320d(prompt);
        let mut best_sim = -1.0_f64;
        let mut best: Option<&CacheEntry> = None;
        for entry in bucket {
            let sim = cosine_320d(&entry.embedding, &q);
            if sim > best_sim {
                best_sim = sim;
                best = Some(entry);
            }
        }
        if let Some(e) = best {
            let (ok, _) = conformal.should_admit_cache(best_sim, risk_score);
            if ok {
                return CacheLookup {
                    hit: true,
                    status: "semantic_hit".into(),
                    response: Some(e.response.clone()),
                    model: Some(e.model.clone()),
                    similarity: best_sim,
                };
            }
        }

        CacheLookup {
            hit: false,
            status: "miss".into(),
            response: None,
            model: None,
            similarity: best_sim.max(0.0),
        }
    }

    /// Admit a verified, trusted response into the cache.
    pub fn store(&mut self, prompt: &str, scope: &ProvenanceScopeKey, response: String, model: String) {
        if scope.origin_integrity == IntegrityRank::Untrusted || response.is_empty() {
            return;
        }
        let skey = scope.digest_hex();
        let phash = blake3::hash(prompt.trim().as_bytes()).to_hex().to_string();
        let ek = (skey.clone(), phash);
        if !self.exact.contains_key(&ek) {
            self.exact_order.push_back(ek.clone());
            if self.exact_order.len() > self.max_entries {
                if let Some(old) = self.exact_order.pop_front() {
                    self.exact.remove(&old);
                }
            }
        }
        self.exact.insert(ek, (response.clone(), model.clone()));

        let gsig = guard_signature(prompt);
        let bucket = self.buckets.entry((skey, gsig)).or_default();
        if bucket.len() >= 256 {
            bucket.pop_front();
        }
        bucket.push_back(CacheEntry {
            embedding: embed_320d(prompt),
            response,
            model,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_and_cross_tenant_isolated() {
        let mut cache = ProvenanceCache::new(64);
        let pid = ConformalPidGate::new_default();
        let s1 = ProvenanceScopeKey {
            tenant_id: "t1".into(),
            model_class: "auto".into(),
            policy_epoch: "e1".into(),
            origin_integrity: IntegrityRank::UserDirect,
            schema_digest: "s1".into(),
        };
        let s2 = ProvenanceScopeKey { tenant_id: "t2".into(), ..s1.clone() };
        let su = ProvenanceScopeKey { origin_integrity: IntegrityRank::Untrusted, ..s1.clone() };
        cache.store("hello world", &s1, "hi!".into(), "gpt-4o".into());
        assert!(cache.lookup("hello world", &s1, 0.1, &pid).hit);
        assert!(!cache.lookup("hello world", &s2, 0.1, &pid).hit);
        assert_eq!(cache.lookup("hello world", &su, 0.1, &pid).status, "bypass_untrusted");
    }
}
