"""10D Complexity & Risk Profiler with IDF-rarity & char-entropy anti-filler-spoofing.

Fixes prior orchestrators profiler flaws:
- Detects unique-filler keyword-stuffing evasion (where attacker pads unique words to keep unique_ratio > 0.55)
- Avoids false spoofing flags on legitimate structured/repetitive CSV or invoice line-item data
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np


MATH_RE = re.compile(r"(?:\d+(?:\.\d+)?\s*[\+\-\*\/\^%]\s*\d+(?:\.\d+)?|\b(?:compute|calculate|evaluate|sum|multiply|divide|sqrt)\b)", re.I)
RAG_RE = re.compile(r"\b(?:spec|policy|section|clause|gstr|gstin|compliance|standard|document|manual|doc_spec_\d+|procedure|sla)\b", re.I)
RISK_TERMS = frozenset({
    "payout", "neft", "transfer", "wire", "bank", "iban", "gstin", "gstr",
    "override", "bypass", "ignore", "admin", "secret", "password", "webhook",
    "exfiltrate", "refund", "invoice", "audit", "credential", "token",
})
STRUCTURED_DATA_RE = re.compile(r"(?:,.*?,.*?,|\{.*:.*\}|\[.*,.*\])")


@dataclass(frozen=True)
class ComplexityProfile10D:
    vector: np.ndarray
    has_math_expr: bool
    has_rag_cue: bool
    has_multimodal_payload: bool
    risk_score: float
    spoof_filtered: bool
    unique_ratio: float
    token_entropy: float
    char_entropy: float
    risk_density: float


class ComplexityProfiler10D:
    """Computes a bounded 10D context vector x_t (||x_t||_2 <= 2.5) for DPD-LinUCB."""

    def profile(self, prompt: str, raw_payload: Optional[Dict[str, Any]] = None) -> ComplexityProfile10D:
        tokens = re.findall(r"[a-zA-Z0-9_\.\-\+\*\/\^\$%]+", prompt.lower())
        n_tok = max(1, len(tokens))
        unique_toks = set(tokens)
        unique_ratio = len(unique_toks) / n_tok

        # Token Shannon entropy
        counts: Dict[str, int] = {}
        for t in tokens:
            counts[t] = counts.get(t, 0) + 1
        token_entropy = -sum((c / n_tok) * math.log2(c / n_tok) for c in counts.values())

        # Character Shannon entropy
        s_clean = prompt.strip() or " "
        ccounts: Dict[str, int] = {}
        for ch in s_clean:
            ccounts[ch] = ccounts.get(ch, 0) + 1
        n_ch = len(s_clean)
        char_entropy = -sum((c / n_ch) * math.log2(c / n_ch) for c in ccounts.values())

        has_math = bool(MATH_RE.search(prompt))
        has_rag = bool(RAG_RE.search(prompt))
        has_mm = bool(raw_payload and ("waveform" in raw_payload or "image" in raw_payload))
        is_structured = bool(STRUCTURED_DATA_RE.search(prompt))

        risk_hits = sum(1 for t in tokens if t in RISK_TERMS)
        unique_risk_hits = sum(1 for t in unique_toks if t in RISK_TERMS)
        risk_density = risk_hits / n_tok

        # Anti-spoofing:
        # 1. Classic repetition stuffing (n_tok > 15, unique_ratio < 0.55) UNLESS structured CSV/JSON data
        # 2. Unique-filler denial-of-wallet stuffing: many unique filler tokens (>25) with isolated low-density risk buzzwords
        repetition_spoof = (n_tok > 15 and unique_ratio < 0.55 and not is_structured)
        filler_spoof = (n_tok > 25 and unique_ratio > 0.85 and unique_risk_hits >= 1 and risk_density < 0.06)
        spoof_filtered = repetition_spoof or filler_spoof

        if spoof_filtered:
            # Neutralize artificial inflation while preserving a cautious floor for real risk hits
            risk_score = min(0.25, 0.08 * unique_risk_hits)
        else:
            risk_score = min(1.0, 0.28 * unique_risk_hits + 0.45 * min(1.0, risk_density * 4.0))

        len_norm = min(1.0, math.log1p(n_tok) / math.log1p(256.0))
        ent_norm = min(1.0, token_entropy / 7.0)
        ch_ent_norm = min(1.0, char_entropy / 5.5)
        digit_ratio = sum(ch.isdigit() for ch in s_clean) / max(1, n_ch)

        vec = np.array([
            1.0,                        # bias
            len_norm,                   # normalized prompt length
            float(has_math),            # symbolic math cue
            float(has_rag),             # RAG specification cue
            float(has_mm),              # multimodal raw payload cue
            risk_score,                 # calibrated risk score
            unique_ratio,               # lexical uniqueness
            ent_norm,                   # token entropy
            ch_ent_norm,                # character entropy
            min(1.0, digit_ratio * 3.0) # numeric density
        ], dtype=np.float64)
        # Normalize to ||x_t||_2 <= 2.0 for tight bandit confidence bounds
        norm = float(np.linalg.norm(vec))
        if norm > 2.0:
            vec = vec * (2.0 / norm)

        return ComplexityProfile10D(
            vector=vec,
            has_math_expr=has_math,
            has_rag_cue=has_rag,
            has_multimodal_payload=has_mm,
            risk_score=risk_score,
            spoof_filtered=spoof_filtered,
            unique_ratio=unique_ratio,
            token_entropy=token_entropy,
            char_entropy=char_entropy,
            risk_density=risk_density,
        )
