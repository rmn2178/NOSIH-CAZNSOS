"""Circuit-Breaking Pluggable LLM Provider Layer for NOSIH.

Fixes prior orchestrators defects:
- 3-state CircuitBreaker (CLOSED -> OPEN -> HALF_OPEN -> CLOSED) with exponential backoff + jitter
- TTL-cached model discovery (fixes permanent negative cache poisoning on transient Ollama outage)
- Priority ProviderFailoverChain (Ollama -> Secondary / CalibratedTrace -> Deterministic Fallback)
- Strict provenance tagging: live providers tagged 'LIVE_LOCAL_LLM', offline benchmark replay tagged 'CALIBRATED_TRACE_SIM'
"""
from __future__ import annotations

import asyncio
import json
import random
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass(frozen=True)
class LLMResponse:
    ok: bool
    text: str
    confidence: float
    latency_ms: float
    cost_norm: float
    provider_name: str
    execution_mode: str  # "LIVE_LOCAL_LLM" | "CALIBRATED_TRACE_SIM" | "PROVIDER_UNAVAILABLE"
    error: Optional[str] = None


class CircuitBreaker:
    """3-state resilience circuit breaker with exponential backoff & full jitter."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_s: float = 10.0,
        base_backoff_s: float = 0.05,
        max_backoff_s: float = 1.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.base_backoff_s = base_backoff_s
        self.max_backoff_s = max_backoff_s
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.opened_at: Optional[float] = None

    def allow_request(self, now: Optional[float] = None) -> bool:
        ts = time.time() if now is None else now
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if self.opened_at is not None and (ts - self.opened_at) >= self.recovery_timeout_s:
                self.state = CircuitState.HALF_OPEN
                return True
            return False
        return True  # HALF_OPEN allows probe

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.opened_at = None
        self.state = CircuitState.CLOSED

    def record_failure(self, now: Optional[float] = None) -> None:
        ts = time.time() if now is None else now
        self.consecutive_failures += 1
        if self.state == CircuitState.HALF_OPEN or self.consecutive_failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.opened_at = ts

    def backoff_delay(self, attempt: int) -> float:
        cap = min(self.max_backoff_s, self.base_backoff_s * (2 ** attempt))
        return random.uniform(0.0, cap)


class BaseLLMProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def generate(self, prompt: str, tier: str = "small", timeout_s: float = 5.0) -> LLMResponse:
        ...


class OllamaProviderV3(BaseLLMProvider):
    """Real local Ollama HTTP provider with TTL-cached discovery (never permanently poisons cache)."""

    name = "ollama_local"

    def __init__(self, base_url: str = "http://localhost:11434", discovery_ttl_s: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.discovery_ttl_s = discovery_ttl_s
        self._cached_models: Optional[List[str]] = None
        self._cache_expires_at: float = 0.0

    def list_installed_models(self, now: Optional[float] = None) -> List[str]:
        ts = time.time() if now is None else now
        if self._cached_models is not None and ts < self._cache_expires_at:
            return list(self._cached_models)
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m["name"] for m in data.get("models", []) if "name" in m]
                self._cached_models = models
                self._cache_expires_at = ts + self.discovery_ttl_s
                return list(models)
        except Exception:
            # Short negative TTL (5s) so transient daemon restarts recover automatically!
            self._cached_models = []
            self._cache_expires_at = ts + min(5.0, self.discovery_ttl_s)
            return []

    async def generate(self, prompt: str, tier: str = "small", timeout_s: float = 5.0) -> LLMResponse:
        t0 = time.perf_counter()
        models = self.list_installed_models()
        if not models:
            return LLMResponse(
                ok=False,
                text="",
                confidence=0.0,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                cost_norm=0.0,
                provider_name=self.name,
                execution_mode="PROVIDER_UNAVAILABLE",
                error="ollama_unreachable_or_no_models",
            )
        model = models[0]
        payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
        try:
            def _post() -> Dict[str, Any]:
                req = urllib.request.Request(
                    f"{self.base_url}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    return json.loads(resp.read().decode("utf-8"))

            res = await asyncio.to_thread(_post)
            lat = (time.perf_counter() - t0) * 1000.0
            return LLMResponse(
                ok=True,
                text=str(res.get("response", "")),
                confidence=0.85,
                latency_ms=lat,
                cost_norm=0.2 if tier == "small" else 0.7,
                provider_name=self.name,
                execution_mode="LIVE_LOCAL_LLM",
            )
        except Exception as exc:
            return LLMResponse(
                ok=False,
                text="",
                confidence=0.0,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                cost_norm=0.0,
                provider_name=self.name,
                execution_mode="PROVIDER_UNAVAILABLE",
                error=str(exc),
            )


class CalibratedTraceProvider(BaseLLMProvider):
    """Explicitly tagged offline trace/fault-injection provider for reproducible benchmarks & chaos tests."""

    def __init__(
        self,
        name: str = "calibrated_trace_sim",
        handler: Optional[Callable[[str, str], LLMResponse]] = None,
    ) -> None:
        self.name = name
        self._handler = handler

    async def generate(self, prompt: str, tier: str = "small", timeout_s: float = 5.0) -> LLMResponse:
        if self._handler is not None:
            return self._handler(prompt, tier)
        return LLMResponse(
            ok=True,
            text=f"[SIM:{tier}] {prompt[:64]}",
            confidence=0.82 if tier == "small" else 0.94,
            latency_ms=25.0 if tier == "small" else 140.0,
            cost_norm=0.15 if tier == "small" else 0.75,
            provider_name=self.name,
            execution_mode="CALIBRATED_TRACE_SIM",
        )


class ProviderFailoverChain:
    """Resilient priority provider chain with per-provider CircuitBreakers."""

    def __init__(self, providers: List[BaseLLMProvider], failure_threshold: int = 3, recovery_timeout_s: float = 10.0) -> None:
        self.providers = providers
        self.breakers: Dict[str, CircuitBreaker] = {
            p.name: CircuitBreaker(failure_threshold=failure_threshold, recovery_timeout_s=recovery_timeout_s)
            for p in providers
        }

    async def generate(self, prompt: str, tier: str = "small", timeout_s: float = 5.0) -> LLMResponse:
        last_err = "no_providers_configured"
        for p in self.providers:
            cb = self.breakers[p.name]
            if not cb.allow_request():
                last_err = f"circuit_open:{p.name}"
                continue
            try:
                resp = await asyncio.wait_for(p.generate(prompt, tier=tier, timeout_s=timeout_s), timeout=timeout_s)
            except asyncio.TimeoutError:
                cb.record_failure()
                last_err = f"timeout:{p.name}"
                continue
            except Exception as exc:
                cb.record_failure()
                last_err = f"exception:{p.name}:{exc}"
                continue

            if resp.ok:
                cb.record_success()
                return resp
            cb.record_failure()
            last_err = resp.error or f"failed:{p.name}"

        return LLMResponse(
            ok=False,
            text="",
            confidence=0.0,
            latency_ms=0.0,
            cost_norm=0.0,
            provider_name="failover_chain_exhausted",
            execution_mode="PROVIDER_UNAVAILABLE",
            error=last_err,
        )
