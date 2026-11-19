"""SPCCE-Macaroon: DAG-Bound Offline-Attenuable Cryptographic Capability Chains.

Closes prior orchestrators defects F-05, F-12, F-13, F-14:
- Strict per-key_id 256-bit key provider with zero silent fallback to a default master key
- HKDF-SHA256 (RFC 5869) per-(tenant, session) domain-separated key derivation
- Macaroon chained-HMAC offline monotonic attenuation across DAG hops
- Exact Decimal evaluation for financial caveats (arg_max_decimal)
- Atomic SQLite WAL JTI replay protection with TTL pruning (supports concurrent out-of-order DAG branches)
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .jcs_v3 import jcs_bytes


ROOT_DOMAIN = b"NOSIH-V3-ROOT\x00"
CAVEAT_DOMAIN = b"NOSIH-V3-CAV\x00"
HKDF_INFO = b"NOSIH-V3-CAP-ROOT"


class MissingSecretError(RuntimeError):
    """Fail-closed error when a required cryptographic key is absent or weak."""


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 in pure Python stdlib."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


class StrictSecretProvider:
    """Fail-closed per-key_id secret store enforcing >= 32-byte keys with zero fallback."""

    def __init__(self, keys: Dict[str, bytes]) -> None:
        if not keys:
            raise MissingSecretError("At least one 256-bit signing key is required")
        self._keys: Dict[str, bytes] = {}
        for kid, kbytes in keys.items():
            if not isinstance(kbytes, (bytes, bytearray)) or len(kbytes) < 32:
                raise MissingSecretError(f"Key '{kid}' must be >= 32 raw bytes")
            self._keys[str(kid)] = bytes(kbytes)

    @classmethod
    def ephemeral(cls, key_id: str = "k1") -> "StrictSecretProvider":
        return cls({key_id: secrets.token_bytes(32)})

    def get_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise MissingSecretError(f"unknown_key_id:{key_id}")
        return self._keys[key_id]


@dataclass(frozen=True)
class Caveat:
    kind: str
    params: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "params": self.params}


@dataclass(frozen=True)
class AttenuatedCapability:
    cap_id: str
    key_id: str
    tenant_id: str
    session_id: str
    dag_id: str
    dag_plan_digest: str
    issued_at: float
    max_expires_at: float
    caveats: Tuple[Caveat, ...]
    tag_hex: str

    def header_dict(self) -> Dict[str, Any]:
        return {
            "cap_id": self.cap_id,
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "dag_id": self.dag_id,
            "dag_plan_digest": self.dag_plan_digest,
            "issued_at": round(self.issued_at, 6),
            "max_expires_at": round(self.max_expires_at, 6),
        }

    def attenuate(self, caveat: Caveat) -> "AttenuatedCapability":
        """Offline monotonic attenuation without access to the root secret."""
        prev_tag = bytes.fromhex(self.tag_hex)
        next_tag = hmac.new(
            prev_tag, CAVEAT_DOMAIN + jcs_bytes(caveat.to_dict()), hashlib.sha256
        ).hexdigest()
        return AttenuatedCapability(
            cap_id=self.cap_id,
            key_id=self.key_id,
            tenant_id=self.tenant_id,
            session_id=self.session_id,
            dag_id=self.dag_id,
            dag_plan_digest=self.dag_plan_digest,
            issued_at=self.issued_at,
            max_expires_at=self.max_expires_at,
            caveats=self.caveats + (caveat,),
            tag_hex=next_tag,
        )


class AtomicJTIReplayStore:
    """SQLite WAL single-use JTI store with TTL pruning (supports parallel DAG execution)."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=FULL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consumed_jtis (
                        jti TEXT PRIMARY KEY,
                        dag_id TEXT NOT NULL,
                        hop_id TEXT NOT NULL,
                        consumed_at REAL NOT NULL,
                        expires_at REAL NOT NULL
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_jti_exp ON consumed_jtis(expires_at);")
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def consume_jti(self, jti: str, dag_id: str, hop_id: str, expires_at: float, now: Optional[float] = None) -> bool:
        """Atomically consume JTI; returns True iff this is the first consumption."""
        ts = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                try:
                    conn.execute(
                        "INSERT INTO consumed_jtis (jti, dag_id, hop_id, consumed_at, expires_at) VALUES (?, ?, ?, ?, ?);",
                        (jti, dag_id, hop_id, ts, expires_at),
                    )
                    conn.execute("COMMIT;")
                    return True
                except sqlite3.IntegrityError:
                    conn.execute("ROLLBACK;")
                    return False
            finally:
                conn.close()

    def prune_expired(self, now: Optional[float] = None, grace_seconds: float = 60.0) -> int:
        ts = time.time() if now is None else now
        cutoff = ts - grace_seconds
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                cur = conn.execute("DELETE FROM consumed_jtis WHERE expires_at < ?;", (cutoff,))
                deleted = cur.rowcount
                conn.execute("COMMIT;")
                return deleted
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def count(self) -> int:
        with self._lock:
            conn = self._connect()
            try:
                return int(conn.execute("SELECT COUNT(*) FROM consumed_jtis;").fetchone()[0])
            finally:
                conn.close()


class SPCCEMacaroonAuthority:
    """Mints root capabilities and independently verifies + consumes attenuated chains."""

    REQUIRED_SINK_CAVEATS = frozenset({"jti_single_use", "schema_pin", "hop_bind", "ttl_max"})

    def __init__(self, secret_provider: StrictSecretProvider, replay_store: AtomicJTIReplayStore) -> None:
        self.secrets = secret_provider
        self.replay_store = replay_store

    def _derive_session_key(self, key_id: str, tenant_id: str, session_id: str) -> bytes:
        root_key = self.secrets.get_key(key_id)
        salt = f"{tenant_id}:{session_id}".encode("utf-8")
        return hkdf_sha256(root_key, salt, HKDF_INFO, 32)

    def mint_root(
        self,
        key_id: str,
        tenant_id: str,
        session_id: str,
        dag_id: str,
        dag_plan_digest: str,
        ttl_seconds: float = 300.0,
        now: Optional[float] = None,
    ) -> AttenuatedCapability:
        ts = round(time.time() if now is None else now, 6)
        exp = round(ts + ttl_seconds, 6)
        cap_id = secrets.token_hex(16)
        k_su = self._derive_session_key(key_id, tenant_id, session_id)
        header = {
            "cap_id": cap_id,
            "key_id": key_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "dag_id": dag_id,
            "dag_plan_digest": dag_plan_digest,
            "issued_at": ts,
            "max_expires_at": exp,
        }
        sigma0 = hmac.new(k_su, ROOT_DOMAIN + jcs_bytes(header), hashlib.sha256).hexdigest()
        return AttenuatedCapability(
            cap_id=cap_id,
            key_id=key_id,
            tenant_id=tenant_id,
            session_id=session_id,
            dag_id=dag_id,
            dag_plan_digest=dag_plan_digest,
            issued_at=ts,
            max_expires_at=exp,
            caveats=(),
            tag_hex=sigma0,
        )

    @staticmethod
    def _eval_caveat(cav: Caveat, ctx: Dict[str, Any], now: float) -> Tuple[bool, str]:
        k = cav.kind
        p = cav.params
        if k == "tool_allowlist":
            allowed = set(p.get("tools", []))
            if ctx.get("tool_name") not in allowed:
                return False, "caveat_violation:tool_allowlist"
            return True, "ok"
        if k == "arg_eq":
            field_name = p["field"]
            if ctx.get("arguments", {}).get(field_name) != p["value"]:
                return False, f"caveat_violation:arg_eq:{field_name}"
            return True, "ok"
        if k == "arg_max_decimal":
            field_name = p["field"]
            raw_val = ctx.get("arguments", {}).get(field_name)
            if raw_val is None or isinstance(raw_val, bool):
                return False, f"caveat_violation:arg_max_decimal_type:{field_name}"
            try:
                val_dec = Decimal(str(raw_val))
                max_dec = Decimal(str(p["max_value"]))
            except InvalidOperation:
                return False, f"caveat_violation:arg_max_decimal_parse:{field_name}"
            if val_dec <= Decimal("0") or val_dec > max_dec:
                return False, f"caveat_violation:arg_max_decimal:{field_name}"
            return True, "ok"
        if k == "hop_bind":
            if ctx.get("dag_id") != p.get("dag_id") or ctx.get("hop_id") != p.get("hop_id"):
                return False, "hop_bind_mismatch"
            return True, "ok"
        if k == "schema_pin":
            if ctx.get("schema_digest") != p.get("schema_digest"):
                return False, "schema_pin_mismatch"
            return True, "ok"
        if k == "witness_pin":
            if ctx.get("witness_digest") != p.get("witness_digest"):
                return False, "witness_pin_mismatch"
            return True, "ok"
        if k == "ttl_max":
            if now > float(p["expires_at"]):
                return False, "capability_expired"
            return True, "ok"
        if k == "jti_single_use":
            jti = p.get("jti")
            if not isinstance(jti, str) or len(jti) < 16:
                return False, "invalid_jti"
            return True, "ok"
        return False, f"unknown_caveat_kind:{k}"

    def verify_and_consume(
        self,
        cap: AttenuatedCapability,
        ctx: Dict[str, Any],
        require_sink_caveats: bool = True,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        ts = time.time() if now is None else now
        # 1. Session, tenant, DAG binding
        if cap.tenant_id != ctx.get("tenant_id"):
            return False, "tenant_mismatch"
        if cap.session_id != ctx.get("session_id"):
            return False, "session_mismatch"
        if cap.dag_id != ctx.get("dag_id"):
            return False, "dag_mismatch"
        if ts > cap.max_expires_at:
            return False, "capability_root_expired"

        # 2. Recompute chained HMAC from strict key_id (fail-closed)
        try:
            k_su = self._derive_session_key(cap.key_id, cap.tenant_id, cap.session_id)
        except MissingSecretError as exc:
            return False, str(exc)

        tag = hmac.new(k_su, ROOT_DOMAIN + jcs_bytes(cap.header_dict()), hashlib.sha256).digest()
        for cav in cap.caveats:
            tag = hmac.new(tag, CAVEAT_DOMAIN + jcs_bytes(cav.to_dict()), hashlib.sha256).digest()
        if not hmac.compare_digest(tag.hex(), cap.tag_hex):
            return False, "invalid_capability_mac"

        # 3. Required sink caveats
        present_kinds = {c.kind for c in cap.caveats}
        if require_sink_caveats and not self.REQUIRED_SINK_CAVEATS.issubset(present_kinds):
            missing = sorted(self.REQUIRED_SINK_CAVEATS - present_kinds)
            return False, f"missing_required_caveats:{','.join(missing)}"

        # 4. Evaluate conjunction of all caveats
        jtis: List[str] = []
        min_exp = cap.max_expires_at
        for cav in cap.caveats:
            ok, reason = self._eval_caveat(cav, ctx, ts)
            if not ok:
                return False, reason
            if cav.kind == "jti_single_use":
                jtis.append(str(cav.params["jti"]))
            elif cav.kind == "ttl_max":
                min_exp = min(min_exp, float(cav.params["expires_at"]))

        # 5. Atomically consume single-use JTIs
        hop_id = str(ctx.get("hop_id", "root"))
        for jti in jtis:
            if not self.replay_store.consume_jti(jti, cap.dag_id, hop_id, min_exp, now=ts):
                return False, "replay_duplicate_jti"

        return True, "ok"
