"""RFC 6962 / RFC 9162 Domain-Separated Binary Merkle Transparency Log (MTLog).

Replaces prior orchestrators's O(N) unlocked JSONL hash chain with a concurrency-safe
SQLite WAL binary Merkle tree supporting:
- Domain separation: 0x00 || leaf_bytes for leaves, 0x01 || left || right for internal nodes
- Authenticated Signed Tree Heads (STH) with HMAC-SHA256
- O(log N) Merkle Inclusion Proofs (PATH) & independent verification
- O(log N) Merkle Consistency Proofs (SUBPROOF) & prefix-append-only verification
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .jcs_v3 import jcs_bytes


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
STH_DOMAIN = b"NOSIH-V3-STH\x00"


def hash_leaf(canonical_leaf_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + canonical_leaf_bytes).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    if n <= 1:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


@dataclass(frozen=True)
class SignedTreeHead:
    tree_size: int
    timestamp_utc: float
    root_hash_hex: str
    signature_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tree_size": self.tree_size,
            "timestamp_utc": self.timestamp_utc,
            "root_hash_hex": self.root_hash_hex,
            "signature_hex": self.signature_hex,
        }


class MerkleTransparencyLog:
    """SQLite WAL-backed RFC 6962/9162 Binary Merkle Transparency Log."""

    def __init__(self, db_path: str | Path, sth_signing_key: bytes) -> None:
        if not isinstance(sth_signing_key, (bytes, bytearray)) or len(sth_signing_key) < 32:
            raise ValueError("STH signing key must be at least 32 bytes")
        self.db_path = str(db_path)
        self._sth_key = bytes(sth_signing_key)
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
                    CREATE TABLE IF NOT EXISTS merkle_leaves (
                        leaf_index INTEGER PRIMARY KEY,
                        created_at REAL NOT NULL,
                        payload_jcs BLOB NOT NULL,
                        leaf_hash BLOB NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS merkle_sths (
                        tree_size INTEGER PRIMARY KEY,
                        timestamp_utc REAL NOT NULL,
                        root_hash_hex TEXT NOT NULL,
                        signature_hex TEXT NOT NULL
                    );
                    """
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def _sign_sth(self, tree_size: int, timestamp_utc: float, root_hash_hex: str) -> str:
        body = jcs_bytes({
            "tree_size": tree_size,
            "timestamp_utc": round(timestamp_utc, 6),
            "root_hash_hex": root_hash_hex,
        })
        return hmac.new(self._sth_key, STH_DOMAIN + body, hashlib.sha256).hexdigest()

    def verify_sth_signature(self, sth: SignedTreeHead) -> bool:
        expected = self._sign_sth(sth.tree_size, sth.timestamp_utc, sth.root_hash_hex)
        return hmac.compare_digest(expected, sth.signature_hex)

    def _load_leaf_hashes(self, conn: sqlite3.Connection, upto_size: Optional[int] = None) -> List[bytes]:
        if upto_size is None:
            rows = conn.execute(
                "SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_index ASC;"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT leaf_hash FROM merkle_leaves WHERE leaf_index < ? ORDER BY leaf_index ASC;",
                (upto_size,),
            ).fetchall()
        return [bytes(r[0]) for r in rows]

    @staticmethod
    def _mth(hashes: List[bytes]) -> bytes:
        n = len(hashes)
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return hashes[0]
        k = _largest_power_of_two_less_than(n)
        return hash_children(
            MerkleTransparencyLog._mth(hashes[:k]),
            MerkleTransparencyLog._mth(hashes[k:]),
        )

    def append(self, event: Dict[str, Any]) -> Tuple[int, str, SignedTreeHead]:
        """Atomically append an event and return (leaf_index, leaf_hash_hex, SignedTreeHead)."""
        payload = jcs_bytes(event)
        lhash = hash_leaf(payload)
        now = round(time.time(), 6)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                row = conn.execute("SELECT COUNT(*) FROM merkle_leaves;").fetchone()
                leaf_index = int(row[0])
                conn.execute(
                    "INSERT INTO merkle_leaves (leaf_index, created_at, payload_jcs, leaf_hash) VALUES (?, ?, ?, ?);",
                    (leaf_index, now, payload, lhash),
                )
                all_hashes = self._load_leaf_hashes(conn)
                tree_size = len(all_hashes)
                root = self._mth(all_hashes).hex()
                sig = self._sign_sth(tree_size, now, root)
                conn.execute(
                    "INSERT INTO merkle_sths (tree_size, timestamp_utc, root_hash_hex, signature_hex) VALUES (?, ?, ?, ?);",
                    (tree_size, now, root, sig),
                )
                conn.execute("COMMIT;")
                sth = SignedTreeHead(tree_size=tree_size, timestamp_utc=now, root_hash_hex=root, signature_hex=sig)
                return leaf_index, lhash.hex(), sth
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def size(self) -> int:
        with self._lock:
            conn = self._connect()
            try:
                return int(conn.execute("SELECT COUNT(*) FROM merkle_leaves;").fetchone()[0])
            finally:
                conn.close()

    def get_sth(self, tree_size: Optional[int] = None) -> SignedTreeHead:
        with self._lock:
            conn = self._connect()
            try:
                if tree_size is None:
                    row = conn.execute(
                        "SELECT tree_size, timestamp_utc, root_hash_hex, signature_hex FROM merkle_sths ORDER BY tree_size DESC LIMIT 1;"
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT tree_size, timestamp_utc, root_hash_hex, signature_hex FROM merkle_sths WHERE tree_size = ?;",
                        (tree_size,),
                    ).fetchone()
                if not row:
                    raise KeyError(f"STH not found for tree_size={tree_size}")
                return SignedTreeHead(
                    tree_size=int(row[0]),
                    timestamp_utc=float(row[1]),
                    root_hash_hex=str(row[2]),
                    signature_hex=str(row[3]),
                )
            finally:
                conn.close()

    def get_leaf(self, leaf_index: int) -> Tuple[bytes, str]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT payload_jcs, leaf_hash FROM merkle_leaves WHERE leaf_index = ?;",
                    (leaf_index,),
                ).fetchone()
                if not row:
                    raise IndexError(f"Leaf index {leaf_index} out of range")
                return bytes(row[0]), bytes(row[1]).hex()
            finally:
                conn.close()

    @classmethod
    def _audit_path(cls, m: int, hashes: List[bytes]) -> List[bytes]:
        n = len(hashes)
        if n == 1:
            return []
        k = _largest_power_of_two_less_than(n)
        if m < k:
            return cls._audit_path(m, hashes[:k]) + [cls._mth(hashes[k:])]
        return cls._audit_path(m - k, hashes[k:]) + [cls._mth(hashes[:k])]

    def inclusion_proof(self, leaf_index: int, tree_size: Optional[int] = None) -> List[str]:
        """Generate RFC 6962 O(log N) Merkle inclusion proof for leaf_index at tree_size."""
        with self._lock:
            conn = self._connect()
            try:
                hashes = self._load_leaf_hashes(conn, upto_size=tree_size)
            finally:
                conn.close()
        n = len(hashes)
        if not (0 <= leaf_index < n):
            raise IndexError(f"leaf_index={leaf_index} invalid for tree_size={n}")
        return [h.hex() for h in self._audit_path(leaf_index, hashes)]

    @staticmethod
    def verify_inclusion(
        leaf_payload_jcs: bytes,
        leaf_index: int,
        tree_size: int,
        proof_hex: List[str],
        expected_root_hex: str,
    ) -> bool:
        """Independently verify RFC 6962 inclusion proof in O(log N)."""
        if not (0 <= leaf_index < tree_size):
            return False
        fn = leaf_index
        sn = tree_size - 1
        r = hash_leaf(leaf_payload_jcs)
        for p_hex in proof_hex:
            try:
                p = bytes.fromhex(p_hex)
            except ValueError:
                return False
            if sn == 0:
                return False
            if (fn & 1) == 1 or fn == sn:
                r = hash_children(p, r)
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                r = hash_children(r, p)
            fn >>= 1
            sn >>= 1
        if sn != 0:
            return False
        return hmac.compare_digest(r.hex(), expected_root_hex)

    @classmethod
    def _subproof(cls, m: int, hashes: List[bytes], start_from_old: bool) -> List[bytes]:
        n = len(hashes)
        if m == n:
            return [] if start_from_old else [cls._mth(hashes)]
        k = _largest_power_of_two_less_than(n)
        if m <= k:
            return cls._subproof(m, hashes[:k], start_from_old) + [cls._mth(hashes[k:])]
        return cls._subproof(m - k, hashes[k:], False) + [cls._mth(hashes[:k])]

    def consistency_proof(self, old_size: int, new_size: int) -> List[str]:
        """Generate RFC 6962 O(log N) consistency proof proving old_size is prefix of new_size."""
        if not (0 < old_size <= new_size):
            raise ValueError(f"Require 0 < old_size <= new_size, got {old_size}, {new_size}")
        with self._lock:
            conn = self._connect()
            try:
                hashes = self._load_leaf_hashes(conn, upto_size=new_size)
            finally:
                conn.close()
        if len(hashes) < new_size:
            raise ValueError(f"Tree has only {len(hashes)} leaves, requested {new_size}")
        return [h.hex() for h in self._subproof(old_size, hashes, True)]

    @staticmethod
    def verify_consistency(
        old_size: int,
        new_size: int,
        old_root_hex: str,
        new_root_hex: str,
        proof_hex: List[str],
    ) -> bool:
        """Independently verify RFC 6962 consistency proof in O(log N)."""
        if old_size <= 0 or old_size > new_size:
            return False
        if old_size == new_size:
            return len(proof_hex) == 0 and hmac.compare_digest(old_root_hex, new_root_hex)
        if not proof_hex:
            return False
        try:
            proof = [bytes.fromhex(h) for h in proof_hex]
            old_root = bytes.fromhex(old_root_hex)
            new_root = bytes.fromhex(new_root_hex)
        except ValueError:
            return False

        # RFC 9162 §2.1.4.2 algorithm
        if (old_size & (old_size - 1)) == 0:
            proof = [old_root] + proof
        fn = old_size - 1
        sn = new_size - 1
        while (fn & 1) == 1:
            fn >>= 1
            sn >>= 1
        fr = proof[0]
        sr = proof[0]
        for c in proof[1:]:
            if sn == 0:
                return False
            if (fn & 1) == 1 or fn == sn:
                fr = hash_children(c, fr)
                sr = hash_children(c, sr)
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = hash_children(sr, c)
            fn >>= 1
            sn >>= 1
        return (
            sn == 0
            and hmac.compare_digest(fr, old_root)
            and hmac.compare_digest(sr, new_root)
        )
