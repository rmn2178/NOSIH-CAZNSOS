"""Temporal-Style Event-Sourced JournalStore & Deterministic Replay Engine.

Supports three execution modes:
- RECORD: executes live nodes, logs canonical input JCS hash + outputs + Merkle leaf index
- REPLAY: injects recorded boundary outputs and asserts bit-for-bit input/topology identity
- COUNTERFACTUAL_DIFF: replays recorded tool/LLM outputs under a modified policy/router to measure deltas offline
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..plane1_security.jcs_v3 import jcs_sha256


class ReplayMode(str, Enum):
    RECORD = "RECORD"
    REPLAY = "REPLAY"
    COUNTERFACTUAL_DIFF = "COUNTERFACTUAL_DIFF"


class NonDeterminismError(RuntimeError):
    """Raised during REPLAY when orchestration diverges from recorded event history."""


@dataclass(frozen=True)
class JournalEvent:
    run_id: str
    seq_no: int
    node_id: str
    event_type: str
    input_jcs_sha256: str
    output_json: str
    merkle_leaf_idx: int
    created_at: float


class JournalStore:
    """SQLite WAL event-sourced journal for durable execution and deterministic replay."""

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
                    CREATE TABLE IF NOT EXISTS replay_journal (
                        run_id TEXT NOT NULL,
                        seq_no INTEGER NOT NULL,
                        node_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        input_jcs_sha256 TEXT NOT NULL,
                        output_json TEXT NOT NULL,
                        merkle_leaf_idx INTEGER NOT NULL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY (run_id, seq_no)
                    );
                    """
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def append_event(
        self,
        run_id: str,
        node_id: str,
        event_type: str,
        input_obj: Any,
        output_obj: Any,
        merkle_leaf_idx: int = -1,
    ) -> JournalEvent:
        in_hash = jcs_sha256(input_obj)
        out_json = json.dumps(output_obj, sort_keys=True, default=str)
        now = round(time.time(), 6)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                row = conn.execute(
                    "SELECT COALESCE(MAX(seq_no), -1) + 1 FROM replay_journal WHERE run_id = ?;",
                    (run_id,),
                ).fetchone()
                seq_no = int(row[0])
                conn.execute(
                    """
                    INSERT INTO replay_journal
                    (run_id, seq_no, node_id, event_type, input_jcs_sha256, output_json, merkle_leaf_idx, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (run_id, seq_no, node_id, event_type, in_hash, out_json, merkle_leaf_idx, now),
                )
                conn.execute("COMMIT;")
                return JournalEvent(run_id, seq_no, node_id, event_type, in_hash, out_json, merkle_leaf_idx, now)
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def load_run(self, run_id: str) -> List[JournalEvent]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT run_id, seq_no, node_id, event_type, input_jcs_sha256, output_json, merkle_leaf_idx, created_at
                    FROM replay_journal WHERE run_id = ? ORDER BY seq_no ASC;
                    """,
                    (run_id,),
                ).fetchall()
                return [JournalEvent(*r) for r in rows]
            finally:
                conn.close()


class DeterministicReplayer:
    """Replays recorded runs verifying bit-for-bit identity or running counterfactual policy diffs."""

    def __init__(self, store: JournalStore) -> None:
        self.store = store

    def replay_node_lookup(self, run_id: str) -> Dict[str, JournalEvent]:
        events = self.store.load_run(run_id)
        return {e.node_id: e for e in events}

    def verify_replay_step(self, recorded: JournalEvent, live_node_id: str, live_input_obj: Any, mode: ReplayMode) -> Any:
        live_hash = jcs_sha256(live_input_obj)
        if mode == ReplayMode.REPLAY:
            if recorded.node_id != live_node_id or recorded.input_jcs_sha256 != live_hash:
                raise NonDeterminismError(
                    f"Replay divergence at node={live_node_id}: expected hash={recorded.input_jcs_sha256}, got={live_hash}"
                )
        return json.loads(recorded.output_json)
