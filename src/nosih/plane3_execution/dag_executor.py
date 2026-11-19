"""Capability-Gated Verifiable Async DAG Executor for NOSIH.

Fixes prior orchestrators defects:
- Static pre-execution verification: Kahn acyclicity + CaMeLoT-inspired static IFC check
  (blocks UNTRUSTED_EXTERNAL -> control_sink edges without an explicit gate/sanitizer node)
- Event-driven asyncio ready-queue scheduler (eliminates wave-barrier head-of-line stalls)
- Hard per-node asyncio.wait_for cancellation on BOTH single-node and multi-node topologies (zero zombie threads!)
- Per-node offline SPCCE-Macaroon capability attenuation + Merkle Transparency Log recording
- Supports RECORD, REPLAY, and COUNTERFACTUAL_DIFF deterministic replay modes
"""
from __future__ import annotations

import asyncio
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from ..plane1_security.jcs_v3 import jcs_sha256
from ..plane1_security.merkle_log import MerkleTransparencyLog
from ..plane1_security.postw_v3 import IntegrityLevel, ProvenanceLabel, ProvenanceValue
from ..plane1_security.spcce_v3 import AttenuatedCapability, Caveat, SPCCEMacaroonAuthority
from .replay_engine import DeterministicReplayer, JournalStore, ReplayMode


class StaticIFCError(ValueError):
    """Raised during pre-execution DAG verification when a cycle or illegal IFC edge is detected."""


@dataclass(frozen=True)
class DAGNode:
    node_id: str
    tool_name: str
    dependencies: Tuple[str, ...] = ()
    timeout_seconds: float = 2.0
    is_control_sink: bool = False
    is_approval_gate: bool = False
    output_integrity_hint: IntegrityLevel = IntegrityLevel.DERIVED_DET
    required_max_integrity: IntegrityLevel = IntegrityLevel.UNTRUSTED
    fallback_node_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DAGPlan:
    dag_id: str
    nodes: Tuple[DAGNode, ...]

    def plan_digest(self) -> str:
        canonical = [
            {
                "node_id": n.node_id,
                "tool_name": n.tool_name,
                "dependencies": list(n.dependencies),
                "is_control_sink": n.is_control_sink,
                "is_approval_gate": n.is_approval_gate,
                "output_integrity_hint": int(n.output_integrity_hint),
                "required_max_integrity": int(n.required_max_integrity),
            }
            for n in sorted(self.nodes, key=lambda x: x.node_id)
        ]
        return jcs_sha256({"dag_id": self.dag_id, "nodes": canonical})


NodeHandler = Callable[[DAGNode, Dict[str, ProvenanceValue], AttenuatedCapability], Awaitable[ProvenanceValue]]


class CapabilityGatedDAGExecutor:
    """Event-driven asyncio DAG executor enforcing static IFC, per-node Macaroons, and replay."""

    def __init__(
        self,
        authority: SPCCEMacaroonAuthority,
        merkle_log: MerkleTransparencyLog,
        journal_store: Optional[JournalStore] = None,
    ) -> None:
        self.authority = authority
        self.merkle_log = merkle_log
        self.journal_store = journal_store
        self.replayer = DeterministicReplayer(journal_store) if journal_store else None

    @staticmethod
    def verify_plan_static(plan: DAGPlan) -> List[str]:
        """Static Kahn topological sort + IFC/temporal safety verification."""
        node_map = {n.node_id: n for n in plan.nodes}
        if len(node_map) != len(plan.nodes):
            raise StaticIFCError("Duplicate node_id detected in DAGPlan")

        in_deg: Dict[str, int] = {n.node_id: 0 for n in plan.nodes}
        children: Dict[str, List[str]] = {n.node_id: [] for n in plan.nodes}
        for n in plan.nodes:
            for dep in n.dependencies:
                if dep not in node_map:
                    raise StaticIFCError(f"Unknown dependency '{dep}' referenced by '{n.node_id}'")
                in_deg[n.node_id] += 1
                children[dep].append(n.node_id)

        q: deque[str] = deque(sorted(nid for nid, d in in_deg.items() if d == 0))
        topo: List[str] = []
        while q:
            u = q.popleft()
            topo.append(u)
            for v in sorted(children[u]):
                in_deg[v] -= 1
                if in_deg[v] == 0:
                    q.append(v)

        if len(topo) != len(plan.nodes):
            raise StaticIFCError("Cycle detected in DAGPlan (must be strictly acyclic)")

        # Static abstract interpretation of integrity taint across topological order
        abstract_integrity: Dict[str, IntegrityLevel] = {}
        for nid in topo:
            node = node_map[nid]
            if node.is_approval_gate:
                abstract_integrity[nid] = IntegrityLevel.HUMAN_APPROVAL
                continue
            dep_worst = max((int(abstract_integrity[d]) for d in node.dependencies), default=int(IntegrityLevel.SYSTEM_POLICY))
            if node.is_control_sink and dep_worst > int(node.required_max_integrity):
                raise StaticIFCError(
                    f"Static IFC violation: control sink '{nid}' receives integrity={IntegrityLevel(dep_worst).name} "
                    f"exceeding required {node.required_max_integrity.name}"
                )
            abstract_integrity[nid] = IntegrityLevel(max(dep_worst, int(node.output_integrity_hint)))

        return topo

    async def execute(
        self,
        plan: DAGPlan,
        handlers: Dict[str, NodeHandler],
        root_cap: AttenuatedCapability,
        tenant_id: str,
        session_id: str,
        run_id: str,
        replay_mode: ReplayMode = ReplayMode.RECORD,
        replay_source_run_id: Optional[str] = None,
    ) -> Tuple[Dict[str, ProvenanceValue], Dict[str, Any]]:
        """Execute DAG with event-driven ready queue, hard cancellation, and per-node capabilities."""
        topo = self.verify_plan_static(plan)
        node_map = {n.node_id: n for n in plan.nodes}
        plan_digest = plan.plan_digest()
        t0 = time.perf_counter()

        recorded_map = {}
        if replay_mode in (ReplayMode.REPLAY, ReplayMode.COUNTERFACTUAL_DIFF):
            if self.replayer is None or replay_source_run_id is None:
                raise ValueError("Replay mode requires journal_store and replay_source_run_id")
            recorded_map = self.replayer.replay_node_lookup(replay_source_run_id)

        remaining_deps: Dict[str, Set[str]] = {n.node_id: set(n.dependencies) for n in plan.nodes}
        dependents: Dict[str, List[str]] = {n.node_id: [] for n in plan.nodes}
        for n in plan.nodes:
            for dep in n.dependencies:
                dependents[dep].append(n.node_id)

        results: Dict[str, ProvenanceValue] = {}
        node_timings: Dict[str, float] = {}
        node_statuses: Dict[str, str] = {}
        merkle_leaves: Dict[str, int] = {}

        async def _run_node(node: DAGNode) -> Tuple[str, ProvenanceValue, str, float, int]:
            nt0 = time.perf_counter()
            dep_vals = {d: results[d] for d in node.dependencies}
            combined_label = ProvenanceLabel.one()
            for dv in dep_vals.values():
                combined_label = combined_label.mul(dv.label)

            # Attenuate capability offline for this exact DAG hop
            jti = secrets.token_hex(16)
            node_cap = (
                root_cap
                .attenuate(Caveat("tool_allowlist", {"tools": [node.tool_name]}))
                .attenuate(Caveat("hop_bind", {"dag_id": plan.dag_id, "hop_id": node.node_id}))
                .attenuate(Caveat("schema_pin", {"schema_digest": plan_digest}))
                .attenuate(Caveat("ttl_max", {"expires_at": time.time() + max(5.0, node.timeout_seconds + 5.0)}))
                .attenuate(Caveat("jti_single_use", {"jti": jti}))
            )

            # Verify capability at node execution boundary
            cap_ok, cap_reason = self.authority.verify_and_consume(
                node_cap,
                {
                    "tenant_id": tenant_id,
                    "session_id": session_id,
                    "dag_id": plan.dag_id,
                    "hop_id": node.node_id,
                    "tool_name": node.tool_name,
                    "arguments": node.metadata,
                    "schema_digest": plan_digest,
                },
                require_sink_caveats=True,
            )
            if not cap_ok:
                raise PermissionError(f"Capability check failed on node '{node.node_id}': {cap_reason}")

            input_canonical = {
                "node_id": node.node_id,
                "tool_name": node.tool_name,
                "deps": {k: str(v.value) for k, v in sorted(dep_vals.items())},
                "metadata": node.metadata,
            }

            if replay_mode in (ReplayMode.REPLAY, ReplayMode.COUNTERFACTUAL_DIFF) and node.node_id in recorded_map:
                rec = recorded_map[node.node_id]
                out_raw = self.replayer.verify_replay_step(rec, node.node_id, input_canonical, replay_mode)
                pv = ProvenanceValue(value=out_raw, label=combined_label)
                status = f"replayed:{replay_mode.value}"
            else:
                handler = handlers[node.tool_name]
                try:
                    pv = await asyncio.wait_for(handler(node, dep_vals, node_cap), timeout=node.timeout_seconds)
                    # Propagate algebraic semiring provenance from dependencies
                    pv = ProvenanceValue(value=pv.value, label=combined_label.mul(pv.label))
                    status = "ok"
                except asyncio.TimeoutError:
                    pv = ProvenanceValue(value={"error": "node_timeout", "node_id": node.node_id}, label=combined_label)
                    status = "timeout_cancelled"

            lat_ms = (time.perf_counter() - nt0) * 1000.0
            leaf_idx, _, _ = self.merkle_log.append({
                "event_type": "DAG_NODE_EXECUTED",
                "run_id": run_id,
                "dag_id": plan.dag_id,
                "node_id": node.node_id,
                "tool_name": node.tool_name,
                "status": status,
                "integrity": int(pv.label.integrity),
                "conf_tier": int(pv.label.conf_tier),
                "deriv_hash": pv.label.deriv_hash,
            })

            if replay_mode == ReplayMode.RECORD and self.journal_store is not None:
                self.journal_store.append_event(
                    run_id=run_id,
                    node_id=node.node_id,
                    event_type="DAG_NODE_RESULT",
                    input_obj=input_canonical,
                    output_obj=pv.value,
                    merkle_leaf_idx=leaf_idx,
                )

            return node.node_id, pv, status, lat_ms, leaf_idx

        # Event-driven ready queue: launch any node the instant its dependencies complete!
        active_tasks: Dict[asyncio.Task, str] = {}
        for nid in topo:
            if not remaining_deps[nid]:
                task = asyncio.create_task(_run_node(node_map[nid]))
                active_tasks[task] = nid

        while active_tasks:
            done, _ = await asyncio.wait(active_tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                active_tasks.pop(task)
                nid, pv, status, lat_ms, leaf_idx = task.result()
                results[nid] = pv
                node_statuses[nid] = status
                node_timings[nid] = round(lat_ms, 4)
                merkle_leaves[nid] = leaf_idx

                for child_id in dependents[nid]:
                    remaining_deps[child_id].discard(nid)
                    if not remaining_deps[child_id]:
                        child_task = asyncio.create_task(_run_node(node_map[child_id]))
                        active_tasks[child_task] = child_id

        total_ms = (time.perf_counter() - t0) * 1000.0
        return results, {
            "dag_id": plan.dag_id,
            "plan_digest": plan_digest,
            "topo_order": topo,
            "node_statuses": node_statuses,
            "node_timings_ms": node_timings,
            "merkle_leaves": merkle_leaves,
            "total_wall_ms": round(total_ms, 4),
            "replay_mode": replay_mode.value,
        }
