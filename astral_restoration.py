"""
Astral Plane Restoration Utilities

Deterministic tools for restoring altered astral-plane nodes to a known-good
baseline. This module treats the astral plane as a fictional/simulation graph:
restoration means replacing altered node metadata with trusted baseline data,
quarantining unknown nodes, and producing an audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Set


class AstralNodeStatus(Enum):
    """Restoration status for an astral-plane node."""

    STABLE = "stable"
    ALTERED = "altered"
    RESTORED = "restored"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class AstralNode:
    """A single node in the astral plane simulation graph."""

    node_id: str
    resonance: float = 1.0
    alignment: str = "neutral"
    anchors: Set[str] = field(default_factory=set)
    status: AstralNodeStatus = AstralNodeStatus.STABLE
    metadata: Mapping[str, str] = field(default_factory=dict)

    def normalized(self) -> "AstralNode":
        """Return a safely normalized node suitable for baseline comparison."""
        return AstralNode(
            node_id=self.node_id.strip(),
            resonance=max(0.0, min(1.0, float(self.resonance))),
            alignment=self.alignment.strip().lower() or "neutral",
            anchors={anchor.strip() for anchor in self.anchors if anchor.strip()},
            status=self.status,
            metadata={str(k): str(v) for k, v in self.metadata.items()},
        )


@dataclass
class AstralRestorationReport:
    """Audit output from an astral-plane restoration pass."""

    restored_nodes: List[str] = field(default_factory=list)
    quarantined_nodes: List[str] = field(default_factory=list)
    stable_nodes: List[str] = field(default_factory=list)
    missing_nodes_recreated: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def altered_node_count(self) -> int:
        """Number of altered or missing nodes corrected by the pass."""
        return len(self.restored_nodes) + len(self.missing_nodes_recreated)

    def as_dict(self) -> Dict[str, object]:
        """Serialize this report for logging or JSON export."""
        return {
            "timestamp": self.timestamp,
            "restored_nodes": list(self.restored_nodes),
            "quarantined_nodes": list(self.quarantined_nodes),
            "stable_nodes": list(self.stable_nodes),
            "missing_nodes_recreated": list(self.missing_nodes_recreated),
            "altered_node_count": self.altered_node_count,
        }


class AstralPlaneRestorer:
    """Restore altered astral-plane nodes from trusted baseline nodes."""

    def __init__(self, baseline_nodes: Iterable[AstralNode]):
        self.baseline: Dict[str, AstralNode] = {}
        for node in baseline_nodes:
            normalized = node.normalized()
            if not normalized.node_id:
                raise ValueError("baseline node_id cannot be empty")
            self.baseline[normalized.node_id] = normalized

    def detect_alterations(self, current_nodes: Mapping[str, AstralNode]) -> List[str]:
        """Return baseline node IDs whose current state differs from baseline."""
        altered: List[str] = []
        for node_id, baseline_node in self.baseline.items():
            current_node = current_nodes.get(node_id)
            if current_node is None or current_node.normalized() != baseline_node:
                altered.append(node_id)
        return altered

    def restore(
        self,
        current_nodes: MutableMapping[str, AstralNode],
        *,
        quarantine_unknown: bool = True,
    ) -> AstralRestorationReport:
        """
        Restore the current astral-plane graph in place.

        Known nodes that are missing or altered are replaced with baseline nodes.
        Unknown nodes can be quarantined so they remain visible without being
        treated as trusted parts of the restored plane.
        """
        report = AstralRestorationReport()

        for node_id, baseline_node in self.baseline.items():
            current_node = current_nodes.get(node_id)
            if current_node is None:
                current_nodes[node_id] = baseline_node
                report.missing_nodes_recreated.append(node_id)
                continue

            if current_node.normalized() != baseline_node:
                current_nodes[node_id] = baseline_node
                report.restored_nodes.append(node_id)
            else:
                report.stable_nodes.append(node_id)

        if quarantine_unknown:
            for node_id, node in list(current_nodes.items()):
                if node_id in self.baseline:
                    continue
                current_nodes[node_id] = AstralNode(
                    node_id=node.node_id,
                    resonance=0.0,
                    alignment="quarantined",
                    anchors=set(),
                    status=AstralNodeStatus.QUARANTINED,
                    metadata={"reason": "unknown_node_after_astral_restoration"},
                )
                report.quarantined_nodes.append(node_id)

        return report


def create_default_astral_baseline() -> List[AstralNode]:
    """Create a compact baseline for common astral-plane simulation nodes."""
    return [
        AstralNode("astral_root", resonance=1.0, alignment="neutral", anchors={"prime"}),
        AstralNode("lunar_gate", resonance=0.82, alignment="reflective", anchors={"astral_root"}),
        AstralNode("stellar_archive", resonance=0.91, alignment="observant", anchors={"astral_root"}),
        AstralNode("dream_delta", resonance=0.74, alignment="liminal", anchors={"lunar_gate"}),
    ]
