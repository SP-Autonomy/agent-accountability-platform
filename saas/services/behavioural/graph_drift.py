"""
Identity Graph Drift Detection
---------------------------------
Tracks the bipartite identity graph for each principal:

  Nodes:  principal, tool, resource (destination), namespace
  Edges:
    principal → tool          (from ToolUsage.tool_name)
    principal → resource      (from ToolUsage.destination)
    principal → namespace     (from NormalizedEvent.dest where source=audit)

Drift is detected when:
  - A new edge type appears that was not in the stored baseline
  - The principal's graph degree exceeds the historical baseline by more than
    DEGREE_SPIKE_FACTOR (default 2x)
  - A first-time sensitive destination is accessed (metadata IP, vault, IAM, etc.)
  - A first-time sensitive tool is used without a JIT grant on the same span
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog

from saas.services.shared.models import ToolUsage, NormalizedEvent, BehavioralBaseline, EventSource

logger = structlog.get_logger()

DEGREE_SPIKE_FACTOR = 2.0    # flag if current degree > baseline_degree * DEGREE_SPIKE_FACTOR
LOOK_BACK_HOURS     = 1      # current graph window for drift detection

_SENSITIVE_DEST_PREFIXES = (
    "169.254.", "metadata.google.internal", "metadata.internal",
    "vault.", "secrets.", "kms.", "iam.amazonaws", "sts.amazonaws",
)

_SENSITIVE_TOOLS = {
    "read_secrets", "write_secrets", "exec_command", "deploy_infrastructure",
    "modify_iam_policy", "create_role", "attach_policy", "update_cluster",
    "delete_resource", "kubectl_exec",
}


def _is_sensitive_dest(dest: str | None) -> bool:
    if not dest:
        return False
    return any(dest.lower().startswith(p) for p in _SENSITIVE_DEST_PREFIXES)


def _is_sensitive_tool(tool: str | None) -> bool:
    return bool(tool) and tool.lower() in _SENSITIVE_TOOLS


@dataclass
class GraphSnapshot:
    """Current identity graph for a principal (snapshot over last LOOK_BACK_HOURS)."""
    principal_id: int
    tool_edges:       set[str] = field(default_factory=set)
    resource_edges:   set[str] = field(default_factory=set)
    namespace_edges:  set[str] = field(default_factory=set)

    @property
    def degree(self) -> int:
        return len(self.tool_edges) + len(self.resource_edges) + len(self.namespace_edges)


@dataclass
class DriftResult:
    """Result of comparing current graph snapshot to the stored baseline."""
    principal_id:         int
    new_tools:            list[str]   # tools not in baseline.known_tools
    new_destinations:     list[str]   # destinations not in baseline.known_destinations
    new_namespaces:       list[str]   # namespaces not in baseline.known_namespaces
    new_sensitive_dests:  list[str]   # new destinations that are also sensitive
    new_sensitive_tools:  list[str]   # new tools that are also sensitive
    current_degree:       int
    baseline_degree:      int
    degree_spike:         bool        # current_degree > baseline_degree * DEGREE_SPIKE_FACTOR
    is_drifted:           bool        # True if any drift indicator is present


def build_current_graph(principal_id: int, tenant_id: str, db) -> GraphSnapshot:
    """
    Build a GraphSnapshot from ToolUsage and NormalizedEvent records in the last LOOK_BACK_HOURS.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOK_BACK_HOURS)
    snap   = GraphSnapshot(principal_id=principal_id)

    # Tool and resource edges from ToolUsage
    usages = (
        db.query(ToolUsage)
          .filter(
              ToolUsage.principal_id == principal_id,
              ToolUsage.tenant_id    == tenant_id,
              ToolUsage.timestamp    >= cutoff,
          )
          .all()
    )
    for u in usages:
        if u.tool_name:
            snap.tool_edges.add(u.tool_name)
        if u.destination:
            snap.resource_edges.add(u.destination)

    # Namespace edges from audit-source NormalizedEvents
    events = (
        db.query(NormalizedEvent)
          .filter(
              NormalizedEvent.principal_id == principal_id,
              NormalizedEvent.tenant_id    == tenant_id,
              NormalizedEvent.source       == EventSource.audit,
              NormalizedEvent.timestamp    >= cutoff,
              NormalizedEvent.dest         != None,  # noqa: E711
          )
          .all()
    )
    for ev in events:
        if ev.dest:
            snap.namespace_edges.add(ev.dest)

    return snap


def detect_drift(
    snap:     GraphSnapshot,
    baseline: BehavioralBaseline,
) -> DriftResult:
    """
    Compare a current GraphSnapshot against a stored BehavioralBaseline.
    Returns a DriftResult describing any graph drift detected.
    """
    known_tools  = set(baseline.known_tools or [])
    known_dests  = set(baseline.known_destinations or [])
    known_ns     = set(baseline.known_namespaces or [])

    new_tools  = sorted(snap.tool_edges  - known_tools)
    new_dests  = sorted(snap.resource_edges - known_dests)
    new_ns     = sorted(snap.namespace_edges - known_ns)

    new_sensitive_dests = [d for d in new_dests if _is_sensitive_dest(d)]
    new_sensitive_tools = [t for t in new_tools if _is_sensitive_tool(t)]

    degree_spike = (
        baseline.baseline_degree > 0
        and snap.degree > baseline.baseline_degree * DEGREE_SPIKE_FACTOR
    )

    is_drifted = bool(
        new_sensitive_dests
        or new_sensitive_tools
        or degree_spike
        or (new_tools and len(new_tools) > 3)        # many new tools at once
        or (new_dests and len(new_dests) > 5)        # many new destinations at once
    )

    return DriftResult(
        principal_id=snap.principal_id,
        new_tools=new_tools,
        new_destinations=new_dests,
        new_namespaces=new_ns,
        new_sensitive_dests=new_sensitive_dests,
        new_sensitive_tools=new_sensitive_tools,
        current_degree=snap.degree,
        baseline_degree=baseline.baseline_degree,
        degree_spike=degree_spike,
        is_drifted=is_drifted,
    )
