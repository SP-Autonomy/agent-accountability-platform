"""
Rule: shadow_tool_route
-------------------------
Detects two classes of shadow tool access:

1. eBPF: Direct access to the tools service port (9000) from a non-orchestrator pod.
   The Cilium network policy should only allow the orchestrator pod to reach the
   tools service. Any other source reaching port 9000 is a shadow route.
   - action=blocked: Cilium prevented it → PREVENTED
   - action=observed: it got through (misconfigured policy) → DETECTED

2. OTel: A tool call span carries the "shadow_tool" or "supply_chain_risk" risk
   flag, indicating the agent called an unregistered or attacker-controlled
   endpoint (supply chain compromise, shadow tool injection).
"""

import json
from typing import Optional

from saas.services.shared.models import (
    NormalizedEvent, Finding, Severity, FindingStatus, EventSource,
)

SCENARIO_ID = "shadow_tool_route"

TOOLS_PORT = 9000
ORCHESTRATOR_KEYWORD = "orchestrator"

_SHADOW_FLAGS = {"shadow_tool", "supply_chain_risk", "unregistered_endpoint"}


def _has_shadow_flag(ev: NormalizedEvent) -> bool:
    attrs = ev.payload.get("attributes", {})
    raw = attrs.get("aiaap.risk.flags", "")
    if not raw:
        return False
    try:
        flags = set(json.loads(raw))
    except (json.JSONDecodeError, TypeError):
        flags = {raw}
    return bool(flags & _SHADOW_FLAGS)


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    ebpf_hits = []
    otel_hits = []

    for ev in events:
        if ev.source == EventSource.ebpf:
            dest_port = int(ev.payload.get("dest_port", 0) or 0)
            pod_name  = ev.payload.get("pod_name", "")
            if dest_port == TOOLS_PORT and ORCHESTRATOR_KEYWORD not in pod_name.lower():
                ebpf_hits.append(ev)

        elif ev.source == EventSource.otel and _has_shadow_flag(ev):
            otel_hits.append(ev)

    if not ebpf_hits and not otel_hits:
        return None

    tenant_id = events[0].tenant_id

    if ebpf_hits:
        first  = ebpf_hits[0]
        action = first.payload.get("action", "observed")
        status = FindingStatus.prevented if action == "blocked" else FindingStatus.detected
        pod    = first.payload.get("pod_name", "unknown")
        title  = f"Shadow Tool Route: Direct access to tools service from {pod}"
        evidence_ids = [ev.id for ev in ebpf_hits]
    else:
        # OTel-only shadow tool detection
        first    = otel_hits[0]
        dest     = first.dest or first.payload.get("attributes", {}).get("aiaap.tool.destination_host", "unknown")
        tool     = first.tool_name or "unknown"
        status   = FindingStatus.detected
        title    = f"Supply Chain / Shadow Tool: '{tool}' called unknown endpoint '{dest}'"
        evidence_ids = [ev.id for ev in otel_hits]

    return Finding(
        tenant_id=tenant_id,
        title=title,
        severity=Severity.high,
        status=status,
        evidence_refs=evidence_ids,
        scenario_id=SCENARIO_ID,
    )
