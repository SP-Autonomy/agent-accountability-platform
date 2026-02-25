"""
Rule: confused_deputy
-----------------------
Detects identity mismatch within a single OTel trace - two patterns:

Pattern A (K8s service account mismatch):
  - tool_call_requested span has aiaap.agent.id = "low-priv-agent"
  - tool_call_executed span has k8s.serviceaccount.name = "high-priv-sa"
  This indicates a low-privilege identity induced a high-privilege downstream action.

Pattern B (Cross-agent delegation - multi-agent hijack):
  - Within the same trace, different spans carry different aiaap.agent.id values.
  - The executing agent (worker) was never directly authorised by the user;
    the orchestrator was, and it delegated without explicit user consent.

Status: DETECTED - both spans must be in the same trace group.
"""

from typing import Optional

from saas.services.shared.models import (
    NormalizedEvent, Finding, Severity, FindingStatus, EventSource,
)

SCENARIO_ID = "confused_deputy"

_SPAN_REQUESTED = "tool_call_requested"
_SPAN_EXECUTED  = "tool_call_executed"

# Known high-privilege service accounts (expand as needed)
_HIGH_PRIV_SA = {"admin", "cluster-admin", "high-priv-sa", "privileged-sa"}


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    # Group by trace_id to find matching requested+executed pairs
    by_trace: dict[str, list] = {}
    for ev in events:
        if ev.trace_id:
            by_trace.setdefault(ev.trace_id, []).append(ev)

    hits = []
    pattern = "unknown"

    for trace_id, trace_events in by_trace.items():
        otel_events   = [e for e in trace_events if e.source == EventSource.otel]
        req_spans     = [e for e in otel_events if e.event_type == _SPAN_REQUESTED]
        exec_spans    = [e for e in otel_events if e.event_type == _SPAN_EXECUTED]

        # --- Pattern A: service-account mismatch ---
        for req in req_spans:
            req_attrs = req.payload.get("attributes", {})
            req_agent = req_attrs.get("aiaap.agent.id", "")

            for exe in exec_spans:
                exe_attrs = exe.payload.get("attributes", {})
                exe_sa = (
                    exe_attrs.get("k8s.serviceaccount.name", "")
                    or exe_attrs.get("aiaap.k8s.service_account", "")
                )

                if req_agent and exe_sa and req_agent != exe_sa:
                    if exe_sa in _HIGH_PRIV_SA or req_agent not in _HIGH_PRIV_SA:
                        hits.extend([req, exe])
                        pattern = "sa_mismatch"

        if hits:
            break

        # --- Pattern B: aiaap.agent.id mismatch within the same trace ---
        # Collect all distinct agent IDs seen across all spans in this trace
        agent_ids = set()
        for ev in otel_events:
            aid = ev.payload.get("attributes", {}).get("aiaap.agent.id", "")
            if aid:
                agent_ids.add(aid)

        if len(agent_ids) > 1:
            # Multiple distinct agents in the same trace - cross-agent delegation
            # Flag the exec spans that have a different agent ID from req spans
            req_agent_ids  = {
                e.payload.get("attributes", {}).get("aiaap.agent.id", "")
                for e in req_spans
            } - {""}
            exec_agent_ids = {
                e.payload.get("attributes", {}).get("aiaap.agent.id", "")
                for e in exec_spans
            } - {""}

            if req_agent_ids and exec_agent_ids and req_agent_ids != exec_agent_ids:
                hits.extend(req_spans + exec_spans)
                pattern = "cross_agent_delegation"
                break

    if not hits:
        return None

    # Deduplicate evidence refs
    evidence_ids = list(dict.fromkeys(ev.id for ev in hits))
    tenant_id    = events[0].tenant_id

    if pattern == "sa_mismatch":
        first_req = next((e for e in hits if e.event_type == _SPAN_REQUESTED), hits[0])
        req_attrs = first_req.payload.get("attributes", {})
        req_agent = req_attrs.get("aiaap.agent.id", "unknown")

        first_exe = next((e for e in hits if e.event_type == _SPAN_EXECUTED), hits[-1])
        exe_attrs = first_exe.payload.get("attributes", {})
        exe_sa    = exe_attrs.get("k8s.serviceaccount.name",
                                  exe_attrs.get("aiaap.k8s.service_account", "unknown"))
        title = f"Confused Deputy: '{req_agent}' induced privileged action by '{exe_sa}'"
    else:
        # cross_agent_delegation
        agents = list({
            e.payload.get("attributes", {}).get("aiaap.agent.id", "")
            for e in hits
        } - {""})
        title = f"Cross-Agent Delegation: Agents {agents} in same trace without authorisation"

    return Finding(
        tenant_id=tenant_id,
        title=title,
        severity=Severity.high,
        status=FindingStatus.detected,
        evidence_refs=evidence_ids,
        scenario_id=SCENARIO_ID,
    )
