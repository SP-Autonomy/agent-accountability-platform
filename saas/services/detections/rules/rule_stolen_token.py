"""
Rule: stolen_token_usage
--------------------------
Detects cross-namespace service account token usage. Fires when an audit event
shows a request from a service account that doesn't belong to the request's namespace.

Heuristic:
  username = system:serviceaccount:<sa_namespace>:<sa_name>
  objectRef.namespace = <request_namespace>

  If sa_namespace != request_namespace and verb is sensitive → flag it.

Status: DETECTED (cannot be prevented without additional network/audit enforcement).
"""

from typing import Optional

from saas.services.shared.models import (
    NormalizedEvent, Finding, Severity, FindingStatus, EventSource,
)

SCENARIO_ID = "stolen_token_usage"

_SENSITIVE_VERBS = {"get", "list", "create", "update", "patch", "delete"}
_SA_PREFIX = "system:serviceaccount:"


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    hits = []

    for ev in events:
        if ev.source != EventSource.audit:
            continue

        user      = ev.payload.get("user", "")
        verb      = ev.payload.get("verb", "")
        req_ns    = ev.payload.get("namespace", "")

        if not user.startswith(_SA_PREFIX):
            continue
        if verb not in _SENSITIVE_VERBS:
            continue

        # Parse SA namespace from username
        # Format: system:serviceaccount:<namespace>:<name>
        parts = user[len(_SA_PREFIX):].split(":", 1)
        if len(parts) != 2:
            continue
        sa_namespace = parts[0]

        # Cross-namespace usage: SA is from one namespace, acting in another
        if req_ns and sa_namespace and sa_namespace != req_ns:
            hits.append(ev)

    if not hits:
        return None

    first = hits[0]
    user  = first.payload.get("user", "unknown")
    tenant_id = events[0].tenant_id

    return Finding(
        tenant_id=tenant_id,
        title=f"Stolen Token: Cross-namespace SA usage by {user}",
        severity=Severity.high,
        status=FindingStatus.detected,
        evidence_refs=[ev.id for ev in hits],
        scenario_id=SCENARIO_ID,
    )
