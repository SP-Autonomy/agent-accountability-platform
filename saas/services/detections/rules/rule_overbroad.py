"""
Rule: overbroad_permissions
-----------------------------
Detects tool calls that indicate privileged access without proper authorisation:
  - "privileged_action" flag with no active JIT grant for the calling principal
  - "jit_scope_exceeded" flag: action outside the granted JIT scope (always flagged)
  - "credential_access" flag: direct credential/secret access without authorisation

Uses direct DB query instead of HTTP call to identity service - avoids blocking
the correlation loop on network latency or identity service unavailability.

Status: DETECTED (recommendation: create a properly-scoped JIT grant).
"""

import json
from datetime import datetime, timezone
from typing import Optional

from saas.services.shared.models import (
    NormalizedEvent, Finding, Severity, FindingStatus, EventSource, JitGrant,
)

SCENARIO_ID = "overbroad_permissions"

# Risk flags that always indicate an overbroad/unauthorised action
_ALWAYS_FLAG = {"jit_scope_exceeded"}

# Risk flags that require no active JIT grant to be flagged
_REQUIRES_NO_GRANT = {"privileged_action", "credential_access"}


def _has_active_jit_grant(principal_id: int, db) -> bool:
    """Check if the principal has any active (non-revoked, non-expired) JIT grant."""
    now = datetime.now(timezone.utc)
    count = (
        db.query(JitGrant)
          .filter(
              JitGrant.principal_id == principal_id,
              JitGrant.revoked == False,  # noqa: E712
              JitGrant.expires_at > now,
          )
          .count()
    )
    return count > 0


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    hits = []

    for ev in events:
        if ev.source != EventSource.otel:
            continue

        attrs = ev.payload.get("attributes", {})
        risk_flags_raw = attrs.get("aiaap.risk.flags", "")
        if not risk_flags_raw:
            continue

        try:
            risk_flags = set(json.loads(risk_flags_raw))
        except (json.JSONDecodeError, TypeError):
            risk_flags = {risk_flags_raw}

        # Always flag scope violations regardless of whether a grant exists
        if risk_flags & _ALWAYS_FLAG:
            hits.append(ev)
            continue

        # Flag credential/privileged access when no JIT grant covers the principal
        if risk_flags & _REQUIRES_NO_GRANT:
            principal_id = ev.principal_id
            if principal_id and _has_active_jit_grant(principal_id, db):
                continue  # Grant exists and scope not exceeded - authorized
            hits.append(ev)

    if not hits:
        return None

    first     = hits[0]
    tool_name = first.tool_name or "unknown"
    tenant_id = events[0].tenant_id

    first_attrs = first.payload.get("attributes", {})
    first_flags_raw = first_attrs.get("aiaap.risk.flags", "[]")
    try:
        first_flags = json.loads(first_flags_raw)
    except (json.JSONDecodeError, TypeError):
        first_flags = []

    if "jit_scope_exceeded" in first_flags:
        title = f"JIT Scope Exceeded: '{tool_name}' called outside grant scope"
    elif "credential_access" in first_flags:
        title = f"Unauthorised Credential Access: '{tool_name}' called without JIT grant"
    else:
        title = f"Overbroad Permissions: Privileged tool '{tool_name}' called without JIT grant"

    return Finding(
        tenant_id=tenant_id,
        title=title,
        severity=Severity.medium,
        status=FindingStatus.detected,
        evidence_refs=[ev.id for ev in hits],
        scenario_id=SCENARIO_ID,
    )
