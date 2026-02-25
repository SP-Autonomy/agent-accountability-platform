"""
Rule: rbac_escalation_misconfig
---------------------------------
Detects creation or modification of overly-permissive RBAC bindings.
Matches K8s audit events for clusterrolebinding/rolebinding create/update/patch.

Status: always DETECTED (audit log is our signal; we cannot prevent at this layer -
prevention is via Kyverno admission policy).
"""

from typing import Optional

from saas.services.shared.models import (
    NormalizedEvent, Finding, Severity, FindingStatus, EventSource,
)

SCENARIO_ID = "rbac_escalation_misconfig"

_TRIGGER_EVENT_TYPES = {
    "k8s_audit_create_clusterrolebindings",
    "k8s_audit_update_clusterrolebindings",
    "k8s_audit_patch_clusterrolebindings",
    "k8s_audit_create_rolebindings",
    "k8s_audit_update_rolebindings",
    "k8s_audit_patch_rolebindings",
}


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    hits = [ev for ev in events if ev.source == EventSource.audit and ev.event_type in _TRIGGER_EVENT_TYPES]

    if not hits:
        return None

    evidence_ids = [ev.id for ev in hits]
    tenant_id    = events[0].tenant_id

    # Extract user who made the change for the title
    first_hit = hits[0]
    user = first_hit.payload.get("user", "unknown")
    resource = first_hit.payload.get("resource", "binding")

    return Finding(
        tenant_id=tenant_id,
        title=f"RBAC Escalation: {resource} created/modified by {user}",
        severity=Severity.high,
        status=FindingStatus.detected,
        evidence_refs=evidence_ids,
        scenario_id=SCENARIO_ID,
    )
