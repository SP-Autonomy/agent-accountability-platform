"""
Detection Rule: IAM Privilege Escalation (Cloud)
-------------------------------------------------
Detects AWS IAM privilege escalation actions forwarded from CloudTrail.
Matches on the normalized event_type field using the cloud.iam.* naming convention.

Triggered by:
  - AttachRolePolicy  → cloud.iam.attach_role_policy
  - PutRolePolicy     → cloud.iam.put_role_policy
  - CreatePolicyVersion → cloud.iam.create_policy_version
  - UpdateAssumeRolePolicy → cloud.iam.update_assume_role_policy
  - CreateRole        → cloud.iam.create_role
  - PassRole          → cloud.iam.pass_role
  - PutGroupPolicy    → cloud.iam.put_group_policy
  - AddUserToGroup    → cloud.iam.add_user_to_group

Status: always DETECTED (enforcement is via IAM policies / SCP, not AIAAP inline)
"""

from typing import Optional
from saas.services.shared.models import NormalizedEvent, Finding, EventSource, Severity, FindingStatus

IAM_ESCALATION_EVENT_TYPES = {
    "cloud.iam.create_policy_version",
    "cloud.iam.attach_role_policy",
    "cloud.iam.put_role_policy",
    "cloud.iam.update_assume_role_policy",
    "cloud.iam.create_role",
    "cloud.iam.pass_role",
    "cloud.iam.put_group_policy",
    "cloud.iam.add_user_to_group",
}


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    """
    Scan events for IAM privilege escalation actions from cloud sources.
    Returns a Finding if any escalation event is found, else None.
    """
    cloud_events = [e for e in events if e.source == EventSource.cloud]
    if not cloud_events:
        return None

    for ev in cloud_events:
        if ev.event_type not in IAM_ESCALATION_EVENT_TYPES:
            continue

        # Extract human-readable details from payload
        action   = ev.payload.get("eventName", ev.event_type)
        identity = ev.payload.get("userIdentity") or {}
        actor    = identity.get("arn") or identity.get("principalId") or "unknown"
        dest     = ev.dest or ev.payload.get("_aiaap_dest", "")
        region   = ev.payload.get("awsRegion", "")

        title = f"IAM Privilege Escalation: {action}"
        if dest:
            title += f" on {dest}"
        if region:
            title += f" ({region})"

        return Finding(
            tenant_id=ev.tenant_id,
            title=title,
            severity=Severity.high,
            status=FindingStatus.detected,
            scenario_id="iam_escalation",
            evidence_refs=[ev.id],
        )

    return None
