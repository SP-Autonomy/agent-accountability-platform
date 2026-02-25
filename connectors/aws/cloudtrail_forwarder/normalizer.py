"""
AWS CloudTrail → AIAAP NormalizedEvent normalizer.

Converts raw CloudTrail events (as delivered by EventBridge or polled via API)
into the AIAAP NormalizedEvent payload schema that the ingest service accepts.

Event type naming convention: cloud.<service>.<snake_case_action>
Examples:
  AttachRolePolicy  → cloud.iam.attach_role_policy
  PutRolePolicy     → cloud.iam.put_role_policy
  GetObject         → cloud.s3.get_object
"""

import re

# IAM actions that indicate privilege escalation attempts.
# These map to high severity and trigger the iam_escalation detection rule.
IAM_ESCALATION_ACTIONS = {
    "CreatePolicyVersion",
    "AttachRolePolicy",
    "PutRolePolicy",
    "UpdateAssumeRolePolicy",
    "CreateRole",
    "PassRole",
}


def _camel_to_snake(name: str) -> str:
    """Convert CamelCase action name to snake_case: AttachRolePolicy → attach_role_policy"""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _extract_affected_resource(ct_event: dict) -> str:
    """
    Extract the affected resource (role name, policy ARN, etc.) from requestParameters.
    Returns the most specific identifier available, or empty string.
    """
    req = ct_event.get("requestParameters") or {}
    # Priority: specific ARN > name > fallback to resources list
    return (
        req.get("policyArn")
        or req.get("roleName")
        or req.get("policyName")
        or req.get("userName")
        or req.get("groupName")
        or (ct_event.get("resources") or [{}])[0].get("ARN", "")
    )


def normalize_cloudtrail_event(ct_event: dict, tenant_id: str) -> dict:
    """
    Normalize a CloudTrail event dict into AIAAP ingest payload format.

    Args:
        ct_event: Raw CloudTrail event dict (the 'detail' field from EventBridge,
                  or an event from cloudtrail.lookup_events())
        tenant_id: AIAAP tenant identifier

    Returns:
        Dict matching IngestEventRequest schema with source="cloud"
    """
    event_name = ct_event.get("eventName", "")
    event_source = ct_event.get("eventSource", "")  # e.g. "iam.amazonaws.com"

    # Derive service label: "iam.amazonaws.com" → "iam", "s3.amazonaws.com" → "s3"
    service = event_source.replace(".amazonaws.com", "").replace(".", "_")
    snake_action = _camel_to_snake(event_name) if event_name else "unknown"
    event_type = f"cloud.{service}.{snake_action}" if service else f"cloud.{snake_action}"

    # Actor: who performed the action
    user_identity = ct_event.get("userIdentity") or {}
    actor_arn = user_identity.get("arn") or user_identity.get("principalId") or "unknown"

    # Affected resource (role/policy/user being modified)
    dest = _extract_affected_resource(ct_event)

    # Severity: HIGH for known privilege escalation actions
    severity = "high" if event_name in IAM_ESCALATION_ACTIONS else "medium"

    # Build the payload exactly as IngestEventRequest expects it
    return {
        "tenant_id": tenant_id,
        "source": "cloud",
        "payload": {
            **ct_event,
            # Enrich with normalized fields for easy rule matching
            "_aiaap_event_type": event_type,
            "_aiaap_actor_arn": actor_arn,
            "_aiaap_dest": dest,
            "_aiaap_source_type": "cloudtrail",
        },
    }
