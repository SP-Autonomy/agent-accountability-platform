"""
AIAAP Ingest Normalizer
------------------------
Converts raw OTel span payloads, eBPF events, and K8s audit log entries
into the common NormalizedEvent schema.

Each source has its own normalizer function:
  normalize_otel_payload(raw_event_id, body, content_type) - async, from background task
  normalize_ebpf_event(payload, tenant_id, raw_event_id, db)
  normalize_audit_event(payload, tenant_id, raw_event_id, db)
"""

import json
import logging
from datetime import datetime,timezone

import structlog

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import (
    AgentPrincipal, NormalizedEvent, ToolUsage, EventSource, Severity, ConnectorType,
)

logger = structlog.get_logger()

# Agent name prefixes that identify lab/scenario-generated signals
_LAB_AGENT_PREFIXES = ("scenario-",)


def _classify_signal_source(agent_id: str) -> str:
    """
    Return "lab" for agents spawned by adversarial lab scenarios (scenario-* prefix),
    "operational" for all real workload agents.
    This is the single enforcement point for signal_source classification.
    """
    if agent_id and any(agent_id.startswith(p) for p in _LAB_AGENT_PREFIXES):
        return "lab"
    return "operational"


# IPs / hostnames that indicate cloud metadata service access
_METADATA_PREFIXES = (
    "169.254.169.254",
    "169.254.",
    "metadata.google.internal",
    "metadata.internal",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_metadata_dest(dest: str | None) -> bool:
    if not dest:
        return False
    return any(dest.startswith(p) for p in _METADATA_PREFIXES)


def _upsert_principal(db, agent_id: str, namespace: str, service_account: str, tenant_id: str) -> int | None:
    """Find or create an AgentPrincipal record. Returns the principal ID."""
    if not agent_id:
        return None
    principal = db.query(AgentPrincipal).filter_by(name=agent_id, tenant_id=tenant_id).first()
    if principal:
        principal.last_seen = datetime.now(timezone.utc)
        db.commit()
        return principal.id
    else:
        new_p = AgentPrincipal(
            name=agent_id,
            namespace=namespace or "unknown",
            service_account=service_account or "default",
            tenant_id=tenant_id,
        )
        db.add(new_p)
        db.commit()
        db.refresh(new_p)
        logger.info("principal_created", name=agent_id, tenant_id=tenant_id)
        return new_p.id


# ── OTel Span Normalizer ──────────────────────────────────────────────────────

def _parse_otlp_json(body: bytes) -> list[dict]:
    """
    Parse OTLP JSON export format.
    Returns a flat list of span dicts extracted from resourceSpans → scopeSpans → spans.
    """
    try:
        data = json.loads(body)
    except Exception:
        return []

    spans = []
    for resource_span in data.get("resourceSpans", []):
        resource_attrs = {
            a["key"]: a.get("value", {}).get("stringValue", "")
            for a in resource_span.get("resource", {}).get("attributes", [])
        }
        for scope_span in resource_span.get("scopeSpans", []):
            for span in scope_span.get("spans", []):
                flat_attrs = {
                    a["key"]: a.get("value", {}).get("stringValue", "")
                    for a in span.get("attributes", [])
                }
                flat_attrs.update(resource_attrs)  # resource attrs enrich span attrs
                span["attributes"] = flat_attrs
                spans.append(span)
    return spans


def normalize_otel_payload(raw_event_id: int, body: bytes, content_type: str):
    """
    Background task: parse and normalize an OTLP payload.
    Accepts both JSON (application/json) and protobuf content types.
    For MVP, JSON mode is always supported. Protobuf requires protobuf decoding (future).
    """
    db = SessionLocal()
    try:
        # MVP: only JSON encoding is fully supported
        # The OTel Collector can be configured to export OTLP/HTTP JSON
        if "json" in content_type or not content_type:
            spans = _parse_otlp_json(body)
        else:
            # Protobuf - store raw for now, log warning
            logger.warning("otlp_protobuf_not_yet_supported", raw_event_id=raw_event_id)
            return

        # Get tenant_id and connector metadata from the raw event record
        from saas.services.shared.models import RawEvent
        raw = db.query(RawEvent).filter_by(id=raw_event_id).first()
        tenant_id = raw.payload.get("tenant_id", "default") if raw else "default"
        connector_type_val = raw.connector_type.value if raw and raw.connector_type else None
        connector_instance_id = raw.connector_instance_id if raw else None

        for span in spans:
            _normalize_otel_span(
                span, tenant_id, raw_event_id, db,
                connector_type=connector_type_val,
                connector_instance_id=connector_instance_id,
            )

    except Exception as exc:
        logger.error("normalize_otel_error", raw_event_id=raw_event_id, error=str(exc))
    finally:
        db.close()


def _normalize_otel_span(
    span: dict, tenant_id: str, raw_event_id: int, db,
    connector_type: str | None = None,
    connector_instance_id: str | None = None,
) -> NormalizedEvent:
    """Normalize a single OTel span dict into NormalizedEvent + optional ToolUsage."""
    attrs       = span.get("attributes", {})
    tool_name   = attrs.get("aiaap.tool.name")
    dest        = attrs.get("aiaap.tool.destination_host")
    agent_id    = attrs.get("aiaap.agent.id", "")
    namespace   = attrs.get("aiaap.k8s.namespace", attrs.get("k8s.namespace.name", ""))
    svc_account = attrs.get("aiaap.k8s.service_account", "")
    trace_id    = span.get("traceId", "")
    span_id     = span.get("spanId", "")
    span_name   = span.get("name", "unknown")

    # Prefer span-level connector instance override (set via aiaap.connector.instance_id attribute)
    span_connector_instance = attrs.get("aiaap.connector.instance_id", connector_instance_id)

    severity = Severity.high if _is_metadata_dest(dest) else Severity.info

    principal_id  = _upsert_principal(db, agent_id, namespace, svc_account, tenant_id)
    signal_source = _classify_signal_source(agent_id)

    ct = None
    if connector_type:
        try:
            ct = ConnectorType(connector_type)
        except ValueError:
            pass

    normalized = NormalizedEvent(
        tenant_id=tenant_id,
        event_type=span_name,
        principal_id=principal_id,
        tool_name=tool_name,
        dest=dest,
        severity=severity,
        source=EventSource.otel,
        trace_id=trace_id,
        timestamp=datetime.now(timezone.utc),
        signal_source=signal_source,
        connector_type=ct,
        connector_instance_id=span_connector_instance,
        payload={
            "span_id": span_id,
            "span_name": span_name,
            "attributes": attrs,
        },
        raw_event_id=raw_event_id,
    )
    db.add(normalized)

    if tool_name:
        usage = ToolUsage(
            principal_id=principal_id,
            tool_name=tool_name,
            destination=dest,
            trace_id=trace_id,
            span_id=span_id,
            attributes=attrs,
            tenant_id=tenant_id,
            signal_source=signal_source,
        )
        db.add(usage)

    db.commit()

    # ── Intent Envelope extraction (SDK-provided via aiaap.intent.* attributes) ──
    # If the span carries intent declarations, upsert an IntentEnvelope so the
    # behavioural engine can later detect violations against it.
    intent_label = attrs.get("aiaap.intent.label")
    if intent_label and principal_id:
        try:
            import json as _json
            raw_tools = attrs.get("aiaap.intent.allowed_tools", "")
            raw_dests = attrs.get("aiaap.intent.allowed_destinations", "")
            max_priv  = attrs.get("aiaap.intent.max_privilege", "low")

            allowed_tools = _json.loads(raw_tools) if raw_tools else []
            allowed_dests = _json.loads(raw_dests) if raw_dests else []

            from saas.services.behavioural.intent_envelope import upsert_envelope_from_sdk
            upsert_envelope_from_sdk(
                principal_id  = principal_id,
                tenant_id     = tenant_id,
                trace_id      = trace_id or None,
                intent_label  = intent_label,
                allowed_tools = allowed_tools,
                allowed_dests = allowed_dests,
                max_privilege = max_priv,
                db            = db,
            )
            db.commit()
            logger.info("intent_envelope_from_sdk", label=intent_label, trace_id=trace_id)
        except Exception as _exc:
            logger.warning("intent_envelope_extraction_failed", error=str(_exc))

    logger.info("otel_span_normalized", span_name=span_name, tool=tool_name, dest=dest)
    return normalized


# ── eBPF Event Normalizer ─────────────────────────────────────────────────────

def normalize_ebpf_event(
    payload: dict, tenant_id: str, raw_event_id: int, db,
    connector_type: str | None = None,
    connector_instance_id: str | None = None,
) -> NormalizedEvent:
    """
    Normalize a Tetragon network event into NormalizedEvent.
    Tetragon emits events shaped like:
      { "type": "process_connect", "process": {...}, "destination_ip": "...", "destination_port": 443, ... }
    """
    event_type  = payload.get("type", "unknown")
    dest_ip     = payload.get("destination_ip") or payload.get("dest_ip", "")
    dest_port   = str(payload.get("destination_port") or payload.get("dest_port", ""))
    namespace   = payload.get("namespace", "")
    pod_name    = payload.get("pod_name", "")
    action      = payload.get("action", "observed")  # "blocked" or "observed"

    dest = f"{dest_ip}:{dest_port}" if dest_ip else None

    severity = Severity.info
    if _is_metadata_dest(dest_ip):
        severity = Severity.high
    elif action == "blocked":
        severity = Severity.medium

    ct = None
    if connector_type:
        try:
            ct = ConnectorType(connector_type)
        except ValueError:
            pass

    normalized = NormalizedEvent(
        tenant_id=tenant_id,
        event_type=f"ebpf_{event_type}",
        dest=dest,
        severity=severity,
        source=EventSource.ebpf,
        timestamp=datetime.now(timezone.utc),
        connector_type=ct,
        connector_instance_id=connector_instance_id,
        payload={
            "namespace": namespace,
            "pod_name": pod_name,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "action": action,
            "raw": payload,
        },
        raw_event_id=raw_event_id,
    )
    db.add(normalized)
    db.commit()
    logger.info("ebpf_event_normalized", event_type=event_type, dest=dest, action=action)
    return normalized


# ── K8s Audit Event Normalizer ────────────────────────────────────────────────

# Verbs + resources that require elevated attention
_AUDIT_HIGH = {
    ("create",  "rolebindings"),
    ("update",  "rolebindings"),
    ("patch",   "rolebindings"),
    ("create",  "clusterrolebindings"),
    ("update",  "clusterrolebindings"),
    ("patch",   "clusterrolebindings"),
    ("create",  "pods/exec"),
    ("create",  "pods/attach"),
}
_AUDIT_MEDIUM = {
    ("get",  "secrets"),
    ("list", "secrets"),
    ("get",  "serviceaccounts/token"),
}


def normalize_cloud_event(
    payload: dict, tenant_id: str, raw_event_id: int, db,
    connector_type: str | None = None,
    connector_instance_id: str | None = None,
) -> NormalizedEvent:
    """
    Normalize a cloud control-plane event (CloudTrail, GCP Audit, Azure Activity Log).
    The AIAAP CloudTrail connector pre-enriches the payload with _aiaap_* fields.
    Falls back to deriving fields directly from CloudTrail event structure.
    """
    import re as _re

    event_name   = payload.get("eventName", "")
    event_source = payload.get("eventSource", "")  # e.g. "iam.amazonaws.com"

    # Use pre-computed event_type from connector if available, else derive it
    event_type = payload.get("_aiaap_event_type")
    if not event_type:
        service    = event_source.replace(".amazonaws.com", "").replace(".", "_")
        snake_name = _re.sub(r"(?<!^)(?=[A-Z])", "_", event_name).lower() if event_name else "unknown"
        event_type = f"cloud.{service}.{snake_name}" if service else f"cloud.unknown.{snake_name}"

    # Affected resource: role/policy ARN or name
    dest = payload.get("_aiaap_dest") or ""
    if not dest:
        req = payload.get("requestParameters") or {}
        dest = (
            req.get("policyArn")
            or req.get("roleName")
            or req.get("policyName")
            or ""
        )

    # HIGH severity for known IAM privilege escalation actions
    _IAM_ESCALATION = {
        "CreatePolicyVersion", "AttachRolePolicy", "PutRolePolicy",
        "UpdateAssumeRolePolicy", "CreateRole", "PassRole",
        "PutGroupPolicy", "AddUserToGroup",
    }
    severity = Severity.high if event_name in _IAM_ESCALATION else Severity.medium

    ct = None
    if connector_type:
        try:
            ct = ConnectorType(connector_type)
        except ValueError:
            pass

    normalized = NormalizedEvent(
        tenant_id=tenant_id,
        event_type=event_type,
        dest=dest,
        severity=severity,
        source=EventSource.cloud,
        timestamp=datetime.now(timezone.utc),
        connector_type=ct,
        connector_instance_id=connector_instance_id,
        payload=payload,
        raw_event_id=raw_event_id,
    )
    db.add(normalized)
    db.commit()
    logger.info("cloud_event_normalized", event_type=event_type, event_name=event_name, dest=dest)
    return normalized


def normalize_audit_event(
    payload: dict, tenant_id: str, raw_event_id: int, db,
    connector_type: str | None = None,
    connector_instance_id: str | None = None,
) -> NormalizedEvent:
    """
    Normalize a Kubernetes audit log entry.
    K8s audit logs are JSON with fields: verb, objectRef, user, responseStatus, etc.
    """
    verb      = payload.get("verb", "")
    obj_ref   = payload.get("objectRef", {})
    resource  = obj_ref.get("resource", "")
    subresource = obj_ref.get("subresource", "")
    full_resource = f"{resource}/{subresource}" if subresource else resource
    user_name = payload.get("user", {}).get("username", "")
    namespace = obj_ref.get("namespace", "")

    severity = Severity.info
    key = (verb, full_resource)
    if key in _AUDIT_HIGH or (verb, resource) in _AUDIT_HIGH:
        severity = Severity.high
    elif key in _AUDIT_MEDIUM or (verb, resource) in _AUDIT_MEDIUM:
        severity = Severity.medium

    event_type = f"k8s_audit_{verb}_{full_resource.replace('/', '_')}"

    ct = None
    if connector_type:
        try:
            ct = ConnectorType(connector_type)
        except ValueError:
            pass

    normalized = NormalizedEvent(
        tenant_id=tenant_id,
        event_type=event_type,
        dest=namespace,
        severity=severity,
        source=EventSource.audit,
        timestamp=datetime.now(timezone.utc),
        connector_type=ct,
        connector_instance_id=connector_instance_id,
        payload={
            "verb": verb,
            "resource": full_resource,
            "user": user_name,
            "namespace": namespace,
            "response_code": payload.get("responseStatus", {}).get("code"),
            "raw": payload,
        },
        raw_event_id=raw_event_id,
    )
    db.add(normalized)
    db.commit()
    logger.info("audit_event_normalized", event_type=event_type, verb=verb, resource=full_resource)
    return normalized
