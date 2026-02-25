"""
Intent Envelope - CRUD helpers and violation detection
--------------------------------------------------------
An IntentEnvelope declares what an agent principal is allowed to do within a
session or trace: which tools, which destinations, which data classes, and
what maximum privilege tier.

Violations are detected by comparing observed ToolUsage against the active
envelope and emitting intent_boundary_violation Findings.

Three envelope creation paths:
  A) SDK-provided:  OTel spans carry aiaap.intent.* attributes (see normalizer.py)
  B) UI-created:    Dashboard form calls create_envelope_from_ui()
  C) Auto fallback: auto_create_envelope_from_baseline() builds from BehavioralBaseline
"""

import fnmatch
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import (
    IntentEnvelope, AgentPrincipal, BehavioralBaseline,
    ToolUsage, Finding, Severity, FindingStatus,
)

logger = structlog.get_logger()

# ── Privilege tier ordering ───────────────────────────────────────────────────

_TIER_ORDER = {"low": 0, "medium": 1, "high": 2}

_PRIVILEGED_TOOLS = {
    "read_secrets", "write_secrets", "exec_command", "deploy_infrastructure",
    "modify_iam_policy", "create_role", "attach_policy", "update_cluster",
    "delete_resource", "kubectl_exec", "fetch_url",
}

_MEDIUM_PRIVILEGE_TOOLS = {"search_docs", "get_customer", "read_file"}


def _infer_privilege_tier(tool_name: str | None) -> str:
    if not tool_name:
        return "low"
    t = tool_name.lower()
    if t in _PRIVILEGED_TOOLS:
        return "high"
    if t in _MEDIUM_PRIVILEGE_TOOLS:
        return "medium"
    return "low"


# ── Envelope lookup ───────────────────────────────────────────────────────────

def get_active_envelope(
    principal_id: int,
    tenant_id: str,
    db,
    trace_id: str | None = None,
) -> Optional[IntentEnvelope]:
    """
    Return the most relevant active envelope for a principal.
    Priority: trace-specific > most recent active envelope.
    Returns None if no envelope exists.
    """
    now = datetime.now(timezone.utc)

    q = (
        db.query(IntentEnvelope)
          .filter(
              IntentEnvelope.principal_id == principal_id,
              IntentEnvelope.tenant_id    == tenant_id,
              IntentEnvelope.active       == True,           # noqa: E712
          )
          .filter(
              (IntentEnvelope.expires_at == None) |          # noqa: E711
              (IntentEnvelope.expires_at > now)
          )
    )

    if trace_id:
        trace_match = q.filter(IntentEnvelope.trace_id == trace_id).first()
        if trace_match:
            return trace_match

    return q.order_by(IntentEnvelope.created_at.desc()).first()


# ── Violation check ───────────────────────────────────────────────────────────

def check_violation(
    tool_name:   str | None,
    destination: str | None,
    privilege_tier: str,
    envelope: IntentEnvelope,
) -> tuple[bool, list[str]]:
    """
    Compare a single tool invocation against the envelope.
    Returns (is_violation, list_of_violation_reasons).
    """
    reasons: list[str] = []

    allowed_tools = envelope.allowed_tools or []
    allowed_dests = envelope.allowed_destinations or []
    max_tier      = envelope.max_privilege_tier or "low"

    # Tool name check (exact match or wildcard)
    if tool_name and allowed_tools:
        if not any(fnmatch.fnmatch(tool_name.lower(), pat.lower()) for pat in allowed_tools):
            reasons.append(f"tool '{tool_name}' not in allowed_tools {allowed_tools}")

    # Destination check (exact match or glob)
    if destination and allowed_dests:
        if not any(fnmatch.fnmatch(destination.lower(), pat.lower()) for pat in allowed_dests):
            reasons.append(f"destination '{destination}' not in allowed_destinations")

    # Privilege tier check
    if _TIER_ORDER.get(privilege_tier, 0) > _TIER_ORDER.get(max_tier, 0):
        reasons.append(
            f"privilege tier '{privilege_tier}' exceeds max allowed '{max_tier}'"
        )

    return bool(reasons), reasons


# ── Finding creation ──────────────────────────────────────────────────────────

def create_violation_finding(
    principal: AgentPrincipal,
    envelope: IntentEnvelope,
    tool_name: str | None,
    destination: str | None,
    reasons: list[str],
    evidence_event_id: int | None,
    db,
) -> Finding:
    detail = json.dumps({
        "intent_label":    envelope.intent_label,
        "tool_name":       tool_name,
        "destination":     destination,
        "violations":      reasons,
        "envelope_id":     envelope.id,
        "envelope_source": envelope.created_by,
    })
    severity = (
        Severity.high
        if any("privilege" in r or "secret" in r or "169.254" in r for r in reasons)
        else Severity.medium
    )
    f = Finding(
        tenant_id     = principal.tenant_id,
        title         = f"Intent Boundary Violation: {principal.name} - {reasons[0][:80]}",
        severity      = severity,
        status        = FindingStatus.detected,
        evidence_refs = [evidence_event_id] if evidence_event_id else [],
        scenario_id   = "intent_boundary",
    )
    db.add(f)
    logger.info(
        "intent_boundary_violation",
        principal=principal.name,
        tool=tool_name,
        dest=destination,
        reasons=reasons,
    )
    return f


# ── Auto envelope creation from baseline ─────────────────────────────────────

def auto_create_envelope_from_baseline(
    principal: AgentPrincipal,
    tenant_id: str,
    db,
    ttl_hours: int = 24,
) -> IntentEnvelope:
    """
    Build a conservative IntentEnvelope from the existing BehavioralBaseline.
    Used as a fallback when no explicit envelope has been declared.
    """
    baseline: BehavioralBaseline | None = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal.id, tenant_id=tenant_id)
          .first()
    )

    allowed_tools = list(baseline.known_tools or []) if baseline else []
    allowed_dests = list(baseline.known_destinations or []) if baseline else []
    max_priv      = "low"

    # Infer max privilege from baseline tools
    if baseline and any(t in _PRIVILEGED_TOOLS for t in (baseline.known_tools or [])):
        max_priv = "high"
    elif baseline and any(t in _MEDIUM_PRIVILEGE_TOOLS for t in (baseline.known_tools or [])):
        max_priv = "medium"

    envelope = IntentEnvelope(
        tenant_id            = tenant_id,
        principal_id         = principal.id,
        intent_label         = f"auto:{principal.name}",
        allowed_tools        = allowed_tools,
        allowed_destinations = allowed_dests,
        allowed_data_classes = ["public"],
        max_privilege_tier   = max_priv,
        expires_at           = datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
        created_by           = "auto",
        active               = True,
    )
    db.add(envelope)
    logger.info(
        "auto_envelope_created",
        principal=principal.name,
        tools=len(allowed_tools),
        dests=len(allowed_dests),
    )
    return envelope


# ── SDK envelope upsert ────────────────────────────────────────────────────────

def upsert_envelope_from_sdk(
    principal_id: int,
    tenant_id:    str,
    trace_id:     str | None,
    intent_label: str,
    allowed_tools: list[str],
    allowed_dests: list[str],
    max_privilege: str,
    db,
) -> IntentEnvelope:
    """
    Called by the ingest normalizer when OTel spans carry aiaap.intent.* attributes.
    Upserts by (principal_id, trace_id) - one envelope per trace.
    """
    existing = None
    if trace_id:
        existing = (
            db.query(IntentEnvelope)
              .filter_by(principal_id=principal_id, tenant_id=tenant_id, trace_id=trace_id)
              .first()
        )

    if existing:
        # Update in place
        existing.intent_label         = intent_label or existing.intent_label
        existing.allowed_tools        = allowed_tools or existing.allowed_tools
        existing.allowed_destinations = allowed_dests or existing.allowed_destinations
        existing.max_privilege_tier   = max_privilege or existing.max_privilege_tier
        return existing

    envelope = IntentEnvelope(
        tenant_id            = tenant_id,
        principal_id         = principal_id,
        trace_id             = trace_id,
        intent_label         = intent_label or "sdk-provided",
        allowed_tools        = allowed_tools,
        allowed_destinations = allowed_dests,
        allowed_data_classes = [],
        max_privilege_tier   = max_privilege or "low",
        expires_at           = datetime.now(timezone.utc) + timedelta(hours=8),
        created_by           = "sdk",
        active               = True,
    )
    db.add(envelope)
    logger.info(
        "sdk_envelope_upserted",
        principal_id=principal_id,
        trace_id=trace_id,
        label=intent_label,
    )
    return envelope


# ── Batch violation scan ──────────────────────────────────────────────────────

VIOLATION_DEDUP_MINUTES = 10   # suppress duplicate intent_boundary Findings


def _has_recent_violation_finding(principal: AgentPrincipal, db) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=VIOLATION_DEDUP_MINUTES)
    return (
        db.query(Finding)
          .filter(
              Finding.scenario_id == "intent_boundary",
              Finding.tenant_id   == principal.tenant_id,
              Finding.created_at  >= cutoff,
          )
          .first()
    ) is not None


def run_envelope_violation_scan(tenant_id: str = "default") -> int:
    """
    Background task: scan recent ToolUsage against active IntentEnvelopes.
    Called every INTENT_INTERVAL seconds.
    Returns count of new Findings created.
    """
    db = SessionLocal()
    findings_created = 0

    try:
        # Scan last 5-minute window for new tool calls
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)

        principals = (
            db.query(AgentPrincipal)
              .filter(AgentPrincipal.tenant_id == tenant_id)
              .all()
        )

        for principal in principals:
            # Skip if we already raised a violation for this principal recently
            if _has_recent_violation_finding(principal, db):
                continue

            envelope = get_active_envelope(principal.id, tenant_id, db)
            if not envelope:
                # No envelope yet - try auto-create if baseline exists
                bl = (
                    db.query(BehavioralBaseline)
                      .filter_by(principal_id=principal.id, tenant_id=tenant_id)
                      .first()
                )
                if bl and bl.observations >= 3:
                    envelope = auto_create_envelope_from_baseline(principal, tenant_id, db)
                    db.flush()
                else:
                    continue

            recent_usages = (
                db.query(ToolUsage)
                  .filter(
                      ToolUsage.principal_id == principal.id,
                      ToolUsage.tenant_id    == tenant_id,
                      ToolUsage.timestamp    >= cutoff,
                  )
                  .all()
            )

            for usage in recent_usages:
                tier = _infer_privilege_tier(usage.tool_name)
                is_violation, reasons = check_violation(
                    usage.tool_name,
                    usage.destination,
                    tier,
                    envelope,
                )
                if is_violation:
                    create_violation_finding(
                        principal, envelope,
                        usage.tool_name, usage.destination,
                        reasons,
                        evidence_event_id=None,
                        db=db,
                    )
                    findings_created += 1
                    db.commit()
                    break  # one finding per principal per scan cycle

    except Exception as exc:
        logger.error("envelope_violation_scan_error", error=str(exc))
        db.rollback()
    finally:
        db.close()

    return findings_created
