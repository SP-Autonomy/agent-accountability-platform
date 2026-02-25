"""
Policy Decision Point (PDP) routes.

Every tool-call pre-flight passes through POST /api/pdp/evaluate.
Evaluation order (first match wins):
  1. high-risk destination   → BLOCK
  2. privileged tool, no JIT → STEP_UP
  3. privileged tool, bad JIT → BLOCK
  4. privileged tool, scope mismatch → BLOCK
  5. intent envelope violation → SANDBOX
  6. rate limit exceeded → RATE_LIMIT
  7. default → ALLOW

Every call persists one EnforcementDecision row for audit.
"""

import fnmatch
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query

from saas.services.shared.database import get_db
from saas.services.shared.models import (
    EnforcementDecision, DecisionOutcome,
    JitGrant, IntentEnvelope, ToolUsage,
)
from saas.services.shared.schemas import PDPEvaluateRequest, PDPEvaluateResponse, EnforcementDecisionOut

router = APIRouter()

# ── PDP constants ─────────────────────────────────────────────────────────────

PRIVILEGED_TOOLS: set[str] = {
    "read_secrets", "write_secrets", "write_secret", "admin_reset",
    "exec_command", "exec_shell_command", "kubectl_exec",
    "deploy_infrastructure", "modify_iam_policy", "create_role",
    "attach_policy", "update_cluster", "delete_resource",
}

HIGH_RISK_DEST_PREFIXES: tuple[str, ...] = (
    "169.254.", "metadata.google.internal", "metadata.internal",
)

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PDP_RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX_CALLS      = int(os.getenv("PDP_RATE_LIMIT_MAX_CALLS", "20"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scope_covers_tool(grant_scope: str, tool_name: str) -> bool:
    """
    True if the grant scope authorises the requested tool.
    'admin' and '*' are wildcards.
    Otherwise check for canonical tool→scope equivalence.
    """
    gs = grant_scope.lower().strip()
    tn = tool_name.lower().replace("_", ":")
    if gs in ("admin", "*"):
        return True
    # Direct segment match: grant "secrets:read" covers "read_secrets"
    if tn in gs or gs in tn:
        return True
    # First scope segment prefix
    first_seg = gs.split(":")[0]
    if tool_name.lower().startswith(first_seg):
        return True
    return False


def _get_active_envelope(
    principal_id: int,
    tenant_id: str,
    trace_id: Optional[str],
    db,
) -> Optional[IntentEnvelope]:
    """Return the most-specific active IntentEnvelope for a principal."""
    now = datetime.now(timezone.utc)
    q = (
        db.query(IntentEnvelope)
        .filter(
            IntentEnvelope.principal_id == principal_id,
            IntentEnvelope.tenant_id == tenant_id,
            IntentEnvelope.active == True,  # noqa: E712
        )
        .filter(
            (IntentEnvelope.expires_at == None) | (IntentEnvelope.expires_at > now)  # noqa: E711
        )
    )
    # Prefer trace-scoped envelope
    if trace_id:
        row = q.filter(IntentEnvelope.trace_id == trace_id).first()
        if row:
            return row
    return q.order_by(IntentEnvelope.created_at.desc()).first()


def _check_envelope(
    tool_name: str,
    destination: Optional[str],
    envelope: IntentEnvelope,
) -> tuple[bool, list[str]]:
    """
    Check tool and destination against the envelope's allowed lists.
    Returns (passes, list_of_violations).
    Uses fnmatch for glob patterns.
    """
    violations: list[str] = []

    allowed_tools: list = envelope.allowed_tools or []
    if allowed_tools:
        if not any(fnmatch.fnmatch(tool_name, pat) for pat in allowed_tools):
            violations.append(f"tool '{tool_name}' not in allowed_tools")

    if destination:
        allowed_dests: list = envelope.allowed_destinations or []
        if allowed_dests:
            if not any(fnmatch.fnmatch(destination, pat) for pat in allowed_dests):
                violations.append(f"destination '{destination}' not in allowed_destinations")

    return len(violations) == 0, violations


# ── Core evaluation ───────────────────────────────────────────────────────────

def _evaluate(req: PDPEvaluateRequest, db) -> tuple[DecisionOutcome, str, list[str], Optional[int]]:
    """
    Returns (outcome, reason, rules_fired, jit_grant_id).
    First match wins.
    """
    rules_fired: list[str] = []
    now = datetime.now(timezone.utc)

    # Rule 1: high-risk destination
    dest = req.destination or ""
    if dest and any(dest.startswith(p) for p in HIGH_RISK_DEST_PREFIXES):
        rules_fired.append("high_risk_destination")
        return DecisionOutcome.block, f"Destination '{dest}' is a high-risk metadata endpoint", rules_fired, None

    # Rules 2-4: privileged tool checks
    if req.tool_name in PRIVILEGED_TOOLS:
        if req.jit_grant_id is None:
            rules_fired.append("no_jit_for_privileged_tool")
            return (
                DecisionOutcome.step_up,
                f"Tool '{req.tool_name}' requires a JIT grant - none provided",
                rules_fired,
                None,
            )

        # Look up the grant
        grant = db.query(JitGrant).filter_by(id=req.jit_grant_id).first()
        if not grant or grant.revoked or grant.expires_at <= now:
            rules_fired.append("invalid_or_expired_jit_grant")
            return (
                DecisionOutcome.block,
                f"JIT grant {req.jit_grant_id} is invalid, expired, or revoked",
                rules_fired,
                None,
            )

        if not _scope_covers_tool(grant.scope, req.tool_name):
            rules_fired.append("jit_scope_mismatch")
            return (
                DecisionOutcome.block,
                f"JIT grant scope '{grant.scope}' does not cover tool '{req.tool_name}'",
                rules_fired,
                grant.id,
            )

        rules_fired.append("jit_grant_valid")

    # Rule 5: intent envelope violation
    if req.principal_id:
        envelope = _get_active_envelope(req.principal_id, req.tenant_id, req.trace_id, db)
        if envelope:
            ok, violations = _check_envelope(req.tool_name, req.destination, envelope)
            if not ok:
                rules_fired.append("intent_envelope_violation")
                return (
                    DecisionOutcome.sandbox,
                    f"Intent envelope violation: {'; '.join(violations)}",
                    rules_fired,
                    req.jit_grant_id,
                )
            rules_fired.append("intent_envelope_passed")

    # Rule 6: rate limiting
    if req.principal_id:
        window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
        call_count = (
            db.query(ToolUsage)
            .filter(
                ToolUsage.principal_id == req.principal_id,
                ToolUsage.tool_name == req.tool_name,
                ToolUsage.timestamp >= window_start,
            )
            .count()
        )
        if call_count >= RATE_LIMIT_MAX_CALLS:
            rules_fired.append("rate_limit_exceeded")
            return (
                DecisionOutcome.rate_limit,
                f"Rate limit: {call_count} calls to '{req.tool_name}' in last {RATE_LIMIT_WINDOW_SECONDS}s",
                rules_fired,
                req.jit_grant_id,
            )

    # Default: allow
    rules_fired.append("default_allow")
    return DecisionOutcome.allow, "All policy checks passed", rules_fired, req.jit_grant_id


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/pdp/evaluate", response_model=PDPEvaluateResponse)
def evaluate(req: PDPEvaluateRequest, db=Depends(get_db)):
    """
    Evaluate a tool call against all active policies.
    Returns ALLOW, BLOCK, STEP_UP, SANDBOX, or RATE_LIMIT.
    Every call is persisted as an EnforcementDecision row.
    """
    outcome, reason, rules_fired, jit_grant_id = _evaluate(req, db)

    decision = EnforcementDecision(
        tenant_id=req.tenant_id,
        principal_id=req.principal_id,
        tool_name=req.tool_name,
        destination=req.destination,
        outcome=outcome,
        reason=reason,
        rules_fired=rules_fired,
        jit_grant_id=jit_grant_id,
        trace_id=req.trace_id,
        request_payload=req.model_dump(exclude={"tenant_id"}),
        signal_source=req.signal_source,
    )
    db.add(decision)
    db.commit()
    db.refresh(decision)

    return PDPEvaluateResponse(
        outcome=outcome.value,
        reason=reason,
        rules_fired=rules_fired,
        decision_id=decision.id,
        jit_grant_id=jit_grant_id,
    )


@router.get("/pdp/decisions", response_model=list[EnforcementDecisionOut])
def list_decisions(
    tenant_id:    str           = "default",
    outcome:      Optional[str] = None,
    principal_id: Optional[int] = None,
    limit:        int           = Query(default=100, le=500),
    offset:       int           = 0,
    db=Depends(get_db),
):
    """List enforcement decisions, newest first."""
    q = db.query(EnforcementDecision).filter(EnforcementDecision.tenant_id == tenant_id)
    if outcome:
        try:
            q = q.filter(EnforcementDecision.outcome == DecisionOutcome(outcome))
        except ValueError:
            pass
    if principal_id:
        q = q.filter(EnforcementDecision.principal_id == principal_id)
    rows = q.order_by(EnforcementDecision.created_at.desc()).offset(offset).limit(limit).all()
    return [EnforcementDecisionOut.model_validate(r) for r in rows]
