"""
JIT Grant routes: create, list, validate, revoke, history.

Security fixes in this version:
  - Scope validation uses prefix-hierarchy matching, not substring match
  - Max TTL enforced via MAX_JIT_TTL_HOURS env var (default 24h)
  - All mutations emit an AuditLog entry
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from saas.services.shared.database import get_db
from saas.services.shared.models import JitGrant, AgentPrincipal, AuditLog, Approval, ApprovalStatus
from saas.services.shared.schemas import JitGrantCreate, JitGrantOut, ApprovalRequest, ApprovalOut

router = APIRouter()

MAX_JIT_TTL_HOURS = int(os.getenv("MAX_JIT_TTL_HOURS", "24"))


# ── Scope validation ───────────────────────────────────────────────────────────

def _scope_matches(requested: str, granted: str) -> bool:
    """
    Prefix-hierarchy scope matching.
    A grant of "secrets:read" covers "secrets:read" and "secrets:read:production"
    but NOT "secrets:write" or "admin".
    """
    return requested == granted or requested.startswith(granted + ":")


# ── Audit helper ───────────────────────────────────────────────────────────────

def _emit_audit(db, tenant_id: str, actor: str, action: str, resource: str, detail: dict):
    log = AuditLog(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource=resource,
        detail=detail,
    )
    db.add(log)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/jit/grants", response_model=list[JitGrantOut])
def list_grants(
    tenant_id: str = "default",
    principal_id: Optional[int] = None,
    active_only: bool = True,
    db=Depends(get_db),
):
    q = db.query(JitGrant).filter(JitGrant.tenant_id == tenant_id)
    if principal_id:
        q = q.filter(JitGrant.principal_id == principal_id)
    if active_only:
        now = datetime.now(timezone.utc)
        q = q.filter(JitGrant.expires_at > now, JitGrant.revoked == False)  # noqa: E712
    rows = q.order_by(JitGrant.created_at.desc()).all()
    return [JitGrantOut.model_validate(r) for r in rows]


@router.get("/jit/grants/history", response_model=list[JitGrantOut])
def grant_history(
    tenant_id: str = "default",
    principal_id: Optional[int] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db=Depends(get_db),
):
    """All grants including expired and revoked, for audit trail viewing."""
    q = db.query(JitGrant).filter(JitGrant.tenant_id == tenant_id)
    if principal_id:
        q = q.filter(JitGrant.principal_id == principal_id)
    rows = q.order_by(JitGrant.created_at.desc()).offset(offset).limit(limit).all()
    return [JitGrantOut.model_validate(r) for r in rows]


@router.post("/jit/grants", response_model=JitGrantOut, status_code=201)
def create_grant(req: JitGrantCreate, db=Depends(get_db)):
    principal = db.query(AgentPrincipal).filter_by(id=req.principal_id).first()
    if not principal:
        raise HTTPException(status_code=404, detail="Principal not found")

    now = datetime.now(timezone.utc)
    if req.expires_at <= now:
        raise HTTPException(status_code=400, detail="expires_at must be in the future")

    max_expiry = now + timedelta(hours=MAX_JIT_TTL_HOURS)
    if req.expires_at > max_expiry:
        raise HTTPException(
            status_code=400,
            detail=f"Grant TTL exceeds maximum of {MAX_JIT_TTL_HOURS} hours",
        )

    grant = JitGrant(**req.model_dump())
    db.add(grant)
    db.flush()   # get grant.id before emit

    _emit_audit(
        db,
        tenant_id=req.tenant_id,
        actor=req.created_by,
        action="jit_grant_created",
        resource=f"jit_grant:{grant.id}",
        detail={
            "principal_id": req.principal_id,
            "scope": req.scope,
            "expires_at": req.expires_at.isoformat(),
            "reason": req.reason,
        },
    )
    db.commit()
    db.refresh(grant)
    return JitGrantOut.model_validate(grant)


@router.get("/jit/grants/{grant_id}", response_model=JitGrantOut)
def get_grant(grant_id: int, db=Depends(get_db)):
    row = db.query(JitGrant).filter_by(id=grant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Grant not found")
    return JitGrantOut.model_validate(row)


@router.delete("/jit/grants/{grant_id}", status_code=204)
def revoke_grant(
    grant_id: int,
    revoked_by: str = "admin",
    db=Depends(get_db),
):
    """Revoke (soft-delete) a JIT grant. Record kept for audit purposes."""
    row = db.query(JitGrant).filter_by(id=grant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Grant not found")
    if row.revoked:
        raise HTTPException(status_code=409, detail="Grant already revoked")

    row.revoked = True
    _emit_audit(
        db,
        tenant_id=row.tenant_id,
        actor=revoked_by,
        action="jit_grant_revoked",
        resource=f"jit_grant:{grant_id}",
        detail={"principal_id": row.principal_id, "scope": row.scope},
    )
    db.commit()


@router.post("/jit/request", response_model=ApprovalOut, status_code=202)
def jit_request(req: ApprovalRequest, db=Depends(get_db)):
    """
    Submit a JIT access request for operator approval.
    Creates a pending Approval with a 120-minute request TTL.
    Returns 202 Accepted - the grant is NOT immediately active.
    Use POST /approvals/{id}/approve to activate.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=120)

    approval = Approval(
        tenant_id=req.tenant_id,
        principal_id=req.principal_id,
        scope=req.scope,
        reason=req.reason,
        ttl_minutes=req.ttl_minutes,
        requested_by=req.requested_by,
        status=ApprovalStatus.pending,
        context=req.context,
        expires_at=expires_at,
    )
    db.add(approval)
    db.flush()

    _emit_audit(
        db,
        tenant_id=req.tenant_id,
        actor=req.requested_by,
        action="jit_approval_requested",
        resource=f"approval:{approval.id}",
        detail={
            "principal_id": req.principal_id,
            "scope": req.scope,
            "ttl_minutes": req.ttl_minutes,
            "reason": req.reason,
        },
    )
    db.commit()
    db.refresh(approval)
    return ApprovalOut.model_validate(approval)


@router.get("/jit/grants/{grant_id}/validate")
def validate_grant(grant_id: int, scope: str, db=Depends(get_db)):
    """
    Check if a specific grant is still active and covers the requested scope.
    Uses prefix-hierarchy scope matching (not substring).
    """
    grant = db.query(JitGrant).filter_by(id=grant_id).first()
    if not grant:
        return {"valid": False, "reason": "not_found"}
    if grant.revoked:
        return {"valid": False, "reason": "revoked"}
    if grant.expires_at <= datetime.now(timezone.utc):
        return {"valid": False, "reason": "expired"}
    if not _scope_matches(scope, grant.scope):
        return {"valid": False, "reason": "scope_mismatch", "granted": grant.scope, "requested": scope}
    return {"valid": True, "grant_id": grant_id, "scope": grant.scope}
