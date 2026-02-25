"""
Approval workflow routes.

Approval lifecycle:
  POST /api/approvals/request  → creates Approval(status=pending)
  POST /api/approvals/{id}/approve → creates JitGrant, sets jit_grant_id
  POST /api/approvals/{id}/deny    → sets status=denied
  GET  /api/approvals              → list (auto-expires stale pending rows)
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from saas.services.shared.database import get_db
from saas.services.shared.models import Approval, ApprovalStatus, JitGrant, AuditLog
from saas.services.shared.schemas import ApprovalOut, ApprovalRequest, ApprovalReviewRequest

router = APIRouter()

REQUEST_TTL_MINUTES = 120  # pending approvals expire after 2 hours if not reviewed


# ── Audit helper ───────────────────────────────────────────────────────────────

def _emit_audit(db, tenant_id: str, actor: str, action: str, resource: str, detail: dict):
    db.add(AuditLog(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource=resource,
        detail=detail,
    ))


def _expire_stale(db, tenant_id: str):
    """Mark pending approvals past their expires_at as expired (lazy expiry)."""
    now = datetime.now(timezone.utc)
    stale = (
        db.query(Approval)
        .filter(
            Approval.tenant_id == tenant_id,
            Approval.status == ApprovalStatus.pending,
            Approval.expires_at <= now,
        )
        .all()
    )
    for a in stale:
        a.status = ApprovalStatus.expired
    if stale:
        db.commit()


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/approvals", response_model=list[ApprovalOut])
def list_approvals(
    tenant_id:    str           = "default",
    status:       Optional[str] = None,
    principal_id: Optional[int] = None,
    limit:        int           = Query(default=100, le=500),
    db=Depends(get_db),
):
    """List approval requests. Auto-expires stale pending rows before returning."""
    _expire_stale(db, tenant_id)

    q = db.query(Approval).filter(Approval.tenant_id == tenant_id)
    if status:
        try:
            q = q.filter(Approval.status == ApprovalStatus(status))
        except ValueError:
            pass
    if principal_id:
        q = q.filter(Approval.principal_id == principal_id)
    rows = q.order_by(Approval.created_at.desc()).limit(limit).all()
    return [ApprovalOut.model_validate(r) for r in rows]


@router.post("/approvals/request", response_model=ApprovalOut, status_code=201)
def request_approval(req: ApprovalRequest, db=Depends(get_db)):
    """Create a pending approval request for a JIT grant."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=REQUEST_TTL_MINUTES)

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
        action="approval_requested",
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


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalOut)
def approve(
    approval_id: int,
    review: ApprovalReviewRequest,
    db=Depends(get_db),
):
    """
    Approve a pending request.
    Creates a JitGrant and links it to the approval.
    Returns 409 if already reviewed, 410 if expired.
    """
    approval = db.query(Approval).filter_by(id=approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    now = datetime.now(timezone.utc)

    if approval.status != ApprovalStatus.pending:
        raise HTTPException(status_code=409, detail=f"Approval already in status '{approval.status.value}'")

    if approval.expires_at <= now:
        approval.status = ApprovalStatus.expired
        db.commit()
        raise HTTPException(status_code=410, detail="Approval request has expired")

    ttl = review.override_ttl_minutes if review.override_ttl_minutes else approval.ttl_minutes
    ttl = max(5, min(ttl, 1440))  # clamp 5m–24h

    grant = JitGrant(
        tenant_id=approval.tenant_id,
        principal_id=approval.principal_id,
        scope=approval.scope,
        expires_at=now + timedelta(minutes=ttl),
        reason=approval.reason or "Approved via approval workflow",
        created_by=review.reviewed_by,
    )
    db.add(grant)
    db.flush()

    approval.status = ApprovalStatus.approved
    approval.reviewed_by = review.reviewed_by
    approval.reviewed_at = now
    approval.jit_grant_id = grant.id

    _emit_audit(
        db,
        tenant_id=approval.tenant_id,
        actor=review.reviewed_by,
        action="approval_approved",
        resource=f"approval:{approval_id}",
        detail={
            "principal_id": approval.principal_id,
            "scope": approval.scope,
            "jit_grant_id": grant.id,
            "ttl_minutes": ttl,
        },
    )
    db.commit()
    db.refresh(approval)
    return ApprovalOut.model_validate(approval)


@router.post("/approvals/{approval_id}/deny", response_model=ApprovalOut)
def deny(
    approval_id: int,
    review: ApprovalReviewRequest,
    db=Depends(get_db),
):
    """Deny a pending approval request."""
    approval = db.query(Approval).filter_by(id=approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    if approval.status != ApprovalStatus.pending:
        raise HTTPException(status_code=409, detail=f"Approval already in status '{approval.status.value}'")

    now = datetime.now(timezone.utc)
    approval.status = ApprovalStatus.denied
    approval.reviewed_by = review.reviewed_by
    approval.reviewed_at = now

    _emit_audit(
        db,
        tenant_id=approval.tenant_id,
        actor=review.reviewed_by,
        action="approval_denied",
        resource=f"approval:{approval_id}",
        detail={"principal_id": approval.principal_id, "scope": approval.scope},
    )
    db.commit()
    db.refresh(approval)
    return ApprovalOut.model_validate(approval)
