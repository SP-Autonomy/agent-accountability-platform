"""
AgentPrincipal CRUD routes with pagination and optional filters.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from saas.services.shared.database import get_db
from saas.services.shared.models import AgentPrincipal
from saas.services.shared.schemas import AgentPrincipalCreate, AgentPrincipalOut
from saas.services.identity.posture import compute_risk_score, compute_risk_breakdown

router = APIRouter()


@router.get("/principals", response_model=list[AgentPrincipalOut])
def list_principals(
    tenant_id: str = "default",
    namespace: Optional[str] = None,
    service_account: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db=Depends(get_db),
):
    q = (
        db.query(AgentPrincipal)
          .filter(AgentPrincipal.tenant_id == tenant_id)
    )
    if namespace:
        q = q.filter(AgentPrincipal.namespace == namespace)
    if service_account:
        q = q.filter(AgentPrincipal.service_account == service_account)
    rows = q.order_by(AgentPrincipal.last_seen.desc()).offset(offset).limit(limit).all()
    return [AgentPrincipalOut.model_validate(r) for r in rows]


@router.get("/principals/{principal_id}", response_model=AgentPrincipalOut)
def get_principal(principal_id: int, db=Depends(get_db)):
    row = db.query(AgentPrincipal).filter_by(id=principal_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Principal not found")
    return AgentPrincipalOut.model_validate(row)


@router.post("/principals", response_model=AgentPrincipalOut, status_code=201)
def create_principal(req: AgentPrincipalCreate, db=Depends(get_db)):
    existing = db.query(AgentPrincipal).filter_by(name=req.name, tenant_id=req.tenant_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Principal already exists")
    row = AgentPrincipal(**req.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return AgentPrincipalOut.model_validate(row)


@router.post("/principals/{principal_id}/refresh-risk")
def refresh_risk(principal_id: int, db=Depends(get_db)):
    """Recompute risk score for a principal and persist it."""
    row = db.query(AgentPrincipal).filter_by(id=principal_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Principal not found")
    score = compute_risk_score(row, db)
    row.risk_score = score
    row.risk_score_updated_at = datetime.now(timezone.utc)
    db.commit()
    return {
        "principal_id": principal_id,
        "risk_score": score,
        "risk_score_updated_at": row.risk_score_updated_at.isoformat(),
    }


@router.get("/principals/{principal_id}/risk-breakdown")
def risk_breakdown(principal_id: int, db=Depends(get_db)):
    """
    Return a structured breakdown of how the risk score was computed.
    Includes per-factor points, provenance, and signal_source filter applied.
    This endpoint always uses operational signals - lab signals are excluded.
    """
    row = db.query(AgentPrincipal).filter_by(id=principal_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Principal not found")
    return compute_risk_breakdown(row, db)


@router.delete("/principals/{principal_id}", status_code=204)
def delete_principal(principal_id: int, db=Depends(get_db)):
    row = db.query(AgentPrincipal).filter_by(id=principal_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Principal not found")
    db.delete(row)
    db.commit()
