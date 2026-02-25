"""
Finding API routes.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends

from saas.services.shared.database import get_db
from saas.services.shared.models import Finding
from saas.services.shared.schemas import FindingOut

router = APIRouter()


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    tenant_id:    str            = "default",
    severity:     Optional[str]  = None,
    status:       Optional[str]  = None,
    scenario_id:  Optional[str]  = None,
    since:        Optional[str]  = None,
    signal_source: Optional[str] = None,
    limit:        int            = 200,
    db=Depends(get_db),
):
    """
    List findings. Use signal_source=operational to exclude lab findings,
    or signal_source=lab to see only Assurance Labs findings.
    Default (no filter) returns all findings for backwards compatibility.
    """
    q = db.query(Finding).filter(Finding.tenant_id == tenant_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if scenario_id:
        q = q.filter(Finding.scenario_id == scenario_id)
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            q = q.filter(Finding.created_at >= since_dt)
        except ValueError:
            pass
    if signal_source:
        q = q.filter(Finding.signal_source == signal_source)
    rows = q.order_by(Finding.created_at.desc()).limit(limit).all()
    return [FindingOut.model_validate(r) for r in rows]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db=Depends(get_db)):
    from fastapi import HTTPException
    row = db.query(Finding).filter_by(id=finding_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingOut.model_validate(row)
