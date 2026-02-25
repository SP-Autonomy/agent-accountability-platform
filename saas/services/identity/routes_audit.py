"""
AuditLog query routes.
Provides read-only access to the immutable audit trail.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query

from saas.services.shared.database import get_db
from saas.services.shared.models import AuditLog

router = APIRouter()


@router.get("/audit")
def list_audit_logs(
    tenant_id: str = "default",
    action: Optional[str] = None,
    resource: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db=Depends(get_db),
):
    """
    Query the audit log.
    Supports filtering by action (e.g. "jit_grant_created") and resource prefix (e.g. "jit_grant:").
    """
    q = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if action:
        q = q.filter(AuditLog.action == action)
    if resource:
        q = q.filter(AuditLog.resource.like(f"{resource}%"))
    rows = q.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id":        r.id,
            "actor":     r.actor,
            "action":    r.action,
            "resource":  r.resource,
            "detail":    r.detail,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]
