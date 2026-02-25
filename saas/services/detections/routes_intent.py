"""
Intent Integrity API routes.
Exposes IntentEnvelope, DriftSnapshot, and BlastRadiusSnapshot records
for dashboard consumption.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query

from saas.services.shared.database import get_db
from saas.services.shared.models import (
    IntentEnvelope, DriftSnapshot, BlastRadiusSnapshot,
    AgentPrincipal, Finding,
)

router = APIRouter()


# ── Intent Envelopes ──────────────────────────────────────────────────────────

@router.get("/intent/envelopes")
def list_envelopes(
    tenant_id:    str           = "default",
    principal_id: Optional[int] = None,
    active_only:  bool          = True,
    limit:        int           = 200,
    db=Depends(get_db),
):
    q = db.query(IntentEnvelope).filter(IntentEnvelope.tenant_id == tenant_id)
    if active_only:
        q = q.filter(IntentEnvelope.active == True)  # noqa: E712
    if principal_id is not None:
        q = q.filter(IntentEnvelope.principal_id == principal_id)
    rows = q.order_by(IntentEnvelope.created_at.desc()).limit(limit).all()

    result = []
    for env in rows:
        principal = db.query(AgentPrincipal).filter_by(id=env.principal_id).first()
        result.append({
            "id":                   env.id,
            "tenant_id":            env.tenant_id,
            "principal_id":         env.principal_id,
            "principal_name":       principal.name if principal else None,
            "trace_id":             env.trace_id,
            "session_id":           env.session_id,
            "intent_label":         env.intent_label,
            "allowed_tools":        env.allowed_tools or [],
            "allowed_destinations": env.allowed_destinations or [],
            "allowed_data_classes": env.allowed_data_classes or [],
            "max_privilege_tier":   env.max_privilege_tier,
            "created_at":           env.created_at.isoformat() if env.created_at else None,
            "expires_at":           env.expires_at.isoformat() if env.expires_at else None,
            "created_by":           env.created_by,
            "active":               env.active,
        })
    return result


@router.post("/intent/envelopes")
def create_envelope(body: dict, db=Depends(get_db)):
    """Create an IntentEnvelope via the UI (created_by='ui')."""
    from saas.services.behavioural.intent_envelope import upsert_envelope_from_sdk
    env = upsert_envelope_from_sdk(
        principal_id  = body["principal_id"],
        tenant_id     = body.get("tenant_id", "default"),
        trace_id      = body.get("trace_id"),
        intent_label  = body.get("intent_label", "ui-defined"),
        allowed_tools = body.get("allowed_tools", []),
        allowed_dests = body.get("allowed_destinations", []),
        max_privilege = body.get("max_privilege_tier", "low"),
        db            = db,
        created_by    = "ui",
    )
    db.commit()
    return {"id": env.id, "intent_label": env.intent_label}


# ── Drift Snapshots ───────────────────────────────────────────────────────────

@router.get("/intent/drift-snapshots")
def list_drift_snapshots(
    tenant_id:    str           = "default",
    principal_id: Optional[int] = None,
    hours:        int           = 24,
    limit:        int           = 500,
    db=Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = (
        db.query(DriftSnapshot)
        .filter(DriftSnapshot.tenant_id == tenant_id)
        .filter(DriftSnapshot.created_at >= cutoff)
    )
    if principal_id is not None:
        q = q.filter(DriftSnapshot.principal_id == principal_id)
    rows = q.order_by(DriftSnapshot.created_at.asc()).limit(limit).all()

    result = []
    for snap in rows:
        principal = db.query(AgentPrincipal).filter_by(id=snap.principal_id).first()
        result.append({
            "id":             snap.id,
            "tenant_id":      snap.tenant_id,
            "principal_id":   snap.principal_id,
            "principal_name": principal.name if principal else None,
            "window_start":   snap.window_start.isoformat() if snap.window_start else None,
            "window_end":     snap.window_end.isoformat()   if snap.window_end   else None,
            "drift_score":    snap.drift_score,
            "metrics":        snap.metrics or {},
            "created_at":     snap.created_at.isoformat() if snap.created_at else None,
        })
    return result


# ── Blast Radius Snapshots ────────────────────────────────────────────────────

@router.get("/intent/blast-snapshots")
def list_blast_snapshots(
    tenant_id:    str           = "default",
    principal_id: Optional[int] = None,
    hours:        int           = 24,
    limit:        int           = 500,
    db=Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = (
        db.query(BlastRadiusSnapshot)
        .filter(BlastRadiusSnapshot.tenant_id == tenant_id)
        .filter(BlastRadiusSnapshot.created_at >= cutoff)
    )
    if principal_id is not None:
        q = q.filter(BlastRadiusSnapshot.principal_id == principal_id)
    rows = q.order_by(BlastRadiusSnapshot.created_at.asc()).limit(limit).all()

    result = []
    for snap in rows:
        principal = db.query(AgentPrincipal).filter_by(id=snap.principal_id).first()
        result.append({
            "id":                        snap.id,
            "tenant_id":                 snap.tenant_id,
            "principal_id":              snap.principal_id,
            "principal_name":            principal.name if principal else None,
            "window_start":              snap.window_start.isoformat() if snap.window_start else None,
            "window_end":                snap.window_end.isoformat()   if snap.window_end   else None,
            "unique_destinations_count": snap.unique_destinations_count,
            "unique_resources_count":    snap.unique_resources_count,
            "privileged_edges_count":    snap.privileged_edges_count,
            "new_edges_count":           snap.new_edges_count,
            "blast_radius_score":        snap.blast_radius_score,
            "created_at":                snap.created_at.isoformat() if snap.created_at else None,
        })
    return result


# ── Intent summary per principal ──────────────────────────────────────────────

@router.get("/intent/summary")
def intent_summary(
    tenant_id: str = "default",
    hours:     int = 24,
    db=Depends(get_db),
):
    """Per-principal summary: latest drift score, blast score, violation count, active envelope."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    principals = db.query(AgentPrincipal).filter_by(tenant_id=tenant_id).all()

    rows = []
    for p in principals:
        # Latest drift snapshot
        latest_drift = (
            db.query(DriftSnapshot)
            .filter_by(principal_id=p.id, tenant_id=tenant_id)
            .filter(DriftSnapshot.created_at >= cutoff)
            .order_by(DriftSnapshot.created_at.desc())
            .first()
        )
        # Latest blast snapshot
        latest_blast = (
            db.query(BlastRadiusSnapshot)
            .filter_by(principal_id=p.id, tenant_id=tenant_id)
            .filter(BlastRadiusSnapshot.created_at >= cutoff)
            .order_by(BlastRadiusSnapshot.created_at.desc())
            .first()
        )
        # Violation count - simple count without JSON-contains to avoid backend
        # incompatibilities between SQLite and PostgreSQL JSON operators.
        try:
            violation_count = (
                db.query(Finding)
                .filter_by(tenant_id=tenant_id, scenario_id="intent_boundary")
                .filter(Finding.created_at >= cutoff)
                .count()
            )
        except Exception:
            violation_count = 0

        # Active envelope
        active_env = (
            db.query(IntentEnvelope)
            .filter_by(principal_id=p.id, tenant_id=tenant_id, active=True)
            .order_by(IntentEnvelope.created_at.desc())
            .first()
        )

        rows.append({
            "principal_id":       p.id,
            "principal_name":     p.name,
            "namespace":          p.namespace,
            "drift_score":        latest_drift.drift_score if latest_drift else None,
            "blast_radius_score": latest_blast.blast_radius_score if latest_blast else None,
            "active_envelope":    active_env.intent_label if active_env else None,
            "envelope_created_by": active_env.created_by if active_env else None,
        })
    return rows
