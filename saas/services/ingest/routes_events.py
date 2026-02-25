"""
JSON event ingestion route.
Used by:
  - aiaap-ebpf-forwarder (Tetragon events)         source=ebpf
  - aiaap-k8s-audit-collector (K8s audit logs)     source=audit
  - aiaap-cloudtrail-forwarder (AWS CloudTrail)    source=cloud

POST /api/events
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException

from saas.services.shared.database import get_db
from saas.services.shared.models import RawEvent, EventSource, ConnectorInstance, ConnectorType
from saas.services.shared.schemas import IngestEventRequest, NormalizedEventOut, ConnectorInstanceOut
from saas.services.shared.auth import get_tenant
from saas.services.ingest.normalizer import normalize_ebpf_event, normalize_audit_event, normalize_cloud_event

router = APIRouter()
logger = structlog.get_logger()


def _upsert_connector(db, tenant_id: str, connector_type_str: str | None, instance_id: str | None) -> None:
    """Auto-register or update a connector instance when an event is received."""
    if not instance_id or not connector_type_str:
        return
    try:
        ct = ConnectorType(connector_type_str)
    except ValueError:
        return  # unknown connector type - ignore silently
    now = datetime.now(timezone.utc)
    inst = db.query(ConnectorInstance).filter_by(
        tenant_id=tenant_id, instance_id=instance_id
    ).first()
    if inst:
        inst.last_seen = now
        inst.events_1h = (inst.events_1h or 0) + 1
    else:
        db.add(ConnectorInstance(
            tenant_id=tenant_id,
            connector_type=ct,
            instance_id=instance_id,
            first_seen=now,
            last_seen=now,
            events_1h=1,
        ))


@router.post("/events", status_code=201)
def ingest_event(
    req: IngestEventRequest,
    tenant_id: str = Depends(get_tenant),
    db=Depends(get_db),
):
    """
    Accept a JSON event from an in-cluster sensor (eBPF, audit, CloudTrail).
    tenant_id is resolved by get_tenant() - when REQUIRE_API_KEY=true,
    it is derived from the API key record and cannot be spoofed by the caller.
    """
    # Override payload tenant_id with the authenticated one
    effective_tenant_id = tenant_id

    raw_connector_type = None
    if req.connector_type:
        try:
            raw_connector_type = ConnectorType(req.connector_type)
        except ValueError:
            pass  # unknown connector type - store event without connector metadata

    raw = RawEvent(
        tenant_id=effective_tenant_id,
        source=req.source,
        payload=req.payload,
        connector_type=raw_connector_type,
        connector_instance_id=req.connector_instance_id,
    )
    db.add(raw)
    db.commit()
    db.refresh(raw)

    normalized = None
    if req.source == EventSource.ebpf:
        normalized = normalize_ebpf_event(
            req.payload, effective_tenant_id, raw.id, db,
            connector_type=req.connector_type,
            connector_instance_id=req.connector_instance_id,
        )
    elif req.source == EventSource.audit:
        normalized = normalize_audit_event(
            req.payload, effective_tenant_id, raw.id, db,
            connector_type=req.connector_type,
            connector_instance_id=req.connector_instance_id,
        )
    elif req.source == EventSource.cloud:
        normalized = normalize_cloud_event(
            req.payload, effective_tenant_id, raw.id, db,
            connector_type=req.connector_type,
            connector_instance_id=req.connector_instance_id,
        )
    else:
        logger.warning("unknown_event_source", source=req.source)

    _upsert_connector(db, effective_tenant_id, req.connector_type, req.connector_instance_id)
    db.commit()

    logger.info(
        "event_ingested",
        source=req.source,
        raw_id=raw.id,
        normalized_id=normalized.id if normalized else None,
        connector=req.connector_instance_id,
    )
    return {
        "raw_event_id": raw.id,
        "normalized_event_id": normalized.id if normalized else None,
        "status": "accepted",
    }


@router.get("/events", response_model=list[NormalizedEventOut])
def list_normalized_events(
    tenant_id: str = "default",
    source: str | None = None,
    limit: int = 200,
    db=Depends(get_db),
):
    """List recent normalized events. Used by dashboard and integration tests."""
    from saas.services.shared.models import NormalizedEvent

    q = db.query(NormalizedEvent).filter(NormalizedEvent.tenant_id == tenant_id)
    if source:
        q = q.filter(NormalizedEvent.source == source)
    rows = q.order_by(NormalizedEvent.timestamp.desc()).limit(limit).all()
    return [NormalizedEventOut.model_validate(r) for r in rows]


@router.get("/events/{event_id}", response_model=NormalizedEventOut)
def get_normalized_event(event_id: int, db=Depends(get_db)):
    """Fetch a single normalized event by ID. Used by the findings evidence panel."""
    from saas.services.shared.models import NormalizedEvent
    from fastapi import HTTPException

    row = db.query(NormalizedEvent).filter(NormalizedEvent.id == event_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return NormalizedEventOut.model_validate(row)


@router.get("/connectors", response_model=list[ConnectorInstanceOut])
def list_connectors(tenant_id: str = "default", db=Depends(get_db)):
    """
    List all registered connector instances for a tenant.
    Connectors auto-register when they send their first event to POST /api/events
    or when OTel spans arrive at POST /otlp/v1/traces.
    Used by the Connectors dashboard page.
    """
    rows = db.query(ConnectorInstance).filter_by(tenant_id=tenant_id).order_by(
        ConnectorInstance.last_seen.desc()
    ).all()
    return [ConnectorInstanceOut.model_validate(r) for r in rows]
