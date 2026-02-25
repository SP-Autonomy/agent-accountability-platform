"""
OTLP HTTP receiver route.
The OTel Collector is configured to export to:
  http://aiaap-ingest:8100/otlp/v1/traces
"""

import structlog
from fastapi import APIRouter, Request, Depends, BackgroundTasks

from saas.services.shared.database import get_db
from saas.services.shared.models import RawEvent, EventSource, ConnectorType
from saas.services.shared.auth import get_tenant
from saas.services.ingest.normalizer import normalize_otel_payload
from saas.services.ingest.routes_events import _upsert_connector

router = APIRouter()
logger = structlog.get_logger()


@router.post("/v1/traces", status_code=200)
async def receive_traces(
    request: Request,
    background_tasks: BackgroundTasks,
    tenant_id: str = Depends(get_tenant),
    db=Depends(get_db),
):
    """
    Receives OTLP HTTP trace exports from the OTel Collector.
    Accepts both protobuf (application/x-protobuf) and JSON (application/json).
    Stores raw payload, then normalizes in background.
    tenant_id is resolved by get_tenant() - derived from API key when in production mode.
    Auto-registers a k8s_otel connector instance on first span receipt.
    """
    body         = await request.body()
    content_type = request.headers.get("content-type", "application/json")

    # Connector instance ID: prefer X-AIAAP-Connector-Instance header, else "otel-default"
    connector_instance_id = request.headers.get("x-aiaap-connector-instance", "otel-default")

    raw = RawEvent(
        tenant_id=tenant_id,
        source=EventSource.otel,
        payload={
            "tenant_id": tenant_id,
            "content_type": content_type,
            "body_size_bytes": len(body),
        },
        connector_type=ConnectorType.k8s_otel,
        connector_instance_id=connector_instance_id,
    )
    db.add(raw)
    db.commit()
    db.refresh(raw)

    # Track the k8s_otel connector - auto-registers on first span arrival
    _upsert_connector(db, tenant_id, "k8s_otel", connector_instance_id)
    db.commit()

    # Normalization runs in background so we can respond immediately to the collector
    background_tasks.add_task(normalize_otel_payload, raw.id, body, content_type)

    logger.info("otlp_traces_received", raw_event_id=raw.id, bytes=len(body), tenant=tenant_id,
                connector=connector_instance_id)
    return {"partialSuccess": {}}
