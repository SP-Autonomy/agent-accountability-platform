"""
AIAAP Ingest Service (port 8100)
---------------------------------
Accepts telemetry from two sources:
  1. OTel Collector via OTLP HTTP  → POST /otlp/v1/traces
  2. eBPF forwarder / audit collector → POST /api/events

All incoming payloads are stored as RawEvent and then normalized
into NormalizedEvent + ToolUsage records by the normalizer.
"""

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from saas.services.shared.database import create_all_tables

logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("aiaap_ingest_starting")
    create_all_tables()
    logger.info("aiaap_ingest_tables_ready")
    yield
    logger.info("aiaap_ingest_stopping")


app = FastAPI(
    title="AIAAP Ingest Service",
    version="0.1.0",
    description="Receives OTel spans, eBPF events, and audit logs. Normalizes and stores them.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
from saas.services.ingest.routes_otlp   import router as otlp_router    # noqa: E402
from saas.services.ingest.routes_events import router as events_router  # noqa: E402

app.include_router(otlp_router,   prefix="/otlp",      tags=["OTLP"])
app.include_router(events_router, prefix="/api",        tags=["Events"])


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "service": "aiaap-ingest", "version": "0.1.0"}


@app.get("/api/tool-usages", tags=["Events"])
def list_tool_usages(
    limit: int = 500,
    tenant_id: str = "default",
    signal_source: str | None = None,
):
    """
    List recent ToolUsage records for the dashboard Tool Usage page.
    Use signal_source=operational to exclude lab scenario tool calls.
    Use signal_source=lab for Assurance Labs view.
    Default (no filter) returns all for backwards compatibility.
    """
    from saas.services.shared.database import SessionLocal
    from saas.services.shared.models import ToolUsage
    from saas.services.shared.schemas import ToolUsageOut

    db = SessionLocal()
    try:
        q = (
            db.query(ToolUsage)
              .filter(ToolUsage.tenant_id == tenant_id)
        )
        if signal_source:
            q = q.filter(ToolUsage.signal_source == signal_source)
        rows = q.order_by(ToolUsage.timestamp.desc()).limit(limit).all()
        return [ToolUsageOut.model_validate(r) for r in rows]
    finally:
        db.close()
