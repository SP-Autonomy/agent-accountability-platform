"""
AIAAP Detections Service (port 8200)
--------------------------------------
Runs a background correlation loop that applies 6 detection rules across
recently ingested NormalizedEvents, and exposes Finding + ScenarioRun endpoints.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from saas.services.shared.database import create_all_tables

logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()

CORRELATION_INTERVAL = int(os.getenv("CORRELATION_INTERVAL_SECONDS", "10"))
BEHAVIORAL_INTERVAL  = int(os.getenv("BEHAVIORAL_INTERVAL_SECONDS",  "300"))  # 5 minutes
INTENT_INTERVAL      = int(os.getenv("INTENT_INTERVAL_SECONDS",      "120"))  # 2 minutes


async def _run_behavioral_loop(interval: int) -> None:
    """Background loop: update baselines + score principals every `interval` seconds."""
    # Initial delay so the correlation loop has time to produce some events first
    await asyncio.sleep(interval)
    while True:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                _call_behavioral_analysis,
            )
        except Exception as exc:
            logger.error("behavioral_loop_error", error=str(exc))
        await asyncio.sleep(interval)


def _call_behavioral_analysis() -> None:
    from saas.services.behavioural.anomaly_scoring import run_behavioral_analysis
    from saas.services.shared.database import SessionLocal
    from saas.services.shared.models import AgentPrincipal
    from saas.services.identity.posture import compute_risk_score
    from datetime import datetime, timezone

    run_behavioral_analysis()

    # After behavioral scoring, refresh risk scores for all principals so the
    # dashboard shows up-to-date values without requiring manual "Refresh Risk Score"
    db = SessionLocal()
    try:
        principals = db.query(AgentPrincipal).all()
        for p in principals:
            try:
                score = compute_risk_score(p, db)
                p.risk_score = score
                p.risk_score_updated_at = datetime.now(timezone.utc)
            except Exception as exc:
                logger.warning("risk_refresh_error", principal_id=p.id, error=str(exc))
        db.commit()
        logger.info("risk_scores_refreshed", count=len(principals))
    except Exception as exc:
        logger.error("risk_refresh_loop_error", error=str(exc))
        db.rollback()
    finally:
        db.close()


async def _run_intent_loop(interval: int) -> None:
    """Background loop: intent envelope violations + drift + blast radius every `interval` seconds."""
    # Offset start so it doesn't run simultaneously with the behavioral loop
    await asyncio.sleep(interval // 2)
    while True:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _call_intent_analysis)
        except Exception as exc:
            logger.error("intent_loop_error", error=str(exc))
        await asyncio.sleep(interval)


def _call_intent_analysis() -> None:
    from saas.services.behavioural.intent_envelope import run_envelope_violation_scan
    from saas.services.behavioural.drift_engine    import run_drift_analysis
    from saas.services.behavioural.blast_radius    import run_blast_radius_analysis

    tenant_id  = os.getenv("TENANT_ID", "default")
    violations = run_envelope_violation_scan(tenant_id)
    drifts     = run_drift_analysis(tenant_id)
    blasts     = run_blast_radius_analysis(tenant_id)
    if violations or drifts or blasts:
        logger.info(
            "intent_analysis_complete",
            violations=violations,
            drift_snapshots=drifts,
            blast_snapshots=blasts,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("aiaap_detections_starting")
    create_all_tables()
    logger.info("aiaap_detections_tables_ready")

    # Start the correlation loop as a background task
    from saas.services.detections.correlator import run_correlation_loop
    corr_task = asyncio.create_task(run_correlation_loop(CORRELATION_INTERVAL))
    logger.info("correlation_loop_started", interval=CORRELATION_INTERVAL)

    # Start the behavioral analysis loop (baseline updates + anomaly scoring)
    beh_task = asyncio.create_task(_run_behavioral_loop(BEHAVIORAL_INTERVAL))
    logger.info("behavioral_loop_started", interval=BEHAVIORAL_INTERVAL)

    # Start the intent integrity loop (envelope violations + drift + blast radius)
    intent_task = asyncio.create_task(_run_intent_loop(INTENT_INTERVAL))
    logger.info("intent_loop_started", interval=INTENT_INTERVAL)

    yield

    corr_task.cancel()
    beh_task.cancel()
    intent_task.cancel()
    logger.info("aiaap_detections_stopping")


app = FastAPI(
    title="AIAAP Detections Service",
    version="0.1.0",
    description="Multi-signal correlation engine that produces security Findings.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from saas.services.detections.routes_findings  import router as findings_router   # noqa: E402
from saas.services.detections.routes_scenarios import router as scenarios_router  # noqa: E402
from saas.services.detections.routes_intent    import router as intent_router     # noqa: E402

app.include_router(findings_router,  prefix="/api", tags=["Findings"])
app.include_router(scenarios_router, prefix="/api", tags=["Scenarios"])
app.include_router(intent_router,    prefix="/api", tags=["Intent"])


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "service": "aiaap-detections", "version": "0.1.0"}
