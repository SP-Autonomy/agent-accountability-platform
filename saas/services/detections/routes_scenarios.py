"""
ScenarioRun API routes.
POST /api/scenario-runs  - triggers a scenario run (async via background task)
GET  /api/scenario-runs  - list all runs
GET  /api/scenario-runs/{id} - get a specific run
"""

import asyncio
import logging
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from saas.services.shared.database import get_db
from saas.services.shared.models import ScenarioRun, ScenarioStatus
from saas.services.shared.schemas import ScenarioRunCreate, ScenarioRunOut

router = APIRouter()
logger = structlog.get_logger()

VALID_SCENARIOS = {
    "ssrf_metadata",
    "rbac_escalation_misconfig",
    "stolen_token_usage",
    "shadow_tool_route",
    "overbroad_permissions",
    "confused_deputy",
}


def _run_scenario_background(run_id: int, scenario_id: str):
    """
    Background task: delegates to the scenarios package runner.
    The runner handles setup, execute, poll, teardown, evaluate.
    Falls back gracefully if kubectl is unavailable (compose-only mode).
    """
    try:
        from labs.scenarios.runner import ScenarioRunner
        from labs.scenarios import get_scenario_class

        scenario_class = get_scenario_class(scenario_id)
        if not scenario_class:
            logger.warning("scenario_not_found", scenario_id=scenario_id)
            _mark_failed(run_id)
            return

        runner = ScenarioRunner(scenario=scenario_class(), run_id=run_id)
        runner.run()
    except Exception as exc:
        logger.error("scenario_run_error", scenario_id=scenario_id, error=str(exc))
        _mark_failed(run_id)


def _mark_failed(run_id: int):
    from saas.services.shared.database import SessionLocal
    db = SessionLocal()
    try:
        run = db.query(ScenarioRun).filter_by(id=run_id).first()
        if run:
            run.status = ScenarioStatus.failed
            run.end_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


@router.post("/scenario-runs", response_model=ScenarioRunOut, status_code=201)
def trigger_scenario_run(
    req: ScenarioRunCreate,
    background_tasks: BackgroundTasks,
    db=Depends(get_db),
):
    if req.scenario_id not in VALID_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{req.scenario_id}'. Valid: {sorted(VALID_SCENARIOS)}",
        )

    run = ScenarioRun(
        scenario_id=req.scenario_id,
        tenant_id=req.tenant_id,
        status=ScenarioStatus.running,
        start_at=datetime.now(timezone.utc),
        expected={"outcome": "detected"},  # default; overridden by scenario class
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    background_tasks.add_task(_run_scenario_background, run.id, req.scenario_id)
    logger.info("scenario_run_started", run_id=run.id, scenario=req.scenario_id)
    return ScenarioRunOut.model_validate(run)


@router.get("/scenario-runs", response_model=list[ScenarioRunOut])
def list_scenario_runs(
    tenant_id:   str       = "default",
    scenario_id: str | None = None,
    db=Depends(get_db),
):
    q = db.query(ScenarioRun).filter(ScenarioRun.tenant_id == tenant_id)
    if scenario_id:
        q = q.filter(ScenarioRun.scenario_id == scenario_id)
    rows = q.order_by(ScenarioRun.start_at.desc()).limit(100).all()
    return [ScenarioRunOut.model_validate(r) for r in rows]


@router.get("/scenario-runs/{run_id}", response_model=ScenarioRunOut)
def get_scenario_run(run_id: int, db=Depends(get_db)):
    row = db.query(ScenarioRun).filter_by(id=run_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="ScenarioRun not found")
    return ScenarioRunOut.model_validate(row)
