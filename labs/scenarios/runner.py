"""
AIAAP Scenario Runner

Orchestrates:
  setup -> execute -> poll findings -> teardown -> evaluate -> update DB
Called as a background task from the detections service and can be run via CLI.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import httpx
import structlog
from sqlalchemy.exc import SQLAlchemyError

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import ScenarioRun, ScenarioStatus

from labs.scenarios.base import BaseScenario

logger = structlog.get_logger()

DETECTIONS_URL = os.getenv("DETECTIONS_URL", "http://localhost:8200")
FINDING_POLL_INTERVAL = 5
FINDING_POLL_TIMEOUT = 120


class ScenarioRunner:
    def __init__(
        self,
        scenario: BaseScenario,
        run_id: int | None = None,
        detections_url: str = DETECTIONS_URL,
    ):
        self.scenario = scenario
        self.run_id = run_id
        self.detections_url = detections_url

    def run(self) -> Optional[ScenarioRun]:
        db = SessionLocal()
        run: Optional[ScenarioRun] = None

        try:
            # Create or load run record
            if self.run_id:
                run = db.query(ScenarioRun).filter_by(id=self.run_id).first()

            if not run:
                run = ScenarioRun(
                    scenario_id=self.scenario.scenario_id,
                    status=ScenarioStatus.running,
                    start_at=datetime.now(timezone.utc),
                    expected={"outcome": getattr(self.scenario.expected_outcome, "value", str(self.scenario.expected_outcome))},
                )
                db.add(run)
                db.commit()
                db.refresh(run)

            logger.info("scenario_setup", scenario=self.scenario.scenario_id)
            self.scenario.setup()

            logger.info("scenario_execute", scenario=self.scenario.scenario_id)
            execute_start = datetime.now(timezone.utc)
            self.scenario.execute()

            findings = self._poll_for_findings(execute_start)

            logger.info("scenario_teardown", scenario=self.scenario.scenario_id)
            self.scenario.teardown()

            result = self.scenario.evaluate(findings, [])

            # Update run record
            run.status = ScenarioStatus.complete
            run.end_at = datetime.now(timezone.utc)
            run.verdict = result.verdict
            run.observed_refs = result.finding_ids
            run.expected = {"outcome": getattr(self.scenario.expected_outcome, "value", str(self.scenario.expected_outcome))}
            db.commit()
            db.refresh(run)  # reload all columns so attributes survive session.close()

            logger.info(
                "scenario_complete",
                scenario=self.scenario.scenario_id,
                verdict=result.verdict,
                findings=len(findings),
            )
            return run

        except SQLAlchemyError as exc:
            # DB-level failure (like your "postgres host name could not translate")
            logger.error("scenario_run_db_failed", scenario=self.scenario.scenario_id, error=str(exc))
            try:
                db.rollback()
            except Exception:
                pass
            return None

        except Exception as exc:
            logger.error("scenario_run_failed", scenario=self.scenario.scenario_id, error=str(exc))
            try:
                db.rollback()
            except Exception:
                pass

            # Try to mark run as failed only if it exists and is persistent.
            try:
                if run is not None and getattr(run, "id", None) is not None:
                    run.status = ScenarioStatus.failed
                    run.end_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(run)  # reload so attributes survive session.close()
            except Exception as exc2:
                logger.error("scenario_run_failed_update", scenario=self.scenario.scenario_id, error=str(exc2))
                try:
                    db.rollback()
                except Exception:
                    pass

            return run

        finally:
            db.close()

    def _poll_for_findings(self, since: datetime) -> list[dict[str, Any]]:
        """Poll for ALL findings created after `since`.

        Fetches without a scenario_id filter so that findings from any rule
        (overbroad_permissions, ssrf_metadata, confused_deputy, etc.) are
        returned and the scenario's own evaluate() can pick the relevant ones.
        Local filtering by created_at ensures only this run's findings are
        considered, preventing bleed-in from prior scenario runs.
        """
        deadline = time.time() + FINDING_POLL_TIMEOUT
        # Give the correlator at least one full cycle before starting to poll
        time.sleep(FINDING_POLL_INTERVAL)

        since_iso = since.isoformat()

        while time.time() < deadline:
            try:
                resp = httpx.get(
                    f"{self.detections_url}/api/findings",
                    params={"since": since_iso, "limit": 200},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data:
                        logger.info(
                            "findings_polled",
                            scenario=self.scenario.scenario_id,
                            count=len(data),
                        )
                        return data
            except Exception:
                pass

            time.sleep(FINDING_POLL_INTERVAL)

        return []