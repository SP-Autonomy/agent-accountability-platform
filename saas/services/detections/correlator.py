"""
AIAAP Multi-Signal Correlation Engine
--------------------------------------
Runs as a background asyncio task. Every CORRELATION_INTERVAL seconds:
1. Queries NormalizedEvents from the last 60 seconds
2. Groups by trace_id (OTel) and by source (eBPF/audit/cloud)
3. Applies each of 7 rule modules
4. Deduplicates Findings (same scenario_id within 5 minutes)
5. Persists new Findings to the database
"""

import asyncio
from datetime import datetime, timezone, timedelta

import structlog

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import NormalizedEvent, Finding

from saas.services.detections.rules import (
    rule_ssrf,
    rule_rbac,
    rule_stolen_token,
    rule_shadow_route,
    rule_overbroad,
    rule_confused_deputy,
    rule_iam_escalation,
    rule_runtime,
)

logger = structlog.get_logger()

RULES = [
    rule_ssrf.check,
    rule_rbac.check,
    rule_stolen_token.check,
    rule_shadow_route.check,
    rule_overbroad.check,
    rule_confused_deputy.check,
    rule_iam_escalation.check,   # cloud.iam.* events from CloudTrail connector
    rule_runtime.check,          # AIRS Runtime Pack: injection + PII detections
]

WINDOW_SECONDS      = 60    # events to correlate within
DEDUP_MINUTES       = 5     # suppress duplicate global (no trace_id) findings
DEDUP_TRACE_SECONDS = 90    # suppress duplicate per-trace findings for this period


def _derive_signal_source(events: list) -> str:
    """
    Derive the signal_source for a finding from its triggering events.
    If ANY event is 'lab', the finding is 'lab'; otherwise 'operational'.
    This ensures lab scenario findings never contaminate operational metrics.
    """
    for ev in events:
        if getattr(ev, "signal_source", "operational") == "lab":
            return "lab"
    return "operational"


async def run_correlation_loop(interval_seconds: int = 10):
    """Long-running coroutine. Started during FastAPI lifespan."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await asyncio.get_event_loop().run_in_executor(None, _correlate_once)
        except Exception as exc:
            logger.error("correlation_loop_error", error=str(exc))


def _correlate_once():
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=WINDOW_SECONDS)
        recent: list[NormalizedEvent] = (
            db.query(NormalizedEvent)
              .filter(NormalizedEvent.timestamp >= cutoff)
              .order_by(NormalizedEvent.timestamp.asc())
              .all()
        )

        if not recent:
            return

        # Group events by trace_id for OTel-correlated detection
        by_trace: dict[str, list] = {}
        no_trace: list = []
        for ev in recent:
            if ev.trace_id:
                by_trace.setdefault(ev.trace_id, []).append(ev)
            else:
                no_trace.append(ev)

        findings_created = 0

        # Apply rules to trace groups (OTel-correlated events)
        for trace_id, events in by_trace.items():
            for rule_fn in RULES:
                finding = rule_fn(events, db)
                if finding:
                    # Stamp the trace_id so dedup is per-trace, not global
                    if not finding.trace_id:
                        finding.trace_id = trace_id
                    # Inherit signal_source from events: if any event is lab, finding is lab
                    if not hasattr(finding, "signal_source") or not finding.signal_source:
                        finding.signal_source = _derive_signal_source(events)
                    if _should_persist(finding, db):
                        db.add(finding)
                        db.commit()
                        findings_created += 1
                        logger.info(
                            "finding_created",
                            scenario=finding.scenario_id,
                            signal_source=finding.signal_source,
                            trace_id=trace_id,
                            severity=finding.severity,
                            status=finding.status,
                        )

        # Apply rules to ungrouped events (eBPF/audit-only detections)
        if no_trace:
            for rule_fn in RULES:
                finding = rule_fn(no_trace, db)
                if finding:
                    if not hasattr(finding, "signal_source") or not finding.signal_source:
                        finding.signal_source = _derive_signal_source(no_trace)
                    if _should_persist(finding, db):
                        db.add(finding)
                        db.commit()
                        findings_created += 1
                        logger.info(
                            "finding_created_ungrouped",
                            scenario=finding.scenario_id,
                            signal_source=finding.signal_source,
                            severity=finding.severity,
                            status=finding.status,
                        )

        if findings_created:
            logger.info("correlation_cycle_complete", new_findings=findings_created, events_processed=len(recent))

    except Exception as exc:
        logger.error("correlate_once_error", error=str(exc))
        db.rollback()
    finally:
        db.close()


def _should_persist(finding: Finding, db) -> bool:
    """Return True if this finding is not a duplicate within DEDUP_MINUTES.

    When trace_id is available, dedup is scoped to (scenario_id, trace_id) so
    different agent traces that trigger the same rule are each persisted - this
    allows sequential scenario runs to each produce their own finding.
    When no trace_id is set (e.g. eBPF/audit rules), fall back to global
    (scenario_id, tenant_id) dedup to suppress rapid re-fires.
    """
    if not finding.scenario_id:
        return True

    now = datetime.now(timezone.utc)

    if finding.trace_id:
        # Per-trace dedup: short window - prevents re-firing within a few correlator
        # cycles but allows the same scenario to run again after DEDUP_TRACE_SECONDS.
        dedup_cutoff = now - timedelta(seconds=DEDUP_TRACE_SECONDS)
        existing = (
            db.query(Finding)
              .filter(
                  Finding.scenario_id == finding.scenario_id,
                  Finding.tenant_id   == finding.tenant_id,
                  Finding.trace_id    == finding.trace_id,
                  Finding.created_at  >= dedup_cutoff,
              )
              .first()
        )
    else:
        # Global dedup: longer window for eBPF/audit/cloud findings without a trace
        dedup_cutoff = now - timedelta(minutes=DEDUP_MINUTES)
        existing = (
            db.query(Finding)
              .filter(
                  Finding.scenario_id == finding.scenario_id,
                  Finding.tenant_id   == finding.tenant_id,
                  Finding.created_at  >= dedup_cutoff,
              )
              .first()
        )

    return existing is None
