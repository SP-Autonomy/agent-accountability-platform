"""
Rule: runtime_detections
-------------------------
Promotes high/critical RuntimeDetection rows (created by aiaap-runtime service)
into Findings for the dashboard.

Checks the runtime_detections table for rows from the last 60s window with
severity >= high, and creates:
  - scenario_id "prompt_injection"  for detector_type = "injection"
  - scenario_id "pii_leakage"       for detector_type = "pii"

Does NOT touch NormalizedEvent - runtime detections are a separate signal path.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog

from saas.services.shared.models import (
    NormalizedEvent, RuntimeDetection, Finding, Severity, FindingStatus,
)

logger = structlog.get_logger()

_HIGH_SEVERITIES = {Severity.high, Severity.critical}

_SCENARIO_MAP = {
    "injection": "prompt_injection",
    "pii":       "pii_leakage",
}

_TITLES = {
    "injection": "Prompt Injection Detected in Agent Content",
    "pii":       "PII Leakage Detected in Agent Content",
}


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    """
    Called by correlator on every correlation cycle.
    Queries RuntimeDetection rows independently (ignores the events list -
    runtime detections come from the submit API, not OTel spans).
    Returns the most severe unaddressed detection as a Finding, or None.
    """
    if not events:
        return None

    # Use the tenant_id from the current event batch
    tenant_id = events[0].tenant_id

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)

    # Find any high/critical runtime detection from the last 60s window
    detection: RuntimeDetection | None = (
        db.query(RuntimeDetection)
          .filter(
              RuntimeDetection.tenant_id == tenant_id,
              RuntimeDetection.timestamp >= cutoff,
              RuntimeDetection.severity.in_(_HIGH_SEVERITIES),
          )
          .order_by(RuntimeDetection.timestamp.desc())
          .first()
    )

    if not detection:
        return None

    scenario_id = _SCENARIO_MAP.get(detection.detector_type)
    if not scenario_id:
        return None

    title = _TITLES.get(detection.detector_type, "Runtime Security Detection")

    # Map detector severity to Finding severity
    sev_map = {
        Severity.critical: Severity.critical,
        Severity.high:     Severity.high,
        Severity.medium:   Severity.medium,
        Severity.low:      Severity.low,
    }
    finding_severity = sev_map.get(detection.severity, Severity.high)

    logger.info(
        "rule_runtime_finding",
        tenant_id=tenant_id,
        detector_type=detection.detector_type,
        severity=detection.severity,
        agent_id=detection.agent_id,
    )

    return Finding(
        tenant_id     = tenant_id,
        title         = title,
        severity      = finding_severity,
        status        = FindingStatus.detected,
        evidence_refs = [detection.id],
        scenario_id   = scenario_id,
    )
