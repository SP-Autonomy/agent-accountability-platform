"""
Drift Engine - Behavioural Drift Scoring
------------------------------------------
Computes a drift score (0–100) for each agent principal by comparing
the current 1-hour window metrics against the stored BehavioralBaseline.

Reuses existing baseline.py (compute_current_metrics) and anomaly_scoring
z-score approach. Stores results as DriftSnapshot rows and emits
intent_drift_detected Findings when the drift score exceeds thresholds.

Score components (equal weights, capped per-component):
  z_calls    - z-score of calls_per_hour vs baseline
  z_dest     - z-score of distinct_dest vs baseline
  z_entropy  - z-score of entropy vs baseline
  z_priv     - z-score of privileged_ratio vs baseline
  z_new_tool - z-score of new_tool_freq vs baseline

Final drift_score = min(weighted_sum, 100)
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import (
    AgentPrincipal, BehavioralBaseline,
    DriftSnapshot, Finding, Severity, FindingStatus,
)
from saas.services.behavioural.baseline import compute_current_metrics

logger = structlog.get_logger()

# ── Thresholds ────────────────────────────────────────────────────────────────

DRIFT_FINDING_THRESHOLD = 60.0    # drift_score >= this → emit Finding
DRIFT_DEDUP_MINUTES     = 15      # suppress duplicate drift Findings

# Per-z-score contribution caps (points)
_ZSCORE_CAPS = {
    "z_calls":    20.0,
    "z_dest":     20.0,
    "z_entropy":  20.0,
    "z_priv":     25.0,
    "z_new_tool": 15.0,
}


def _zscore(value: float, mean: float, std: float) -> float:
    if std <= 0:
        return 0.0
    return (value - mean) / std


def _zscore_to_points(z: float, cap: float) -> float:
    """Map |z| to [0, cap] with a smooth sigmoid-like clamp."""
    abs_z = abs(z)
    return min(abs_z * (cap / 3.0), cap)   # 3-sigma → full cap


# ── Core scoring ──────────────────────────────────────────────────────────────

def compute_drift_score(
    principal_id: int,
    tenant_id:    str,
    db,
    window_minutes: int = 60,
) -> Optional[DriftSnapshot]:
    """
    Compute drift score for a single principal and return an unsaved DriftSnapshot.
    Returns None if insufficient data (no baseline or no recent activity).
    """
    baseline: BehavioralBaseline | None = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal_id, tenant_id=tenant_id)
          .first()
    )
    if baseline is None or baseline.observations < 3:
        return None

    current = compute_current_metrics(principal_id, tenant_id, db)
    if current["sample_size"] == 0:
        return None

    # ── Z-score each feature ─────────────────────────────────────────────────
    z_calls    = _zscore(current["calls_per_hour"],   baseline.mean_calls_per_hour,  baseline.std_calls_per_hour)
    z_dest     = _zscore(current["distinct_dest"],    baseline.mean_distinct_dest,   baseline.std_distinct_dest)
    z_entropy  = _zscore(current["entropy"],          baseline.mean_entropy,         baseline.std_entropy)
    z_priv     = _zscore(current["privileged_ratio"], baseline.mean_privileged_ratio, baseline.std_privileged_ratio)
    z_new_tool = _zscore(current["new_tool_freq"],    baseline.mean_new_tool_freq,   baseline.std_new_tool_freq)

    # ── Weighted point sum ────────────────────────────────────────────────────
    score = (
        _zscore_to_points(z_calls,    _ZSCORE_CAPS["z_calls"])
        + _zscore_to_points(z_dest,   _ZSCORE_CAPS["z_dest"])
        + _zscore_to_points(z_entropy, _ZSCORE_CAPS["z_entropy"])
        + _zscore_to_points(z_priv,   _ZSCORE_CAPS["z_priv"])
        + _zscore_to_points(z_new_tool, _ZSCORE_CAPS["z_new_tool"])
    )
    drift_score = min(score, 100.0)

    now = datetime.now(timezone.utc)
    snapshot = DriftSnapshot(
        tenant_id    = tenant_id,
        principal_id = principal_id,
        window_start = now - timedelta(minutes=window_minutes),
        window_end   = now,
        drift_score  = drift_score,
        metrics      = {
            "tool_call_rate":    current["calls_per_hour"],
            "new_tool_ratio":    current.get("new_tool_freq", 0.0),
            "new_dest_ratio":    (
                len(current.get("new_tools", [])) / max(len(current.get("current_tools", [])), 1)
            ),
            "entropy":           current["entropy"],
            "privileged_ratio":  current["privileged_ratio"],
            "sample_size":       current["sample_size"],
            # Z-score breakdown
            "z_calls":           round(z_calls, 3),
            "z_dest":            round(z_dest, 3),
            "z_entropy":         round(z_entropy, 3),
            "z_priv":            round(z_priv, 3),
            "z_new_tool":        round(z_new_tool, 3),
            # New items observed
            "new_tools_seen":    current.get("new_tools", []),
            "current_tools":     current.get("current_tools", []),
            "current_dests":     current.get("current_destinations", []),
        },
    )
    return snapshot


# ── Finding creation ──────────────────────────────────────────────────────────

def _has_recent_drift_finding(principal_id: int, tenant_id: str, db) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=DRIFT_DEDUP_MINUTES)
    return (
        db.query(Finding)
          .filter(
              Finding.scenario_id == "intent_drift",
              Finding.tenant_id   == tenant_id,
              Finding.created_at  >= cutoff,
          )
          .first()
    ) is not None


def _create_drift_finding(
    principal: AgentPrincipal,
    snapshot: DriftSnapshot,
    db,
) -> Finding:
    metrics = snapshot.metrics or {}
    z_breakdown = {
        k: v for k, v in metrics.items()
        if k.startswith("z_")
    }
    sev = Severity.critical if snapshot.drift_score >= 80 else Severity.high

    f = Finding(
        tenant_id     = principal.tenant_id,
        title         = (
            f"Intent Drift: {principal.name} - score {snapshot.drift_score:.0f}/100"
        ),
        severity      = sev,
        status        = FindingStatus.detected,
        evidence_refs = [snapshot.id],
        scenario_id   = "intent_drift",
    )
    db.add(f)
    logger.info(
        "intent_drift_finding",
        principal=principal.name,
        drift_score=snapshot.drift_score,
        z_breakdown=z_breakdown,
    )
    return f


# ── Background loop entry point ───────────────────────────────────────────────

def run_drift_analysis(tenant_id: str = "default") -> int:
    """
    Background task: compute drift for all principals of a tenant.
    Writes DriftSnapshot rows and creates Findings above threshold.
    Returns count of snapshots written.
    """
    db = SessionLocal()
    snapshots_written = 0

    try:
        principals = (
            db.query(AgentPrincipal)
              .filter(AgentPrincipal.tenant_id == tenant_id)
              .all()
        )

        for principal in principals:
            try:
                snapshot = compute_drift_score(principal.id, tenant_id, db)
                if snapshot is None:
                    continue

                db.add(snapshot)
                db.flush()  # get snapshot.id before creating Finding
                snapshots_written += 1

                logger.info(
                    "drift_snapshot",
                    principal=principal.name,
                    drift_score=snapshot.drift_score,
                )

                if (
                    snapshot.drift_score >= DRIFT_FINDING_THRESHOLD
                    and not _has_recent_drift_finding(principal.id, tenant_id, db)
                ):
                    _create_drift_finding(principal, snapshot, db)

                db.commit()

            except Exception as exc:
                logger.warning("drift_analysis_principal_error", principal_id=principal.id, error=str(exc))
                db.rollback()

    except Exception as exc:
        logger.error("drift_analysis_error", error=str(exc))
    finally:
        db.close()

    return snapshots_written
