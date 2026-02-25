"""
Behavioral Anomaly Scoring
----------------------------
Combines statistical baseline comparison (z-score) and identity graph drift
into a single anomaly score per principal, and creates Findings when thresholds
are exceeded.

Algorithm
---------
1. Load stored BehavioralBaseline for the principal.
2. Compute current metrics (last 1 hour) via baseline.compute_current_metrics().
3. For each metric, compute z = |current - mean| / std.
4. Check graph drift via graph_drift.detect_drift().
5. Aggregate flags + compute overall anomaly_score (0–100).
6. If is_anomalous, create a Finding with scenario_id="behavioral_anomaly".

Z-score thresholds (configurable via env vars):
  ZSCORE_CALLS_THRESHOLD   default 3.0  - spike in call volume
  ZSCORE_DEST_THRESHOLD    default 3.0  - spike in distinct destinations
  ZSCORE_ENTROPY_THRESHOLD default 2.5  - unusual entropy in destination distribution
  ZSCORE_PRIV_THRESHOLD    default 2.0  - spike in privileged action ratio
  ZSCORE_NEW_TOOL_THRESHOLD default 2.0 - sudden appearance of new tools

Isolation Forest (optional):
  Install scikit-learn and set ENABLE_ISOFOREST=true.
  The model is trained lazily on the first scoring cycle and re-trained every
  ISOFOREST_RETRAIN_INTERVAL scoring cycles.
  Feature vector: [calls_per_hour, distinct_dest, entropy, privileged_ratio, new_tool_freq]
"""

import os
import math
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from sklearn.ensemble import IsolationForest

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import (
    AgentPrincipal, BehavioralBaseline, Finding, Severity, FindingStatus,
)

logger = structlog.get_logger()

# ── Thresholds ────────────────────────────────────────────────────────────────
_THRESHOLDS = {
    "calls_per_hour":    float(os.getenv("ZSCORE_CALLS_THRESHOLD",    "3.0")),
    "distinct_dest":     float(os.getenv("ZSCORE_DEST_THRESHOLD",     "3.0")),
    "entropy":           float(os.getenv("ZSCORE_ENTROPY_THRESHOLD",  "2.5")),
    "privileged_ratio":  float(os.getenv("ZSCORE_PRIV_THRESHOLD",     "2.0")),
    "new_tool_freq":     float(os.getenv("ZSCORE_NEW_TOOL_THRESHOLD", "2.0")),
}

_BASELINE_MEAN_FIELDS = {
    "calls_per_hour":   ("mean_calls_per_hour",   "std_calls_per_hour"),
    "distinct_dest":    ("mean_distinct_dest",     "std_distinct_dest"),
    "entropy":          ("mean_entropy",           "std_entropy"),
    "privileged_ratio": ("mean_privileged_ratio",  "std_privileged_ratio"),
    "new_tool_freq":    ("mean_new_tool_freq",     "std_new_tool_freq"),
}

ENABLE_ISOFOREST = os.getenv("ENABLE_ISOFOREST", "false").lower() == "true"

# Simple in-memory cache of IsolationForest models keyed by tenant_id
# (only used when ENABLE_ISOFOREST=true and scikit-learn is installed)
_iso_models: dict[str, Any] = {}
_iso_training_counts: dict[str, int] = {}
ISOFOREST_RETRAIN_INTERVAL = 20
ISOFOREST_MIN_SAMPLES = 10


@dataclass
class AnomalyResult:
    principal_id:     int
    principal_name:   str
    tenant_id:        str
    anomaly_score:    float          # 0–100, higher = more anomalous
    z_scores:         dict[str, float] = field(default_factory=dict)
    flags:            list[str]        = field(default_factory=list)
    is_anomalous:     bool             = False
    current_metrics:  dict             = field(default_factory=dict)
    drift_summary:    str              = ""


def _z_score(current: float, mean: float, std: float) -> float:
    if std <= 0:
        return 0.0
    return abs(current - mean) / std


def _isoforest_score(features: list[float], tenant_id: str) -> float | None:
    """
    Optional Isolation Forest scoring. Returns a contamination probability (0–1)
    or None if disabled / scikit-learn not available.

    To enable: pip install scikit-learn; set ENABLE_ISOFOREST=true
    """
    if not ENABLE_ISOFOREST:
        return None
    try:
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore
        except ImportError:
            logger.debug("isoforest_unavailable", hint="pip install scikit-learn")
            return None
        import numpy as np

        model: "IsolationForest | None" = _iso_models.get(tenant_id)
        count = _iso_training_counts.get(tenant_id, 0)

        # Collect training data lazily from BehavioralBaseline table
        if model is None or count % ISOFOREST_RETRAIN_INTERVAL == 0:
            db = SessionLocal()
            try:
                baselines = db.query(BehavioralBaseline).filter_by(tenant_id=tenant_id).all()
                if len(baselines) >= ISOFOREST_MIN_SAMPLES:
                    X = np.array([
                        [
                            b.mean_calls_per_hour,
                            b.mean_distinct_dest,
                            b.mean_entropy,
                            b.mean_privileged_ratio,
                            b.mean_new_tool_freq,
                        ]
                        for b in baselines
                    ])
                    model = IsolationForest(contamination=0.1, random_state=42)
                    model.fit(X)
                    _iso_models[tenant_id] = model
                    logger.info("isoforest_trained", tenant_id=tenant_id, n_samples=len(baselines))
            finally:
                db.close()

        _iso_training_counts[tenant_id] = count + 1

        if model is None:
            return None

        x = np.array([features])
        # score_samples returns negative anomaly scores; convert to 0–1 probability
        raw = model.score_samples(x)[0]
        # IsolationForest: more negative = more anomalous. Normalize to [0, 1].
        normalized = max(0.0, min(1.0, (-raw - 0.2) / 0.8))
        return normalized

    except ImportError:
        logger.debug("isoforest_unavailable", hint="pip install scikit-learn")
        return None
    except Exception as exc:
        logger.warning("isoforest_error", error=str(exc))
        return None


def score_principal(
    principal: AgentPrincipal,
    db,
) -> AnomalyResult | None:
    """
    Score a single principal's current behaviour against its stored baseline.
    Returns None if no baseline exists or there is insufficient data.
    Creates a Finding in the DB if the result is anomalous.
    """
    from saas.services.behavioural.baseline import compute_current_metrics
    from saas.services.behavioural.graph_drift import build_current_graph, detect_drift

    baseline: BehavioralBaseline | None = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal.id, tenant_id=principal.tenant_id)
          .first()
    )

    if baseline is None or baseline.observations < 3:
        return None   # not enough history yet

    current = compute_current_metrics(principal.id, principal.tenant_id, db)
    if current["sample_size"] == 0:
        return None   # no activity in the last hour

    # ── Z-score analysis ──────────────────────────────────────────────────────
    z_scores: dict[str, float] = {}
    flags:    list[str] = []

    for metric, (mean_field, std_field) in _BASELINE_MEAN_FIELDS.items():
        cur_val  = current.get(metric, 0.0)
        mean_val = getattr(baseline, mean_field, 0.0)
        std_val  = getattr(baseline, std_field,  1.0)
        z        = _z_score(cur_val, mean_val, std_val)
        z_scores[metric] = z
        threshold = _THRESHOLDS[metric]
        if z > threshold:
            flags.append(f"{metric}_zscore_{z:.1f}σ")

    # ── Graph drift analysis ──────────────────────────────────────────────────
    snap  = build_current_graph(principal.id, principal.tenant_id, db)
    drift = detect_drift(snap, baseline)
    drift_parts: list[str] = []

    if drift.new_sensitive_dests:
        flags.append(f"first_sensitive_destination:{','.join(drift.new_sensitive_dests[:3])}")
        drift_parts.append(f"sensitive destinations: {drift.new_sensitive_dests}")
    if drift.new_sensitive_tools:
        flags.append(f"first_sensitive_tool:{','.join(drift.new_sensitive_tools[:3])}")
        drift_parts.append(f"sensitive tools: {drift.new_sensitive_tools}")
    if drift.degree_spike:
        flags.append(f"graph_degree_spike:{drift.current_degree}vs{drift.baseline_degree}")
        drift_parts.append(f"degree spike {drift.current_degree}→baseline {drift.baseline_degree}")
    if len(drift.new_tools) > 3:
        flags.append(f"many_new_tools:{len(drift.new_tools)}")
    if len(drift.new_destinations) > 5:
        flags.append(f"many_new_destinations:{len(drift.new_destinations)}")

    # ── Isolation Forest (optional) ───────────────────────────────────────────
    iso_score: float | None = None
    if ENABLE_ISOFOREST:
        features = [
            current.get("calls_per_hour", 0.0),
            current.get("distinct_dest", 0.0),
            current.get("entropy", 0.0),
            current.get("privileged_ratio", 0.0),
            current.get("new_tool_freq", 0.0),
        ]
        iso_score = _isoforest_score(features, principal.tenant_id)
        if iso_score and iso_score > 0.7:
            flags.append(f"isoforest_anomaly:{iso_score:.2f}")

    # ── Aggregate score ───────────────────────────────────────────────────────
    max_z = max(z_scores.values(), default=0.0)
    z_component = min(max_z / max(max(_THRESHOLDS.values()), 1.0) * 70.0, 70.0)
    drift_component = min(len(flags) * 10.0, 30.0)
    anomaly_score = min(z_component + drift_component, 100.0)

    if iso_score:
        anomaly_score = max(anomaly_score, iso_score * 100.0)

    is_anomalous = bool(flags)

    result = AnomalyResult(
        principal_id=principal.id,
        principal_name=principal.name,
        tenant_id=principal.tenant_id,
        anomaly_score=round(anomaly_score, 2),
        z_scores=z_scores,
        flags=flags,
        is_anomalous=is_anomalous,
        current_metrics=current,
        drift_summary="; ".join(drift_parts) if drift_parts else "",
    )

    # ── Persist Finding if anomalous ──────────────────────────────────────────
    if is_anomalous:
        _maybe_create_finding(result, baseline, db)

    # Update anomaly score on the baseline record
    baseline.anomaly_score = anomaly_score
    try:
        db.commit()
    except Exception:
        db.rollback()

    return result


def _maybe_create_finding(result: AnomalyResult, baseline: BehavioralBaseline, db) -> None:
    """Create a behavioral anomaly Finding, deduplicating within a 15-minute window."""
    from saas.services.shared.models import Finding, Severity, FindingStatus

    dedup_cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
    existing = (
        db.query(Finding)
          .filter(
              Finding.scenario_id == "behavioral_anomaly",
              Finding.tenant_id   == result.tenant_id,
              Finding.created_at  >= dedup_cutoff,
          )
          .filter(Finding.title.like(f"%{result.principal_name}%"))
          .first()
    )
    if existing:
        return

    top_flags = result.flags[:5]
    flag_summary = " | ".join(top_flags)

    severity = Severity.high if result.anomaly_score >= 60 else Severity.medium

    finding = Finding(
        tenant_id=result.tenant_id,
        title=(
            f"Behavioral Anomaly: {result.principal_name} - "
            f"score {result.anomaly_score:.0f}/100 ({flag_summary[:80]})"
        ),
        severity=severity,
        status=FindingStatus.detected,
        scenario_id="behavioral_anomaly",
        evidence_refs=[],
    )
    db.add(finding)
    logger.info(
        "behavioral_finding_created",
        principal=result.principal_name,
        score=result.anomaly_score,
        flags=result.flags,
    )


def run_behavioral_analysis(tenant_id: str = "default") -> list[AnomalyResult]:
    """
    Entry point for the background behavioral analysis loop.
    Updates baselines, scores all principals, creates Findings for anomalies.
    Returns list of AnomalyResults for logging/monitoring.
    """
    from saas.services.behavioural.baseline import update_all_baselines

    db = SessionLocal()
    results: list[AnomalyResult] = []
    try:
        # 1. Refresh baselines
        updated = update_all_baselines(tenant_id)
        if updated:
            logger.info("baselines_updated", count=updated, tenant_id=tenant_id)

        # 2. Score each principal
        principals = (
            db.query(AgentPrincipal)
              .filter(AgentPrincipal.tenant_id == tenant_id)
              .all()
        )
        for p in principals:
            try:
                result = score_principal(p, db)
                if result:
                    results.append(result)
                    if result.is_anomalous:
                        logger.warning(
                            "behavioral_anomaly_detected",
                            principal=p.name,
                            score=result.anomaly_score,
                            flags=result.flags[:3],
                        )
            except Exception as exc:
                logger.error("behavioral_score_error", principal_id=p.id, error=str(exc))
                db.rollback()
    finally:
        db.close()

    return results
