"""
Agent posture / risk score computation.
Score 0.0–100.0 where higher = riskier.

Factors (5 total, weights sum to 100):
  1. High-risk destination calls (metadata IPs) last 24h  (+5 each, max +30)
  2. High/critical Findings (operational signals only) last 24h
     (+10 per high-severity finding, +15 per critical, max +25)
  3. Behavioral anomaly score from BehavioralBaseline       (up to +25, proportional)
  4. JIT grant hygiene - no grants ever + >5 tool usages   (+10 static)
  5. Volume anomaly - >50 calls in last 24h                (+10 static)

Signal integrity: Factors 1, 2, 4, 5 filter ToolUsage and Finding by
  signal_source='operational' so lab scenario runs do NOT contaminate
  operational risk scores. This is enforced server-side and is mode-independent.
"""

from datetime import datetime, timezone, timedelta

from saas.services.shared.models import (
    AgentPrincipal, Finding, Severity, ToolUsage, JitGrant, BehavioralBaseline,
)


_METADATA_PREFIXES = ("169.254.", "metadata.google.internal", "metadata.internal")


def compute_risk_score(principal: AgentPrincipal, db) -> float:
    """
    Compute and return a 0–100 risk score for the given principal.
    ALWAYS uses operational signals only - lab signals are excluded.
    Call refresh_risk() to persist the result on the AgentPrincipal record.
    """
    score = 0.0
    now = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)

    # ── Factor 1: High-risk destination calls ─────────────────────────────────
    # Filter to operational signals only - lab scenarios must not inflate this.
    tool_usages = (
        db.query(ToolUsage)
          .filter(
              ToolUsage.principal_id == principal.id,
              ToolUsage.timestamp >= window_24h,
              ToolUsage.signal_source == "operational",
          )
          .all()
    )

    high_risk_dest_count = sum(
        1 for u in tool_usages
        if u.destination and any(u.destination.startswith(p) for p in _METADATA_PREFIXES)
    )
    score += min(high_risk_dest_count * 5.0, 30.0)

    # ── Factor 2: Recent high/critical Findings ────────────────────────────────
    # Scoped to operational findings only. Lab findings (scenario_id set,
    # signal_source='lab') do NOT contribute to operational risk scores.
    recent_findings = (
        db.query(Finding)
          .filter(
              Finding.tenant_id == principal.tenant_id,
              Finding.created_at >= window_24h,
              Finding.signal_source == "operational",
          )
          .all()
    )

    finding_score = 0.0
    for f in recent_findings:
        if f.severity == Severity.critical:
            finding_score += 15.0
        elif f.severity == Severity.high:
            finding_score += 10.0
    score += min(finding_score, 25.0)

    # ── Factor 3: Behavioral anomaly from BehavioralBaseline ─────────────────
    baseline = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal.id, tenant_id=principal.tenant_id)
          .first()
    )
    if baseline and baseline.anomaly_score > 0:
        # anomaly_score is 0–100; map to 0–25 contribution
        score += min(baseline.anomaly_score / 100.0 * 25.0, 25.0)

    # ── Factor 4: JIT grant hygiene ────────────────────────────────────────────
    grant_count = (
        db.query(JitGrant)
          .filter_by(principal_id=principal.id)
          .count()
    )
    if grant_count == 0 and len(tool_usages) > 5:
        score += 10.0

    # ── Factor 5: Volume anomaly ───────────────────────────────────────────────
    if len(tool_usages) > 50:
        score += 10.0

    return min(round(score, 2), 100.0)


def compute_risk_breakdown(principal: AgentPrincipal, db) -> dict:
    """
    Return a structured breakdown of the risk score components with provenance.
    Used by the explainability endpoint GET /api/principals/{id}/risk-breakdown.
    """
    now = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)

    # Factor 1
    tool_usages = (
        db.query(ToolUsage)
          .filter(
              ToolUsage.principal_id == principal.id,
              ToolUsage.timestamp >= window_24h,
              ToolUsage.signal_source == "operational",
          )
          .all()
    )
    high_risk_dests = [
        u.destination for u in tool_usages
        if u.destination and any(u.destination.startswith(p) for p in _METADATA_PREFIXES)
    ]
    factor1_pts = min(len(high_risk_dests) * 5.0, 30.0)

    # Factor 2
    recent_findings = (
        db.query(Finding)
          .filter(
              Finding.tenant_id == principal.tenant_id,
              Finding.created_at >= window_24h,
              Finding.signal_source == "operational",
          )
          .all()
    )
    finding_pts = sum(
        15.0 if f.severity == Severity.critical else 10.0
        for f in recent_findings
        if f.severity in (Severity.critical, Severity.high)
    )
    factor2_pts = min(finding_pts, 25.0)

    # Factor 3
    baseline = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal.id, tenant_id=principal.tenant_id)
          .first()
    )
    anomaly_score = baseline.anomaly_score if baseline else 0.0
    factor3_pts = min(anomaly_score / 100.0 * 25.0, 25.0) if anomaly_score > 0 else 0.0

    # Factor 4
    grant_count = (
        db.query(JitGrant)
          .filter_by(principal_id=principal.id)
          .count()
    )
    factor4_pts = 10.0 if (grant_count == 0 and len(tool_usages) > 5) else 0.0

    # Factor 5
    factor5_pts = 10.0 if len(tool_usages) > 50 else 0.0

    total = min(round(factor1_pts + factor2_pts + factor3_pts + factor4_pts + factor5_pts, 2), 100.0)

    return {
        "principal_id": principal.id,
        "principal_name": principal.name,
        "total_score": total,
        "computed_at": now.isoformat(),
        "signal_source_filter": "operational",
        "factors": [
            {
                "name": "high_risk_destinations",
                "description": "Calls to cloud metadata IPs in last 24h (operational signals only)",
                "points": factor1_pts,
                "max_points": 30,
                "detail": {
                    "count": len(high_risk_dests),
                    "destinations": high_risk_dests[:10],
                    "per_call": 5,
                },
            },
            {
                "name": "recent_findings",
                "description": "High/critical operational findings in last 24h",
                "points": factor2_pts,
                "max_points": 25,
                "detail": {
                    "count": len([f for f in recent_findings if f.severity in (Severity.critical, Severity.high)]),
                    "critical_count": len([f for f in recent_findings if f.severity == Severity.critical]),
                    "high_count": len([f for f in recent_findings if f.severity == Severity.high]),
                },
            },
            {
                "name": "behavioral_anomaly",
                "description": "Anomaly score from behavioral baseline",
                "points": factor3_pts,
                "max_points": 25,
                "detail": {
                    "anomaly_score": anomaly_score,
                    "baseline_computed_at": baseline.computed_at.isoformat() if baseline else None,
                },
            },
            {
                "name": "jit_hygiene",
                "description": "No JIT grants ever with >5 tool calls",
                "points": factor4_pts,
                "max_points": 10,
                "detail": {
                    "grant_count": grant_count,
                    "tool_call_count_24h": len(tool_usages),
                },
            },
            {
                "name": "volume_anomaly",
                "description": ">50 tool calls in last 24h",
                "points": factor5_pts,
                "max_points": 10,
                "detail": {
                    "tool_call_count_24h": len(tool_usages),
                    "threshold": 50,
                },
            },
        ],
    }
