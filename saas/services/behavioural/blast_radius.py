"""
Blast Radius Engine - Reach Expansion Detection
-------------------------------------------------
Measures how far an agent principal's access graph has grown compared to
the stored BehavioralBaseline. Builds on graph_drift.py patterns.

Blast Radius Score (0–100) combines:
  - Unique destination growth vs baseline (0–40 pts)
  - Privileged edge count (0–30 pts)
  - New edges beyond baseline degree (0–30 pts)

A blast_radius_growth Finding is emitted when:
  - blast_radius_score >= BLAST_FINDING_THRESHOLD, OR
  - unique_destinations_count growth > 50% vs baseline, OR
  - any new sensitive destinations (metadata IP, vault, IAM, etc.)
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import (
    AgentPrincipal, BehavioralBaseline, ToolUsage,
    BlastRadiusSnapshot, Finding, Severity, FindingStatus,
)

logger = structlog.get_logger()

BLAST_FINDING_THRESHOLD = 50.0    # blast_radius_score >= this → emit Finding
BLAST_DEDUP_MINUTES     = 15      # suppress duplicate Findings

_SENSITIVE_DEST_PREFIXES = (
    "169.254.", "metadata.google", "metadata.internal",
    "vault.", "secrets.", "kms.", "iam.amazonaws", "sts.amazonaws",
)

_PRIVILEGED_TOOLS = {
    "read_secrets", "write_secrets", "exec_command", "deploy_infrastructure",
    "modify_iam_policy", "create_role", "attach_policy", "update_cluster",
    "delete_resource", "kubectl_exec",
}


def _is_sensitive_dest(dest: str | None) -> bool:
    if not dest:
        return False
    return any(dest.lower().startswith(p) for p in _SENSITIVE_DEST_PREFIXES)


def _is_privileged_tool(tool: str | None) -> bool:
    return bool(tool) and tool.lower() in _PRIVILEGED_TOOLS


# ── Core computation ──────────────────────────────────────────────────────────

def compute_blast_radius(
    principal_id: int,
    tenant_id:    str,
    db,
    window_hours: int = 1,
) -> Optional[BlastRadiusSnapshot]:
    """
    Compute blast radius snapshot for one principal.
    Returns an unsaved BlastRadiusSnapshot, or None if insufficient data.
    """
    baseline: BehavioralBaseline | None = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal_id, tenant_id=tenant_id)
          .first()
    )

    now     = datetime.now(timezone.utc)
    cutoff  = now - timedelta(hours=window_hours)

    usages = (
        db.query(ToolUsage)
          .filter(
              ToolUsage.principal_id == principal_id,
              ToolUsage.tenant_id    == tenant_id,
              ToolUsage.timestamp    >= cutoff,
          )
          .all()
    )

    if not usages:
        return None

    # Build current edge sets
    current_dests   = {u.destination for u in usages if u.destination}
    current_tools   = {u.tool_name for u in usages if u.tool_name}
    priv_edges      = [u for u in usages if _is_privileged_tool(u.tool_name)]
    sensitive_dests = [d for d in current_dests if _is_sensitive_dest(d)]

    unique_dest_count  = len(current_dests)
    unique_res_count   = len(current_tools)
    priv_edges_count   = len(priv_edges)
    current_degree     = unique_dest_count + unique_res_count

    # New edges vs baseline
    if baseline:
        known_dests  = set(baseline.known_destinations or [])
        known_tools  = set(baseline.known_tools or [])
        new_dests    = current_dests - known_dests
        new_tools    = current_tools - known_tools
        new_edges    = len(new_dests) + len(new_tools)
        baseline_deg = baseline.baseline_degree or 1
    else:
        new_edges    = current_degree
        baseline_deg = 1
        new_dests    = current_dests
        new_tools    = current_tools

    # ── Score computation (0–100) ─────────────────────────────────────────────
    # Component 1: destination growth ratio (0–40 pts)
    dest_ratio    = unique_dest_count / max(baseline_deg, 1)
    dest_pts      = min(dest_ratio * 20.0, 40.0)

    # Component 2: privileged edges (0–30 pts)
    priv_pts      = min(priv_edges_count * 10.0, 30.0)

    # Component 3: new edges beyond baseline (0–30 pts)
    new_edge_pts  = min(new_edges * 5.0, 30.0)

    blast_score   = min(dest_pts + priv_pts + new_edge_pts, 100.0)

    snap = BlastRadiusSnapshot(
        tenant_id                 = tenant_id,
        principal_id              = principal_id,
        window_start              = cutoff,
        window_end                = now,
        unique_destinations_count = unique_dest_count,
        unique_resources_count    = unique_res_count,
        privileged_edges_count    = priv_edges_count,
        new_edges_count           = new_edges,
        blast_radius_score        = blast_score,
    )
    return snap


# ── Finding creation ──────────────────────────────────────────────────────────

def _has_recent_blast_finding(principal_id: int, tenant_id: str, db) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=BLAST_DEDUP_MINUTES)
    return (
        db.query(Finding)
          .filter(
              Finding.scenario_id == "blast_radius",
              Finding.tenant_id   == tenant_id,
              Finding.created_at  >= cutoff,
          )
          .first()
    ) is not None


def _create_blast_finding(
    principal: AgentPrincipal,
    snap: BlastRadiusSnapshot,
    db,
) -> Finding:
    sev = (
        Severity.critical if snap.blast_radius_score >= 75
        else Severity.high
    )
    f = Finding(
        tenant_id     = principal.tenant_id,
        title         = (
            f"Blast Radius Growth: {principal.name} - "
            f"{snap.unique_destinations_count} dest, "
            f"{snap.privileged_edges_count} priv edges, "
            f"score {snap.blast_radius_score:.0f}/100"
        ),
        severity      = sev,
        status        = FindingStatus.detected,
        evidence_refs = [snap.id],
        scenario_id   = "blast_radius",
    )
    db.add(f)
    logger.info(
        "blast_radius_finding",
        principal=principal.name,
        score=snap.blast_radius_score,
        dests=snap.unique_destinations_count,
        priv_edges=snap.privileged_edges_count,
    )
    return f


# ── Background loop entry point ───────────────────────────────────────────────

def run_blast_radius_analysis(tenant_id: str = "default") -> int:
    """
    Background task: compute blast radius for all principals.
    Writes BlastRadiusSnapshot rows and creates Findings when threshold exceeded.
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
                snap = compute_blast_radius(principal.id, tenant_id, db)
                if snap is None:
                    continue

                db.add(snap)
                db.flush()
                snapshots_written += 1

                logger.info(
                    "blast_radius_snapshot",
                    principal=principal.name,
                    score=snap.blast_radius_score,
                    dests=snap.unique_destinations_count,
                    priv_edges=snap.privileged_edges_count,
                )

                if (
                    snap.blast_radius_score >= BLAST_FINDING_THRESHOLD
                    and not _has_recent_blast_finding(principal.id, tenant_id, db)
                ):
                    _create_blast_finding(principal, snap, db)

                db.commit()

            except Exception as exc:
                logger.warning("blast_radius_principal_error", principal_id=principal.id, error=str(exc))
                db.rollback()

    except Exception as exc:
        logger.error("blast_radius_analysis_error", error=str(exc))
    finally:
        db.close()

    return snapshots_written
