"""
Centralised platform snapshot - single source of truth for all dashboard pages.

Usage:
    from utils.data_snapshot import get_snapshot, DARK_LAYOUT

    snap = get_snapshot(
        window_hours=24,
        include_labs=False,
        mode="Operational",
        _refresh_token=st.session_state.get("refresh_token", 0),
    )

Cache strategy:
    @st.cache_data with ttl=30 seconds.  Pass _refresh_token (incremented by
    Refresh buttons) to bust the cache on demand.

Dark theme:
    DARK_LAYOUT is a dict you can spread into fig.update_layout():
        fig.update_layout(**DARK_LAYOUT, height=300, ...)
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
import streamlit as st

# ── Service URLs (inherited from env inside Docker or set locally) ─────────────
INGEST_URL     = os.getenv("INGEST_URL",     "http://localhost:8100")
DETECTIONS_URL = os.getenv("DETECTIONS_URL", "http://localhost:8200")
IDENTITY_URL   = os.getenv("IDENTITY_URL",   "http://localhost:8300")


# ── Dark theme constant ────────────────────────────────────────────────────────
# Spread into any plotly fig.update_layout() for consistent dark styling.
DARK_LAYOUT: dict[str, Any] = {
    "paper_bgcolor": "#1e293b",
    "plot_bgcolor":  "#0f172a",
    "font":          {"color": "#e2e8f0"},
}

# High-risk destination prefixes used across pages
HIGH_RISK_PREFIXES: tuple[str, ...] = (
    "169.254.", "metadata.google.internal", "metadata.internal",
)


# ── Internal helper ────────────────────────────────────────────────────────────

def _safe_get(url: str, default: Any = None, params: dict | None = None) -> Any:
    try:
        r = httpx.get(url, timeout=6.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


# ── Main snapshot ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=30)
def get_snapshot(
    window_hours: int = 24,
    include_labs: bool = False,
    mode: str = "Operational",
    _refresh_token: int = 0,
) -> dict[str, Any]:
    """
    Fetch and return a consistent platform snapshot used by all dashboard pages.

    Parameters
    ----------
    window_hours    : look-back window (used for findings, drift, blast queries)
    include_labs    : if False, lab/scenario agents and their signals are filtered out
    mode            : "Operational" | "Lab" (stored in snapshot metadata only)
    _refresh_token  : increment this value to bust the cache (pass via session_state)

    Returns
    -------
    dict with the keys documented below.
    """
    from utils.dashboard_utils import (
        filter_principals,
        filter_usages,
        filter_intent_summaries,
    )

    now         = datetime.now(timezone.utc)
    cutoff      = now - timedelta(hours=window_hours)
    cutoff_s    = cutoff.isoformat()
    cutoff_2x_s = (now - timedelta(hours=window_hours * 2)).isoformat()

    # Signal source filter
    sig_param = None if include_labs else "operational"

    # ── Raw fetches ────────────────────────────────────────────────────────────
    principals_raw: list = _safe_get(f"{IDENTITY_URL}/api/principals", []) or []

    findings_params: dict = {"limit": 500}
    if sig_param:
        findings_params["signal_source"] = sig_param
    all_findings: list = _safe_get(f"{DETECTIONS_URL}/api/findings", [], findings_params) or []

    recent_findings_params: dict = {"since": cutoff_s, "limit": 300}
    if sig_param:
        recent_findings_params["signal_source"] = sig_param
    findings_window: list = _safe_get(f"{DETECTIONS_URL}/api/findings", [], recent_findings_params) or []

    usages_params: dict = {"limit": 1000}
    if sig_param:
        usages_params["signal_source"] = sig_param
    tool_usages_raw: list = _safe_get(f"{INGEST_URL}/api/tool-usages", [], usages_params) or []

    intent_summary_raw: list = _safe_get(
        f"{DETECTIONS_URL}/api/intent/summary", [], {"hours": window_hours}
    ) or []
    drift_snaps: list = _safe_get(
        f"{DETECTIONS_URL}/api/intent/drift-snapshots",
        [], {"hours": window_hours, "limit": 1000},
    ) or []
    blast_snaps: list = _safe_get(
        f"{DETECTIONS_URL}/api/intent/blast-snapshots",
        [], {"hours": window_hours, "limit": 1000},
    ) or []
    jit_grants:    list = _safe_get(f"{IDENTITY_URL}/api/jit/grants", [], {"active_only": "true"}) or []
    scenario_runs: list = _safe_get(f"{DETECTIONS_URL}/api/scenario-runs", [], {"limit": 200}) or []
    enforcement_decisions: list = _safe_get(
        f"{IDENTITY_URL}/api/pdp/decisions", [], {"tenant_id": "default", "limit": 200}
    ) or []
    pending_approvals: list = _safe_get(
        f"{IDENTITY_URL}/api/approvals", [], {"tenant_id": "default", "status": "pending", "limit": 100}
    ) or []
    connector_instances: list = _safe_get(
        f"{INGEST_URL}/api/connectors", [], {"tenant_id": "default"}
    ) or []

    # ── Apply mode filter ──────────────────────────────────────────────────────
    pid_map = {p["id"]: p["name"] for p in principals_raw}
    principals  = filter_principals(principals_raw, include_labs)
    tool_usages = filter_usages(tool_usages_raw, include_labs, pid_map)
    intent_sums = filter_intent_summaries(intent_summary_raw, include_labs)

    # ── Derived: JIT count per principal ──────────────────────────────────────
    jit_count_map: dict[int, int] = defaultdict(int)
    for g in jit_grants:
        pid = g.get("principal_id")
        if pid is not None:
            jit_count_map[pid] += 1

    # ── Derived: intent map (principal_id → summary row) ──────────────────────
    intent_map = {s["principal_id"]: s for s in intent_summary_raw}

    # ── Derived: enriched agents list ─────────────────────────────────────────
    agents: list[dict] = []
    for p in principals:
        im = intent_map.get(p["id"], {})
        agents.append({
            **p,
            "drift_score":        im.get("drift_score"),
            "blast_radius_score": im.get("blast_radius_score"),
            "active_envelope":    im.get("active_envelope"),
            "jit_grants_count":   jit_count_map.get(p["id"], 0),
        })

    # ── Derived: findings grouped by scenario ─────────────────────────────────
    findings_by_scenario: dict[str, list] = defaultdict(list)
    for f in all_findings:
        sid = f.get("scenario_id") or "other"
        findings_by_scenario[sid].append(f)

    runs_by_scenario: dict[str, list] = defaultdict(list)
    for r in scenario_runs:
        sid = r.get("scenario_id") or "other"
        runs_by_scenario[sid].append(r)

    # ── Derived: top access paths ──────────────────────────────────────────────
    path_counts: dict[tuple, int] = defaultdict(int)
    for u in tool_usages:
        agent = pid_map.get(u.get("principal_id") or 0, "unknown")
        tool  = u.get("tool_name") or "unknown"
        dest  = u.get("destination") or ""
        path_counts[(agent, tool, dest)] += 1

    agent_risk_map = {p["name"]: p.get("risk_score", 0) or 0 for p in principals_raw}
    top_access_paths: list[dict] = []
    for (agent, tool, dest), cnt in sorted(path_counts.items(), key=lambda x: -x[1])[:20]:
        if agent == "unknown":
            continue
        risky = dest and any(dest.startswith(pr) for pr in HIGH_RISK_PREFIXES)
        top_access_paths.append({
            "agent":       agent,
            "tool":        tool,
            "destination": dest or "-",
            "calls":       cnt,
            "risk_score":  agent_risk_map.get(agent, 0),
            "is_risky":    bool(risky),
        })

    # ── Derived: new tools / destinations delta ────────────────────────────────
    recent_tools = {u["tool_name"] for u in tool_usages if u.get("timestamp", "") >= cutoff_s}
    older_tools  = {u["tool_name"] for u in tool_usages
                    if cutoff_2x_s <= u.get("timestamp", "") < cutoff_s}
    recent_dests = {u["destination"] for u in tool_usages
                    if u.get("destination") and u.get("timestamp", "") >= cutoff_s}
    older_dests  = {u["destination"] for u in tool_usages
                    if u.get("destination") and cutoff_2x_s <= u.get("timestamp", "") < cutoff_s}

    # ── Behavioral baseline engine (dashboard-side, no DB required) ───────────
    behavioral_findings: list = []
    agent_risk_graph:    dict = {}
    try:
        from utils.baseline_engine import compute_baselines
        from utils.behavior_findings import compute_behavioral_findings
        from utils.risk_graph import compute_risk_graph

        _baselines          = compute_baselines(tool_usages, pid_map)
        behavioral_findings = compute_behavioral_findings(_baselines)
        agent_risk_graph    = compute_risk_graph(tool_usages, pid_map)
    except Exception:
        pass  # never crash the snapshot if the engines fail

    return {
        # ── Raw collections ────────────────────────────────────────────────────
        "principals_raw":     principals_raw,
        "principals":         principals,
        "all_findings":       all_findings,
        "findings_window":    findings_window,    # only within window_hours
        "tool_usages":        tool_usages,        # mode-filtered
        "tool_usages_raw":    tool_usages_raw,
        "intent_summary":     intent_sums,        # mode-filtered
        "intent_summary_raw": intent_summary_raw,
        "drift_snapshots":    drift_snaps,
        "blast_snapshots":    blast_snaps,
        "jit_grants":             jit_grants,
        "scenario_runs":          scenario_runs,
        "enforcement_decisions":  enforcement_decisions,
        "pending_approvals":      pending_approvals,
        "connector_instances":    connector_instances,
        # ── Derived structures ─────────────────────────────────────────────────
        "agents":              agents,            # principals + drift/blast/jit enrichment
        "pid_map":             pid_map,
        "jit_count_map":       dict(jit_count_map),
        "intent_map":          intent_map,
        "findings_by_scenario": dict(findings_by_scenario),
        "runs_by_scenario":    dict(runs_by_scenario),
        "top_access_paths":    top_access_paths,
        "new_tools_count":     len(recent_tools - older_tools),
        "new_dests_count":     len(recent_dests - older_dests),
        # ── Behavioral baseline engine outputs ─────────────────────────────────
        "behavioral_findings": behavioral_findings,  # list[dict] - explainable findings
        "agent_risk_graph":    agent_risk_graph,     # agent_name → blast radius dict
        # ── Metadata ──────────────────────────────────────────────────────────
        "fetched_at":    now.isoformat(),
        "window_hours":  window_hours,
        "include_labs":  include_labs,
        "mode":          mode,
        "cutoff_iso":    cutoff_s,
    }
