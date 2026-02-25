"""
Dashboard Page 1: Overview
5 KPI cards, risk distribution donut, finding severity bar chart, recent findings.
"""

import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import httpx
import plotly.graph_objects as go
import streamlit as st
from utils.dashboard_utils import render_mode_selector, filter_principals
from utils.ui_narrative import render_narrative_header, render_filter_summary
from utils.data_snapshot import DARK_LAYOUT

INGEST_URL     = os.getenv("INGEST_URL",     st.session_state.get("INGEST_URL",     "http://localhost:8100"))
DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))
IDENTITY_URL   = os.getenv("IDENTITY_URL",   st.session_state.get("IDENTITY_URL",   "http://localhost:8300"))
RUNTIME_URL    = os.getenv("RUNTIME_URL",    st.session_state.get("RUNTIME_URL",    "http://localhost:8400"))

st.set_page_config(page_title="Overview | AIAAP", layout="wide")
st.title("Overview")
render_narrative_header(
    outcome="Platform-wide metrics for your agent fleet - agents, findings, JIT grants, and runtime detections.",
    what=["Active agent count (mode-filtered)", "Finding severity distribution (last 24h)", "JIT grants and runtime detections at a glance"],
    why=["Quickly assess whether the fleet is healthy", "Spot spikes in findings or runtime detections"],
    next_steps=["Drill into individual agents via Agents & Access", "Investigate findings in Detections"],
    primary_cta={"label": "Agents & Access", "page": "pages/02_agents_access.py"},
    secondary_cta={"label": "Detections", "page": "pages/05_detections.py"},
)


def safe_get(url: str, default=None, params: dict | None = None):
    try:
        r = httpx.get(url, timeout=4.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


if st.button("Refresh"):
    st.rerun()

with st.sidebar:
    mode, include_labs = render_mode_selector()

# ── Fetch data ────────────────────────────────────────────────────────────────
# Operational mode: findings scoped to operational signals only (no lab contamination).
_findings_params = {"limit": 500}
if not include_labs:
    _findings_params["signal_source"] = "operational"

findings       = safe_get(f"{DETECTIONS_URL}/api/findings", [], _findings_params) or []
all_principals = safe_get(f"{IDENTITY_URL}/api/principals", []) or []
principals     = filter_principals(all_principals, include_labs)
jit_grants    = safe_get(f"{IDENTITY_URL}/api/jit/grants", [], {"active_only": "true"}) or []
scenario_runs = safe_get(f"{DETECTIONS_URL}/api/scenario-runs", []) or []
rt_detections = safe_get(f"{RUNTIME_URL}/api/runtime/detections", [], {"limit": 500}) or []

# 24h cutoff
cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)


def _after_24h(ts_str: str | None) -> bool:
    if not ts_str:
        return False
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt >= cutoff_24h
    except ValueError:
        return False


rt_24h = [d for d in rt_detections if _after_24h(d.get("timestamp"))]

# ── 5 KPI Cards ──────────────────────────────────────────────────────────────
render_filter_summary(all_principals, principals, include_labs)
st.subheader("Key Metrics")
k1, k2, k3, k4, k5 = st.columns(5)

with k1:
    st.metric("Agents", len(principals))
with k2:
    open_findings = len([f for f in findings if f.get("status") in ("detected", "prevented")])
    st.metric("Findings", open_findings)
with k3:
    st.metric("JIT Grants Active", len(jit_grants))
with k4:
    st.metric("Runtime Detections (24h)", len(rt_24h))
with k5:
    runs_done = len([r for r in scenario_runs if r.get("status") == "complete"])
    st.metric("Scenarios Run", runs_done)

st.divider()

# ── Charts ────────────────────────────────────────────────────────────────────
chart_l, chart_r = st.columns(2)

with chart_l:
    st.subheader("Agent Risk Distribution")
    if principals:
        tiers = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for p in principals:
            score = p.get("risk_score", 0) or 0
            if score >= 75:
                tiers["CRITICAL"] += 1
            elif score >= 50:
                tiers["HIGH"] += 1
            elif score >= 25:
                tiers["MEDIUM"] += 1
            else:
                tiers["LOW"] += 1

        fig = go.Figure(go.Pie(
            labels=list(tiers.keys()),
            values=list(tiers.values()),
            hole=0.45,
            marker_colors=["#28a745", "#ffc107", "#dc3545", "#6f42c1"],
            textinfo="label+percent",
        ))
        fig.update_layout(
            **DARK_LAYOUT,
            margin=dict(t=20, b=20, l=20, r=20),
            height=300,
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No agents registered yet.")

with chart_r:
    st.subheader("Finding Severity (24h)")
    findings_24h = [f for f in findings if _after_24h(f.get("created_at"))]
    if findings_24h:
        sev_counts: dict[str, int] = defaultdict(int)
        for f in findings_24h:
            sev_counts[f.get("severity", "info")] += 1

        ordered_sevs = ["critical", "high", "medium", "low", "info"]
        sev_colors   = ["#6f42c1", "#dc3545", "#ffc107", "#17a2b8", "#6c757d"]
        labels = [s for s in ordered_sevs if s in sev_counts]
        values = [sev_counts[s] for s in labels]
        colors = [sev_colors[ordered_sevs.index(s)] for s in labels]

        fig2 = go.Figure(go.Bar(
            x=labels,
            y=values,
            marker_color=colors,
            text=values,
            textposition="outside",
        ))
        fig2.update_layout(
            **DARK_LAYOUT,
            margin=dict(t=20, b=40, l=20, r=20),
            height=300,
            xaxis_title=None,
            yaxis_title="Count",
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No findings in the last 24 hours.")

st.divider()

# ── Recent Findings ───────────────────────────────────────────────────────────
st.subheader("Recent Findings")

STATUS_ICON = {
    "prevented": "🟢",
    "detected":  "🟡",
    "missed":    "🔴",
}
SEV_COLOR = {
    "critical": "red",
    "high":     "orange",
    "medium":   "blue",
    "low":      "gray",
    "info":     "gray",
}

if findings:
    for f in findings[:5]:
        sev      = f.get("severity", "info")
        status   = f.get("status", "detected")
        ts       = (f.get("created_at") or "")[:19]
        icon     = STATUS_ICON.get(status, "⚪")
        scenario = f.get("scenario_id") or "-"
        color    = SEV_COLOR.get(sev, "gray")

        st.markdown(
            f"{icon} `{ts}` &nbsp; :{color}[**{sev.upper()}**] &nbsp; "
            f"**{f.get('title')}** &nbsp; `{status}` &nbsp; `{scenario}`"
        )
else:
    st.info("No findings yet. Run a scenario or trigger a tool call.")
