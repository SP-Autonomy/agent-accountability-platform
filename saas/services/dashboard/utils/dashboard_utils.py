"""
AIAAP Dashboard - shared helpers for mode filtering and accountability scoring.

All pages import from here:
    from utils.dashboard_utils import render_mode_selector, filter_principals
    from utils import render_mode_selector, filter_principals  # also works via __init__
"""

from __future__ import annotations

import streamlit as st

# Agent names (or prefixes) that indicate lab/test runs, not real workloads.
# Extend this list if you add other synthetic test agents.
LAB_PREFIXES: tuple[str, ...] = ("scenario-",)

# Scenario IDs that represent "intent boundary / unauthorized action" findings.
# Used by the Control Room KPI: "Intent Violations (24h)".
INTENT_VIOLATION_SCENARIOS: frozenset[str] = frozenset({
    "intent_boundary",
    "overbroad_permissions",
    "confused_deputy",
    "ssrf_metadata",
})


# ── Mode selector ────────────────────────────────────────────────────────────

def render_mode_selector() -> tuple[str, bool]:
    """
    Render a mode selector in the sidebar.

    Returns:
        (mode, include_labs) where mode is "Operational" or "Lab",
        and include_labs is True when lab/scenario agents should be shown.
    """
    current = st.session_state.get("global_mode", "Operational")

    mode = st.sidebar.radio(
        "View mode",
        options=["Operational", "Lab"],
        index=0 if current == "Operational" else 1,
        key="global_mode",
        help=(
            "**Operational:** hides lab/scenario agents - shows only real workloads.  \n"
            "**Lab:** shows all agents including synthetic test runs."
        ),
    )

    if mode == "Operational":
        include_labs = st.sidebar.toggle(
            "Include lab agents",
            value=st.session_state.get("include_labs", False),
            key="include_labs",
            help="Override: show scenario-* agents in operational view.",
        )
    else:
        include_labs = True
        # Optional: keep include_labs sticky in Lab mode
        st.session_state["include_labs"] = True

    return mode, include_labs


# ── Agent / principal filtering ───────────────────────────────────────────────

def is_lab_agent(agent: dict) -> bool:
    """Return True if this agent/principal appears to be a lab/test entity."""
    name = (
        agent.get("name")
        or agent.get("agent_id")
        or agent.get("principal_name")
        or ""
    ).lower()
    return any(name.startswith(prefix) for prefix in LAB_PREFIXES)


def filter_principals(principals: list[dict], include_labs: bool) -> list[dict]:
    """Remove lab agents from the principals list if include_labs is False."""
    if include_labs:
        return principals
    return [p for p in principals if not is_lab_agent(p)]


def filter_usages(
    usages: list[dict],
    include_labs: bool,
    pid_map: dict[int, str],
) -> list[dict]:
    """
    Remove tool-usage records from lab agents.

    pid_map: {principal_id: agent_name} - from the principals list.
    """
    if include_labs:
        return usages
    lab_names: set[str] = {
        name for name in pid_map.values()
        if any(name.lower().startswith(p) for p in LAB_PREFIXES)
    }
    return [
        u for u in usages
        if pid_map.get(u.get("principal_id") or 0, "") not in lab_names
    ]


def filter_intent_summaries(
    summaries: list[dict],
    include_labs: bool,
) -> list[dict]:
    """Remove intent/drift summaries that belong to lab agents."""
    if include_labs:
        return summaries
    return [
        s for s in summaries
        if not any(
            (s.get("principal_name") or "").lower().startswith(p)
            for p in LAB_PREFIXES
        )
    ]


# ── Accountability score ──────────────────────────────────────────────────────

def accountability_score(
    principals: list[dict],
    intent_summaries: list[dict],
    findings_24h: list[dict],
) -> int:
    """
    Composite accountability score 0–100. Higher = better governed fleet.

    Factor 1 (40 pts): % agents with an active intent envelope
    Factor 2 (35 pts): inverse of average risk score (low risk = more pts)
    Factor 3 (25 pts): penalise active high/critical findings in last 24h
                        (-5 per finding, floored at 0)
    """
    if not principals:
        return 100  # empty fleet is trivially accountable

    # Factor 1: governance coverage
    agents_with_intent = sum(
        1 for s in intent_summaries if s.get("active_envelope")
    )
    gov_pts = int(40 * agents_with_intent / len(principals))

    # Factor 2: posture (inverse avg risk)
    avg_risk = sum(p.get("risk_score") or 0 for p in principals) / len(principals)
    posture_pts = int(35 * (1.0 - avg_risk / 100.0))

    # Factor 3: no active bad findings
    active_bad = [
        f for f in findings_24h
        if f.get("severity") in ("critical", "high")
        and f.get("status") != "missed"
    ]
    finding_pts = max(0, 25 - len(active_bad) * 5)

    return min(100, gov_pts + posture_pts + finding_pts)


# ── Misc helpers ──────────────────────────────────────────────────────────────

def score_color(score: int | float) -> str:
    """Return a Streamlit color string for a 0-100 accountability/risk score."""
    if score >= 80:
        return "green"
    if score >= 60:
        return "orange"
    return "red"
