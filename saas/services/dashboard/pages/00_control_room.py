"""
Dashboard Page 00: Control Room
---------------------------------
Default landing page answering:
  "Are my agents operating within their authorised boundaries?"

Single pane of glass for agent accountability:
  - Composite accountability score
  - Intent violations, drift alerts, blast radius alerts (24h)
  - What changed since yesterday
  - Top risks and recommended actions
"""

import os
from datetime import datetime, timezone, timedelta

import httpx
import pandas as pd
import streamlit as st

from utils.dashboard_utils import (
    render_mode_selector,
    filter_principals,
    filter_intent_summaries,
    accountability_score,
    INTENT_VIOLATION_SCENARIOS,
    score_color,
)
from utils.ui_narrative import render_narrative_header, render_filter_summary

INGEST_URL     = os.getenv("INGEST_URL",     st.session_state.get("INGEST_URL",     "http://localhost:8100"))
DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))
IDENTITY_URL   = os.getenv("IDENTITY_URL",   st.session_state.get("IDENTITY_URL",   "http://localhost:8300"))

st.set_page_config(page_title="Control Room | AIAAP", layout="wide")

# ── Sidebar: mode selector ────────────────────────────────────────────────────
with st.sidebar:
    st.divider()
    mode, include_labs = render_mode_selector()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("Control Room")
render_narrative_header(
    outcome="**Are my agents operating within their authorised boundaries?** Single pane of glass for agent identity, access, and behavioural accountability.",
    what=["Composite accountability score (0–100)", "Intent violations, drift & blast-radius alerts (24h)", "What changed vs. yesterday (new tools, destinations, grants)"],
    why=["Catch governance gaps before they become incidents", "Prioritise which agents need immediate attention", "One view across identity, access, and behavioural signals"],
    next_steps=["High risk → Review findings in Detections", "Drift alerts → Investigate in Behavioral Intelligence", "Ungoverned agents → Create intent envelopes in Agents & Access"],
    secondary_cta={"label": "Assurance Labs", "page": "pages/06_assurance_labs.py"},
)

col_refresh, _ = st.columns([1, 5])
with col_refresh:
    if st.button("Refresh"):
        st.cache_data.clear()
        st.rerun()


# ── Data fetching ─────────────────────────────────────────────────────────────
def safe_get(url: str, default=None, params: dict | None = None):
    try:
        r = httpx.get(url, timeout=5.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


now          = datetime.now(timezone.utc)
cutoff_24h   = now - timedelta(hours=24)
cutoff_48h   = now - timedelta(hours=48)
cutoff_24h_s = cutoff_24h.isoformat()
cutoff_48h_s = cutoff_48h.isoformat()

principals_raw  = safe_get(f"{IDENTITY_URL}/api/principals", []) or []

# Signal source: Operational mode uses operational signals only (lab scenarios excluded).
# Lab mode includes all signals. This prevents lab scenario runs from affecting KPIs.
_findings_params: dict = {"since": cutoff_24h_s, "limit": 300}
_usages_params:   dict = {"limit": 1000}
if not include_labs:
    _findings_params["signal_source"] = "operational"
    _usages_params["signal_source"]   = "operational"

findings_raw    = safe_get(f"{DETECTIONS_URL}/api/findings", [], _findings_params) or []
intent_summary  = safe_get(f"{DETECTIONS_URL}/api/intent/summary",
                           [], {"hours": 24}) or []
drift_snaps     = safe_get(f"{DETECTIONS_URL}/api/intent/drift-snapshots",
                           [], {"hours": 24, "limit": 500}) or []
blast_snaps     = safe_get(f"{DETECTIONS_URL}/api/intent/blast-snapshots",
                           [], {"hours": 24, "limit": 500}) or []
all_usages      = safe_get(f"{INGEST_URL}/api/tool-usages", [], _usages_params) or []
jit_grants           = safe_get(f"{IDENTITY_URL}/api/jit/grants",
                                [], {"active_only": "true"}) or []
enforcement_decisions = safe_get(f"{IDENTITY_URL}/api/pdp/decisions",
                                 [], {"tenant_id": "default", "limit": 200}) or []
pending_approvals    = safe_get(f"{IDENTITY_URL}/api/approvals",
                                [], {"tenant_id": "default", "status": "pending", "limit": 100}) or []

# Apply mode filter
principals   = filter_principals(principals_raw, include_labs)
intent_sums  = filter_intent_summaries(intent_summary, include_labs)
findings_24h = findings_raw


# ── Computed metrics ──────────────────────────────────────────────────────────
acc_score = accountability_score(principals, intent_sums, findings_24h)

# Intent violations: findings from authorization-boundary scenario IDs
intent_violations = [
    f for f in findings_24h
    if f.get("scenario_id") in INTENT_VIOLATION_SCENARIOS
]

# Drift alerts: agents where latest drift_score > 60 in last 24h
latest_drift: dict[int, float] = {}
for snap in drift_snaps:
    pid = snap.get("principal_id")
    score = snap.get("drift_score") or 0
    if pid and score > latest_drift.get(pid, 0):
        latest_drift[pid] = score
drift_alert_agents = sum(1 for s in latest_drift.values() if s > 60)

# Blast radius alerts: agents where latest blast_score > 50
latest_blast: dict[int, float] = {}
for snap in blast_snaps:
    pid = snap.get("principal_id")
    score = snap.get("blast_radius_score") or 0
    if pid and score > latest_blast.get(pid, 0):
        latest_blast[pid] = score
blast_alert_agents = sum(1 for s in latest_blast.values() if s > 50)

# ── KPI Row ───────────────────────────────────────────────────────────────────
_sig_label = "operational signals only" if not include_labs else "all signals (lab + operational)"
st.caption(f"Metrics computed from **{_sig_label}** · refreshed at `{now.strftime('%Y-%m-%d %H:%M:%S')} UTC`")

k1, k2, k3, k4, k5 = st.columns(5)

with k1:
    color = score_color(acc_score)
    st.metric("Accountability Score", acc_score)
    if acc_score >= 80:
        st.success("Fleet in good standing")
    elif acc_score >= 60:
        st.warning("Review recommended")
    else:
        st.error("Immediate attention required")

with k2:
    delta = f"+{len(intent_violations)}" if intent_violations else None
    st.metric("Intent Violations (24h)", len(intent_violations),
              delta=delta, delta_color="inverse")

with k3:
    st.metric("Drift Alerts (24h)", drift_alert_agents,
              delta=f"+{drift_alert_agents}" if drift_alert_agents else None,
              delta_color="inverse")

with k4:
    st.metric("Blast Radius Alerts (24h)", blast_alert_agents,
              delta=f"+{blast_alert_agents}" if blast_alert_agents else None,
              delta_color="inverse")

_blocked_24h = sum(
    1 for d in enforcement_decisions
    if d.get("outcome") == "block"
    and (d.get("created_at") or "") >= cutoff_24h_s
)
with k5:
    st.metric("Enforcement Actions (24h)", len([
        d for d in enforcement_decisions
        if (d.get("created_at") or "") >= cutoff_24h_s
        and d.get("outcome") != "allow"
    ]), delta=f"🚫 {_blocked_24h} blocked" if _blocked_24h else None,
    delta_color="inverse")

render_filter_summary(principals_raw, principals, include_labs)
st.divider()

# ── Two-column section: What changed + Top risks ──────────────────────────────
left_col, right_col = st.columns([4, 5])

with left_col:
    st.subheader("What changed? (last 24h)")

    # New tools delta: tools seen in last 24h vs tools seen in prior 24-48h window
    recent_tools = {
        u.get("tool_name", "") for u in all_usages
        if (u.get("timestamp") or "") >= cutoff_24h_s and u.get("tool_name")
    }
    older_tools = {
        u.get("tool_name", "") for u in all_usages
        if cutoff_48h_s <= (u.get("timestamp") or "") < cutoff_24h_s and u.get("tool_name")
    }
    new_tools_count = len(recent_tools - older_tools)

    # New destinations delta
    recent_dests = {
        u.get("destination", "") for u in all_usages
        if (u.get("timestamp") or "") >= cutoff_24h_s and u.get("destination")
    }
    older_dests = {
        u.get("destination", "") for u in all_usages
        if cutoff_48h_s <= (u.get("timestamp") or "") < cutoff_24h_s and u.get("destination")
    }
    new_dest_count = len(recent_dests - older_dests)

    # Agents with growing blast radius (compare latest vs previous snapshots)
    # Group by principal, check if last score > second-to-last
    from collections import defaultdict
    blast_by_agent: dict[int, list] = defaultdict(list)
    for snap in sorted(blast_snaps, key=lambda s: s.get("created_at") or ""):
        blast_by_agent[snap.get("principal_id")].append(snap.get("blast_radius_score") or 0)
    growing_blast = sum(
        1 for scores in blast_by_agent.values()
        if len(scores) >= 2 and scores[-1] > scores[-2]
    )

    # New JIT grants in last 24h
    new_grants = sum(
        1 for g in jit_grants
        if (g.get("created_at") or "") >= cutoff_24h_s
    )

    mc1, mc2 = st.columns(2)
    with mc1:
        st.metric("New tools", new_tools_count,
                  delta=f"+{new_tools_count}" if new_tools_count else None,
                  delta_color="inverse" if new_tools_count > 0 else "off")
        st.metric("New destinations", new_dest_count,
                  delta=f"+{new_dest_count}" if new_dest_count else None,
                  delta_color="inverse" if new_dest_count > 0 else "off")
    with mc2:
        st.metric("Growing blast radius", growing_blast,
                  delta=f"+{growing_blast}" if growing_blast else None,
                  delta_color="inverse" if growing_blast > 0 else "off")
        st.metric("New JIT grants", new_grants)

    st.metric("New findings", len(findings_24h))

    if new_tools_count == 0 and new_dest_count == 0 and growing_blast == 0 and not findings_24h:
        st.success("No significant changes detected in the last 24 hours.")


with right_col:
    st.subheader("Top risks right now")

    # Build per-agent intent/drift data lookup
    intent_by_pid = {s.get("principal_id"): s for s in intent_sums}
    findings_counts: dict[str, int] = defaultdict(int)
    # Count findings that can be linked to a principal (approximate: scan titles)
    for f in findings_24h:
        if f.get("status") in ("detected", "prevented"):
            findings_counts["_any"] += 1

    risk_rows = []
    for p in sorted(principals, key=lambda x: x.get("risk_score") or 0, reverse=True)[:8]:
        risk = p.get("risk_score") or 0
        if risk == 0:
            continue
        pid = p.get("id")
        summary = intent_by_pid.get(pid, {})
        drift = summary.get("drift_score") or 0
        blast = summary.get("blast_radius_score") or latest_blast.get(pid, 0)

        if risk >= 75:
            reason = "Critical risk score"
        elif blast > 50:
            reason = f"Blast radius alert ({blast:.0f})"
        elif drift > 60:
            reason = f"Behavioral drift ({drift:.0f})"
        elif risk >= 40:
            reason = "Elevated risk score"
        else:
            reason = "Moderate risk"

        tier = "🔴" if risk >= 75 else ("🟠" if risk >= 50 else "🟡")
        risk_rows.append({
            "": tier,
            "Agent": p.get("name", "-"),
            "Risk reason": reason,
            "Score": f"{risk:.0f}",
            "Last seen": (p.get("last_seen") or "-")[:19],
        })

    if risk_rows:
        st.dataframe(
            pd.DataFrame(risk_rows[:5]),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No agents with elevated risk scores.")

st.divider()

# ── Recommended Actions ───────────────────────────────────────────────────────
st.subheader("Recommended Actions")

actions = []

# Ungoverned agents (no active intent envelope)
agents_with_intent_set = {s.get("principal_id") for s in intent_sums if s.get("active_envelope")}
ungoverned = [p for p in principals if p.get("id") not in agents_with_intent_set]
if ungoverned:
    actions.append(("warning", f"**{len(ungoverned)} agent(s)** have no active intent envelope. "
                    "Define allowed tools and destinations in **Agents & Access**."))

# Critical findings
critical = [f for f in findings_24h if f.get("severity") == "critical"
            and f.get("status") in ("detected", "prevented")]
if critical:
    actions.append(("error", f"**{len(critical)} critical finding(s)** detected in the last 24h. "
                    "Review immediately in **Detections**."))
elif (high := [f for f in findings_24h if f.get("severity") == "high"
               and f.get("status") in ("detected", "prevented")]):
    actions.append(("warning", f"**{len(high)} high-severity finding(s)** need review in **Detections**."))

# Drift
drift_agents_list = [
    s.get("principal_name", "?") for s in intent_sums
    if (s.get("drift_score") or 0) > 60
]
if drift_agents_list:
    names = ", ".join(drift_agents_list[:3])
    suffix = f" (+{len(drift_agents_list)-3} more)" if len(drift_agents_list) > 3 else ""
    actions.append(("warning", f"**Behavioral drift** detected for: {names}{suffix}. "
                    "Review in **Behavioral Intelligence**."))

# High blast radius
high_blast_agents = [
    s.get("principal_name", "?") for s in intent_sums
    if (s.get("blast_radius_score") or latest_blast.get(s.get("principal_id"), 0)) > 70
]
if high_blast_agents:
    names = ", ".join(high_blast_agents[:3])
    actions.append(("warning", f"**Blast radius** exceeds 70 for: {names}. "
                    "Consider restricting tool access or creating a JIT grant."))

# Expiring grants (< 30 minutes)
expiring_soon = []
for g in jit_grants:
    exp = g.get("expires_at")
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            remaining = (exp_dt - now).total_seconds()
            if 0 < remaining < 1800:  # < 30 minutes
                expiring_soon.append(g)
        except ValueError:
            pass
if expiring_soon:
    actions.append(("info", f"**{len(expiring_soon)} JIT grant(s)** expire within 30 minutes. "
                    "Review in **Agents & Access**."))

# Pending approvals
if pending_approvals:
    actions.append(("warning", f"**{len(pending_approvals)} JIT approval request(s)** are pending review. "
                    "Approve or deny in **Agents & Access → Approvals**."))

# High block rate
if _blocked_24h >= 5:
    actions.append(("error", f"**{_blocked_24h} tool calls blocked** in the last 24h by the PDP. "
                    "Review blocked decisions in **Detections → Enforcement**."))
elif _blocked_24h > 0:
    actions.append(("warning", f"**{_blocked_24h} tool call(s) blocked** by the Policy Decision Point in the last 24h. "
                    "Review in **Detections → Enforcement**."))

# New tools/destinations (informational)
if new_tools_count > 0:
    new_list = ", ".join(sorted(recent_tools - older_tools)[:5])
    suffix = "..." if new_tools_count > 5 else ""
    actions.append(("info", f"**{new_tools_count} new tool(s)** observed in last 24h: `{new_list}{suffix}`. "
                    "Verify these are expected in **Activity**."))

# Behavioral findings from baseline engine
try:
    _beh_findings = safe_get(f"{INGEST_URL}/api/tool-usages", None, {"limit": 1000})
    if _beh_findings is not None:
        from utils.baseline_engine import compute_baselines
        from utils.behavior_findings import compute_behavioral_findings
        _pid_map = {p["id"]: p["name"] for p in principals_raw}
        _baselines = compute_baselines(_beh_findings, _pid_map)
        _beh = compute_behavioral_findings(_baselines)
        _beh_crit = [f for f in _beh if f["severity"] == "critical"]
        _beh_high = [f for f in _beh if f["severity"] == "high"]
        _beh_hrd  = [f for f in _beh if f["finding_type"] in
                     ("new_high_risk_destination", "known_high_risk_destination")]
        _beh_seq  = [f for f in _beh if f["finding_type"] == "suspicious_sequence"]
        if _beh_hrd:
            dests = sorted({f.get("destination","?") for f in _beh_hrd})[:3]
            actions.append(("error",
                f"**{len(_beh_hrd)} high-risk destination(s)** accessed by agents: "
                f"{', '.join(dests)}. Review in **Behavioral Intelligence → Behavioral Findings**."))
        if _beh_seq:
            agents_seq = sorted({f['agent'] for f in _beh_seq})[:3]
            actions.append(("warning",
                f"**{len(_beh_seq)} suspicious tool sequence(s)** detected for: "
                f"{', '.join(agents_seq)}. Review in **Behavioral Intelligence**."))
        elif _beh_crit or _beh_high:
            n = len(_beh_crit) + len(_beh_high)
            actions.append(("warning",
                f"**{n} critical/high behavioral finding(s)** from baseline analysis. "
                "Review in **Behavioral Intelligence → Behavioral Findings**."))
except Exception:
    pass

if not actions:
    st.success("**No recommended actions - platform is in good standing.**  \n"
               "All agents are governed, no critical findings, and drift metrics are healthy.")
else:
    for level, msg in actions:
        if level == "error":
            st.error(msg)
        elif level == "warning":
            st.warning(msg)
        else:
            st.info(msg)

# ── Golden-path CTAs ──────────────────────────────────────────────────────────
st.divider()
st.caption("**Workflow: Control Room → Investigate → Contain → Validate**")
cta1, cta2, cta3, cta4, cta5 = st.columns(5)
with cta1:
    st.page_link("pages/05_detections.py",      label="🔍 Investigate findings")
with cta2:
    st.page_link("pages/04_behavioral.py",       label="📈 Review drift/blast")
with cta3:
    st.page_link("pages/02_agents_access.py",    label="🪪 Manage access & grants")
with cta4:
    st.page_link("pages/03_activity.py",         label="🔗 Access graph")
with cta5:
    st.page_link("pages/06_assurance_labs.py",   label="🧪 Assurance Labs")

# ── Containment Actions ────────────────────────────────────────────────────────
st.divider()
st.subheader("Containment Actions")
st.caption("One-click containment for high-risk agents. All actions are logged in the audit trail.")

ca1, ca2, ca3 = st.columns(3)

with ca1:
    st.markdown("**Quarantine Agent**")
    st.caption("Revoke all active JIT grants for a specific agent immediately.")
    quarantine_pid = st.number_input("Agent Principal ID", min_value=1, step=1, key="quarantine_pid")
    if st.button("Revoke all grants", key="btn_quarantine", type="primary"):
        active_grants = safe_get(
            f"{IDENTITY_URL}/api/jit/grants",
            [], {"active_only": "true", "principal_id": int(quarantine_pid)},
        ) or []
        revoked_count = 0
        errors = []
        for g in active_grants:
            try:
                r = httpx.delete(
                    f"{IDENTITY_URL}/api/jit/grants/{g['id']}",
                    params={"revoked_by": "control-room"},
                    timeout=5.0,
                )
                if r.status_code == 204:
                    revoked_count += 1
                else:
                    errors.append(f"grant {g['id']}: {r.status_code}")
            except Exception as e:
                errors.append(str(e))
        if revoked_count:
            st.success(f"Revoked {revoked_count} grant(s) for principal {quarantine_pid}.")
        if errors:
            st.error("Errors: " + "; ".join(errors))
        if not active_grants:
            st.info(f"Principal {quarantine_pid} has no active grants to revoke.")

with ca2:
    st.markdown("**Lock Destinations**")
    st.caption("Block egress to high-risk destinations via Cilium network policy.")
    st.info("Network policy enforcement is applied at the Kubernetes cluster level via Cilium. "
            "Use the **Connectors → K8s** Helm chart to apply `aiaap-enforcement` policies.")
    if st.button("View Cilium policy guide", key="btn_cilium"):
        st.markdown("[→ K8s enforcement policies](connectors/k8s/helm/aiaap-enforcement/)")

with ca3:
    st.markdown("**Review Pending Approvals**")
    st.caption(f"{len(pending_approvals)} approval(s) awaiting review.")
    if pending_approvals:
        for ap in pending_approvals[:3]:
            st.markdown(f"- Principal `{ap['principal_id']}` · `{ap['scope']}`")
        if len(pending_approvals) > 3:
            st.caption(f"… and {len(pending_approvals) - 3} more")
    st.page_link("pages/02_agents_access.py", label="→ Go to Approvals tab")
