"""
Dashboard Page 4: Behavioral Intelligence
Tabbed: Intent Integrity | Drift Timeline | Blast Radius

Tells the story of whether agents are behaving as declared:
- Did the agent respect its stated intent (allowed tools, destinations, privilege)?
- Is there statistical drift from established baseline behaviour?
- Has the agent's access blast radius expanded unexpectedly?
"""

import os
from datetime import datetime, timezone, timedelta

import httpx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from utils.dashboard_utils import render_mode_selector, filter_intent_summaries, filter_principals
from utils.ui_narrative import render_narrative_header, render_filter_summary
from utils.data_snapshot import DARK_LAYOUT

DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))
IDENTITY_URL   = os.getenv("IDENTITY_URL",   st.session_state.get("IDENTITY_URL",   "http://localhost:8300"))

st.set_page_config(page_title="Behavioral Intelligence | AIAAP", layout="wide")
st.title("Behavioral Intelligence")
render_narrative_header(
    outcome="Are your agents behaving as declared? Intent integrity, statistical drift, and access blast-radius analysis.",
    what=["Intent envelopes: declared allowed tools and destinations", "Drift score over time (statistical deviation from baseline)", "Blast radius: how far each agent's access graph has grown"],
    why=["Detect policy violations before they generate findings", "Identify creeping privilege that hasn't triggered a rule yet", "Enforce least-privilege with evidence-based intent envelopes"],
    next_steps=["Boundary violation? → Investigate in Detections", "Excessive blast radius → Restrict access or add JIT grant in Agents & Access", "No envelope? → Create one in the Intent Integrity tab"],
    primary_cta={"label": "Detections", "page": "pages/05_detections.py"},
    secondary_cta={"label": "Agents & Access", "page": "pages/02_agents_access.py"},
)

if st.button("Refresh"):
    st.rerun()

with st.sidebar:
    st.divider()
    mode, include_labs = render_mode_selector()


def safe_get(url, default=None, params=None):
    try:
        r = httpx.get(url, timeout=5.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


def safe_post(url, body):
    try:
        r = httpx.post(url, json=body, timeout=5.0)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


# Shared data
all_principals_raw = safe_get(f"{IDENTITY_URL}/api/principals", []) or []
principals         = filter_principals(all_principals_raw, include_labs)
summary            = filter_intent_summaries(safe_get(f"{DETECTIONS_URL}/api/intent/summary", [], {"hours": 24}) or [], include_labs)
render_filter_summary(all_principals_raw, principals, include_labs)
_beh_sig = {} if include_labs else {"signal_source": "operational"}
envelopes    = safe_get(f"{DETECTIONS_URL}/api/intent/envelopes", [], {"active_only": "true"}) or []
violations   = safe_get(f"{DETECTIONS_URL}/api/findings", [], {"scenario_id": "intent_boundary", "limit": 50, **_beh_sig}) or []
drift_finds  = safe_get(f"{DETECTIONS_URL}/api/findings", [], {"scenario_id": "intent_drift",   "limit": 50, **_beh_sig}) or []
blast_finds  = safe_get(f"{DETECTIONS_URL}/api/findings", [], {"scenario_id": "blast_radius",   "limit": 50, **_beh_sig}) or []

cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

# Platform KPIs
k1, k2, k3, k4 = st.columns(4)
k1.metric("Active Envelopes", len(envelopes))
k2.metric("Boundary Violations (24h)", len([f for f in violations if f.get("created_at","") >= cutoff_24h]))
k3.metric("Drift Alerts (24h)", len([f for f in drift_finds if f.get("created_at","") >= cutoff_24h]))
k4.metric("Blast Radius Alerts (24h)", len([f for f in blast_finds if f.get("created_at","") >= cutoff_24h]))

st.divider()

tab_intent, tab_drift, tab_blast, tab_beh = st.tabs([
    "Intent Integrity", "Drift Timeline", "Blast Radius", "Behavioral Findings"
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: INTENT INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
with tab_intent:
    # Per-principal posture table
    st.subheader("Agent Intent Posture")
    if summary:
        df = pd.DataFrame(summary)
        for col in ("drift_score", "blast_radius_score"):
            if col in df.columns:
                df[col] = df[col].apply(lambda x: round(x, 1) if isinstance(x, (int, float)) else "-")

        def _bg(val):
            if not isinstance(val, (int, float)): return ""
            return "background-color: #ffcccc" if val >= 70 else "background-color: #fff3cd" if val >= 40 else "background-color: #d4edda"

        cols = [c for c in ["principal_name", "namespace", "active_envelope", "envelope_created_by",
                             "drift_score", "blast_radius_score"] if c in df.columns]
        score_cols = [c for c in ["drift_score", "blast_radius_score"] if c in cols]
        st.dataframe(df[cols].style.map(_bg, subset=score_cols), use_container_width=True, hide_index=True)
    elif principals:
        # Principals exist but intent analysis hasn't generated summaries yet.
        st.info(
            f"**{len(principals)} agent(s) registered** but no behavioral baselines yet.  \n"
            "Drift and blast-radius scores appear after the behavioral analysis loop runs "
            "(every 5 min). Ingest more OTel spans to build baselines, or switch to **Lab** "
            "mode to see scenario agent data."
        )
        st.caption("Tip: run `make demo-agent` to generate activity and populate baselines.")
    else:
        st.info("No principal data. Ingest OTel spans to populate.")

    st.divider()

    # Active envelopes
    st.subheader("Active Intent Envelopes")
    if envelopes:
        for env in envelopes:
            with st.expander(
                f"**{env.get('principal_name', 'unknown')}** - `{env.get('intent_label', 'unlabeled')}`"
                f"  `[{(env.get('created_by') or 'auto').upper()}]`"
            ):
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.write(f"**Allowed Tools:** `{', '.join(env.get('allowed_tools') or ['*'])}`")
                    st.write(f"**Max Privilege:** `{env.get('max_privilege_tier', 'low')}`")
                with c2:
                    st.write(f"**Allowed Dests:** `{', '.join(env.get('allowed_destinations') or ['*'])}`")
                    st.write(f"**Created by:** `{env.get('created_by')}`")
                with c3:
                    st.write(f"**Created:** `{(env.get('created_at') or '')[:19]}`")
                    st.write(f"**Expires:** `{(env.get('expires_at') or 'no expiry')[:19]}`")
    else:
        st.info("No active intent envelopes. Created automatically from baselines or via OTel SDK `aiaap.intent.*` attributes.")

    # Create envelope UI
    st.divider()
    st.subheader("Create Intent Envelope")
    with st.expander("Define a new envelope for an agent"):
        if principals:
            p_opts = {p["name"]: p["id"] for p in principals}
            sel = st.selectbox("Agent", list(p_opts.keys()))
            label = st.text_input("Intent Label", "document_summarizer")
            tools = st.text_input("Allowed Tools (comma-separated or *)", "summarize_doc, read_file")
            dests = st.text_input("Allowed Destinations (comma-separated or *)", "*.internal")
            priv  = st.selectbox("Max Privilege Tier", ["low", "medium", "high"])
            if st.button("Create Envelope"):
                res = safe_post(f"{DETECTIONS_URL}/api/intent/envelopes", {
                    "principal_id": p_opts[sel], "tenant_id": "default",
                    "intent_label": label,
                    "allowed_tools": [t.strip() for t in tools.split(",") if t.strip()],
                    "allowed_destinations": [d.strip() for d in dests.split(",") if d.strip()],
                    "max_privilege_tier": priv,
                })
                if res:
                    st.success(f"Envelope created: id={res.get('id')}, label={res.get('intent_label')}")
                    st.rerun()
                else:
                    st.error("Failed. Check detections service logs.")

    # Violations feed
    st.divider()
    st.subheader("Recent Boundary Violations")
    SEV = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray", "info": "gray"}
    if violations:
        for f in violations[:15]:
            sev = f.get("severity", "info")
            st.markdown(f"🔴 `{f.get('created_at','')[:19]}` :{SEV.get(sev,'gray')}[**{sev.upper()}**] {f.get('title','')}")
    else:
        st.success("No boundary violations detected.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: DRIFT TIMELINE
# ══════════════════════════════════════════════════════════════════════════════
with tab_drift:
    hours = st.slider("Look-back window (hours)", 1, 168, 24, key="drift_hours")
    show_thresh = st.checkbox("Show alert threshold (60)", value=True, key="drift_thresh")

    drift_snaps = safe_get(f"{DETECTIONS_URL}/api/intent/drift-snapshots", [], {"hours": hours, "limit": 1000}) or []

    if not drift_snaps:
        st.info(
            "No drift snapshots yet. The intent loop runs every 2 min. "
            "Baselines require ~5 min of agent activity."
        )
    else:
        df_d = pd.DataFrame(drift_snaps)
        df_d["created_at"]  = pd.to_datetime(df_d["created_at"], errors="coerce", utc=True)
        df_d["drift_score"] = pd.to_numeric(df_d["drift_score"], errors="coerce").fillna(0)

        agent_names = sorted(df_d["principal_name"].dropna().unique().tolist())
        selected = st.multiselect("Agents", agent_names, default=agent_names[:min(5, len(agent_names))], key="drift_sel")
        if not selected:
            st.warning("Select at least one agent.")
        else:
            df_f = df_d[df_d["principal_name"].isin(selected)]
            colors = px.colors.qualitative.Plotly

            # Score timeline
            st.subheader("Drift Score Over Time")
            fig = go.Figure()
            for i, name in enumerate(selected):
                a = df_f[df_f["principal_name"] == name].sort_values("created_at")
                fig.add_trace(go.Scatter(
                    x=a["created_at"], y=a["drift_score"],
                    mode="lines+markers", name=name,
                    line=dict(color=colors[i % len(colors)], width=2),
                    hovertemplate=f"<b>{name}</b><br>Drift: %{{y:.1f}}<extra></extra>",
                ))
            if show_thresh:
                fig.add_hline(y=60, line_dash="dash", line_color="red",
                              annotation_text="Alert (60)", annotation_position="top right")
            fig.update_layout(**DARK_LAYOUT, yaxis=dict(range=[0, 105]), height=360,
                              margin=dict(t=20, b=40, l=20, r=20),
                              legend=dict(orientation="h", y=1.02, x=1, xanchor="right", yanchor="bottom"))
            st.plotly_chart(fig, use_container_width=True)

            # Feature breakdown
            st.subheader("Feature Contribution (Latest Snapshot)")
            focus = selected[0] if len(selected) == 1 else st.selectbox("Agent", selected, key="drift_focus")
            latest_snap = df_d[df_d["principal_name"] == focus].sort_values("created_at").iloc[-1] if not df_d[df_d["principal_name"] == focus].empty else None
            if latest_snap is not None:
                metrics = latest_snap.get("metrics") or {}
                comps = [
                    ("Call Rate (z_calls)",         "z_calls",   20),
                    ("Destinations (z_dest)",        "z_dest",    20),
                    ("Tool Entropy (z_entropy)",     "z_entropy", 20),
                    ("Privileged Ratio (z_priv)",    "z_priv",    25),
                    ("New Tools (z_new_tool)",       "z_new_tool", 15),
                ]
                labels, values, caps = [], [], []
                for lbl, key, cap in comps:
                    z = metrics.get(key, 0) or 0
                    pts = min(abs(z) * (cap / 3.0), cap)
                    labels.append(lbl); values.append(round(pts, 2)); caps.append(cap)
                bar = go.Figure(go.Bar(
                    x=labels, y=values,
                    text=[f"{v:.1f}/{c}" for v, c in zip(values, caps)],
                    textposition="outside",
                    marker_color=["#dc3545" if v >= c*0.7 else "#ffc107" if v >= c*0.4 else "#28a745"
                                  for v, c in zip(values, caps)],
                ))
                bar.update_layout(
                    **DARK_LAYOUT,
                    yaxis_title="Points", yaxis=dict(range=[0, 30]), height=300,
                    title=f"{focus} - total drift: {latest_snap['drift_score']:.1f}",
                    margin=dict(t=40, b=40, l=20, r=20),
                )
                st.plotly_chart(bar, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: BLAST RADIUS
# ══════════════════════════════════════════════════════════════════════════════
with tab_blast:
    hours_b = st.slider("Look-back window (hours)", 1, 168, 24, key="blast_hours")
    blast_snaps = safe_get(f"{DETECTIONS_URL}/api/intent/blast-snapshots", [],
                           {"hours": hours_b, "limit": 1000}) or []

    if blast_snaps:
        df_b = pd.DataFrame(blast_snaps)
        df_b["created_at"] = pd.to_datetime(df_b["created_at"], errors="coerce", utc=True)

        latest = df_b.sort_values("created_at", ascending=False).groupby("principal_name").first().reset_index()

        # Platform KPIs
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Unique Destinations", int(latest["unique_destinations_count"].sum()))
        k2.metric("Privileged Edges",    int(latest["privileged_edges_count"].sum()))
        k3.metric("New Edges (delta)",   int(latest["new_edges_count"].sum()))
        k4.metric("Max Blast Score",     f"{float(latest['blast_radius_score'].max()):.1f}")

        st.divider()

        # Bar chart by agent
        st.subheader("Blast Radius Score by Agent")
        bar = go.Figure(go.Bar(
            y=latest["principal_name"], x=latest["blast_radius_score"],
            orientation="h",
            text=latest["blast_radius_score"].apply(lambda v: f"{v:.1f}"),
            textposition="outside",
            marker_color=["#dc3545" if v >= 70 else "#ffc107" if v >= 40 else "#28a745"
                          for v in latest["blast_radius_score"]],
        ))
        bar.add_vline(x=50, line_dash="dash", line_color="red",
                      annotation_text="Alert (50)", annotation_position="top right")
        bar.update_layout(
            **DARK_LAYOUT,
            xaxis=dict(title="Score (0–100)", range=[0, 110]),
            yaxis=dict(autorange="reversed"),
            height=max(250, len(latest) * 45 + 60),
            margin=dict(t=20, b=40, l=20, r=80),
        )
        st.plotly_chart(bar, use_container_width=True)

        # Growth timeline
        st.subheader("Blast Radius Growth Timeline")
        agent_names_b = sorted(df_b["principal_name"].dropna().unique().tolist())
        sel_b = st.multiselect("Agents", agent_names_b,
                               default=agent_names_b[:min(4, len(agent_names_b))], key="blast_sel")
        if sel_b:
            df_bf = df_b[df_b["principal_name"].isin(sel_b)]
            colors = ["#6f42c1", "#dc3545", "#fd7e14", "#17a2b8", "#28a745"]
            line = go.Figure()
            for i, name in enumerate(sel_b):
                a = df_bf[df_bf["principal_name"] == name].sort_values("created_at")
                line.add_trace(go.Scatter(
                    x=a["created_at"], y=a["blast_radius_score"],
                    mode="lines+markers", name=name,
                    line=dict(color=colors[i % len(colors)], width=2),
                ))
            line.add_hline(y=50, line_dash="dash", line_color="red",
                           annotation_text="Alert (50)", annotation_position="top right")
            line.update_layout(**DARK_LAYOUT, yaxis=dict(range=[0, 110]), height=340,
                               margin=dict(t=20, b=40, l=20, r=20),
                               legend=dict(orientation="h", y=1.02, x=1, xanchor="right", yanchor="bottom"))
            st.plotly_chart(line, use_container_width=True)

        # Alerts
        st.divider()
        st.subheader("Blast Radius Alerts")
        SEV = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray"}
        if blast_finds:
            for f in blast_finds[:10]:
                sev = f.get("severity", "info")
                st.markdown(f"💥 `{f.get('created_at','')[:19]}` :{SEV.get(sev,'gray')}[**{sev.upper()}**] {f.get('title','')}")
        else:
            st.success("No blast radius alerts.")

    else:
        st.info(
            "No blast radius snapshots yet. The intent loop runs every 2 min. "
            "Snapshots are computed once agents have behavioral baselines."
        )
        with st.expander("How the score is calculated"):
            st.markdown("""
| Component | Max pts | Formula |
|---|---|---|
| Unique Destinations | 40 | Scales 0→40 over 0–20 unique dests |
| Privileged Edges | 30 | +10 per edge, capped |
| New Edges (vs 7d baseline) | 30 | Scales 0→30 over 0–10 new edges |
| **Total** | **100** | Alert threshold: ≥ 50 |
""")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4: BEHAVIORAL FINDINGS (dashboard-side baseline engine)
# ══════════════════════════════════════════════════════════════════════════════
with tab_beh:
    from utils.data_snapshot import get_snapshot

    _snap = get_snapshot(
        window_hours=24,
        include_labs=include_labs,
        mode=mode,
        _refresh_token=st.session_state.get("refresh_token", 0),
    )
    beh_findings: list[dict] = _snap.get("behavioral_findings", [])
    risk_graph:   dict       = _snap.get("agent_risk_graph", {})

    # ── KPI row ────────────────────────────────────────────────────────────
    n_critical = sum(1 for f in beh_findings if f["severity"] == "critical")
    n_high     = sum(1 for f in beh_findings if f["severity"] == "high")
    n_medium   = sum(1 for f in beh_findings if f["severity"] == "medium")
    n_agents   = len({f["agent"] for f in beh_findings})

    bk1, bk2, bk3, bk4 = st.columns(4)
    bk1.metric("Total Behavioral Findings", len(beh_findings))
    bk2.metric("Critical / High", f"{n_critical} / {n_high}",
               delta=f"+{n_critical + n_high}" if n_critical + n_high else None,
               delta_color="inverse")
    bk3.metric("Agents with Findings", n_agents)
    bk4.metric("Graph-based Blast Scores", len(risk_graph))

    st.caption(
        "Findings computed from 7-day behavioral baseline vs current 1-hour window. "
        "Includes new tools, new destinations, distribution drift, privileged ratio spikes, "
        "burst anomalies, and suspicious call sequences."
    )

    if not beh_findings:
        st.info(
            "No behavioral findings in the current 1-hour observation window.  \n"
            "Findings appear when agents deviate from their 7-day baseline. "
            "Ensure tool usages have been ingested (run `make demo-agent` to generate activity)."
        )
    else:
        st.divider()

        # ── Filters ────────────────────────────────────────────────────────
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            agent_opts  = sorted({f["agent"] for f in beh_findings})
            sel_agents  = st.multiselect("Agent", agent_opts, key="beh_agents")
        with fc2:
            type_opts   = sorted({f["finding_type"] for f in beh_findings})
            sel_types   = st.multiselect("Finding Type", type_opts, key="beh_types")
        with fc3:
            sev_opts    = ["critical", "high", "medium", "low"]
            sel_sevs    = st.multiselect("Severity", sev_opts, key="beh_sevs")

        filtered = beh_findings
        if sel_agents: filtered = [f for f in filtered if f["agent"] in sel_agents]
        if sel_types:  filtered = [f for f in filtered if f["finding_type"] in sel_types]
        if sel_sevs:   filtered = [f for f in filtered if f["severity"] in sel_sevs]

        SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

        st.subheader(f"Behavioral Findings ({len(filtered)} shown)")

        for fi in filtered:
            sev  = fi["severity"]
            icon = SEV_ICON.get(sev, "⚪")
            tool_dest = fi.get("tool") or fi.get("destination") or "-"
            header = f"{icon} **{sev.upper()}** · `{fi['agent']}` · `{fi['finding_type']}` · `{tool_dest}`"

            with st.expander(header, expanded=(sev == "critical")):
                col_ev, col_act = st.columns([3, 2])

                with col_ev:
                    st.caption("**Evidence (baseline vs observed)**")
                    ev = fi.get("evidence", {})
                    for k, v in ev.items():
                        if isinstance(v, list):
                            v = ", ".join(str(x) for x in v[:10]) + ("..." if len(v) > 10 else "")
                        st.markdown(f"- **{k}**: `{v}`")

                with col_act:
                    st.caption(f"**Confidence**: {fi['confidence']:.0%}")
                    st.markdown(f"**Recommended action:**  \n{fi['recommended_action']}")

                st.caption(f"Source: `{fi.get('source', 'behavioral_baseline')}` · "
                           f"Generated: `{fi.get('timestamp', '')[:19]} UTC`")

        st.divider()

        # ── Risk Graph: Blast Radius section ───────────────────────────────
        st.subheader("Graph-based Blast Radius")
        st.caption(
            "Computed from the access graph (agent → tool → destination). "
            "High-risk destinations, privileged tool edges, and new unseen edges "
            "all contribute to the score."
        )

        if risk_graph:
            import plotly.graph_objects as go
            sorted_agents = sorted(risk_graph.values(),
                                   key=lambda x: -x["blast_radius_score"])
            labels  = [r["agent_name"] for r in sorted_agents]
            scores  = [r["blast_radius_score"] for r in sorted_agents]
            colors  = ["#dc3545" if s >= 70 else "#ffc107" if s >= 40 else "#28a745"
                       for s in scores]

            fig = go.Figure(go.Bar(
                y=labels, x=scores,
                orientation="h",
                text=[f"{s:.1f}" for s in scores],
                textposition="outside",
                marker_color=colors,
            ))
            fig.add_vline(x=50, line_dash="dash", line_color="red",
                          annotation_text="Alert (50)", annotation_position="top right")
            fig.update_layout(
                **DARK_LAYOUT,
                xaxis=dict(title="Graph Blast Radius Score (0–100)", range=[0, 115]),
                yaxis=dict(autorange="reversed"),
                height=max(200, len(labels) * 40 + 60),
                margin=dict(t=20, b=40, l=20, r=80),
            )
            st.plotly_chart(fig, use_container_width=True)

            # "Why" breakdown table
            st.subheader("Score Breakdown")
            rows = []
            for r in sorted_agents:
                sc = r.get("score_components", {})
                rows.append({
                    "Agent":            r["agent_name"],
                    "Score":            r["blast_radius_score"],
                    "Unique Dests":     r["unique_destinations"],
                    "Privileged Edges": r["privileged_edges"],
                    "New Edges":        r["new_edges"],
                    "High-Risk Dests":  len(r.get("high_risk_destinations", [])),
                    "Why":              r["why"][:80] + "…" if len(r.get("why","")) > 80 else r.get("why",""),
                })
            import pandas as pd
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("No graph data yet - tool usages will be analysed once ingested.")
