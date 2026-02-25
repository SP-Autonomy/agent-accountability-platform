"""
Dashboard Page 3: Activity
Tabbed view: Tool Usage Heatmap | Access Graph

What question does this page answer?
  "What are my agents actually doing - observed tool calls and network access paths."
"""

import os
import tempfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components

from utils.dashboard_utils import (
    render_mode_selector,
    filter_principals,
    filter_usages,
)
from utils.ui_narrative import render_narrative_header, render_filter_summary

INGEST_URL     = os.getenv("INGEST_URL",     st.session_state.get("INGEST_URL",     "http://localhost:8100"))
IDENTITY_URL   = os.getenv("IDENTITY_URL",   st.session_state.get("IDENTITY_URL",   "http://localhost:8300"))
DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))

st.set_page_config(page_title="Activity | AIAAP", layout="wide")
st.title("Agent Activity")
render_narrative_header(
    outcome="What are your AI agents actually doing? Observed tool calls, network access paths, and risky destination patterns.",
    what=["Tool call heatmap (agent × tool matrix)", "Force-directed access graph with risk colouring", "Node inspector with per-agent risk, drift, and blast scores"],
    why=["Ground truth on observed behaviour (not assumed)", "Spot unexpected tools or high-risk destinations early", "Correlate access patterns with findings"],
    next_steps=["Risky destination? → Investigate finding in Detections", "Unexpected tool? → Check intent envelope in Behavioral", "New agent? → Review access in Agents & Access"],
    primary_cta={"label": "Detections", "page": "pages/05_detections.py"},
    secondary_cta={"label": "Behavioral Intelligence", "page": "pages/04_behavioral.py"},
)

# ── Sidebar: mode selector ────────────────────────────────────────────────────
with st.sidebar:
    st.divider()
    mode, include_labs = render_mode_selector()

if st.button("Refresh"):
    st.cache_data.clear()
    st.rerun()


@st.cache_data(ttl=15)
def load_tool_usages(url, signal_source: str | None = None):
    try:
        params = {"limit": 1000}
        if signal_source:
            params["signal_source"] = signal_source
        r = httpx.get(f"{url}/api/tool-usages", params=params, timeout=5.0)
        return r.json() if r.status_code == 200 else []
    except Exception:
        return []


@st.cache_data(ttl=15)
def load_principals(url):
    try:
        r = httpx.get(f"{url}/api/principals", timeout=5.0)
        return r.json() if r.status_code == 200 else []
    except Exception:
        return []


def safe_get(url: str, default=None, params: dict | None = None):
    try:
        r = httpx.get(url, timeout=5.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


# Signal source: Operational mode fetches only operational tool usages from the API,
# avoiding client-side filtering which would still download lab data.
_usage_src  = None if include_labs else "operational"
all_usages  = load_tool_usages(INGEST_URL, signal_source=_usage_src) or []
all_principals = load_principals(IDENTITY_URL) or []

# Apply mode filter (agent-level visibility)
principals = filter_principals(all_principals, include_labs)
pid_map    = {p["id"]: p["name"] for p in all_principals}  # full map for usage lookup
usages     = filter_usages(all_usages, include_labs, pid_map)
render_filter_summary(all_principals, principals, include_labs)

tab_heat, tab_topo = st.tabs(["Tool Call Heatmap", "Access Graph"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: TOOL USAGE HEATMAP
# ══════════════════════════════════════════════════════════════════════════════
with tab_heat:
    if not usages:
        st.info("No tool usage data yet. Trigger agent activity or run `make demo-agent`.")
        st.stop()

    df = pd.DataFrame(usages)
    df["timestamp"]  = pd.to_datetime(df["timestamp"], errors="coerce")
    df["agent_name"] = df["principal_id"].apply(
        lambda pid: pid_map.get(pid, f"unknown-{pid}") if pid else "unidentified"
    )

    # KPIs
    k1, k2, k3 = st.columns(3)
    k1.metric("Total Tool Calls", len(df))
    k2.metric("Unique Tools", df["tool_name"].nunique() if "tool_name" in df.columns else 0)
    k3.metric("Unique Agents", df["agent_name"].nunique())

    st.divider()

    # Heatmap
    st.subheader("Tool Call Heatmap - Agent × Tool")
    pivot = df.pivot_table(
        index="agent_name", columns="tool_name",
        values="id", aggfunc="count", fill_value=0,
    ) if "tool_name" in df.columns else pd.DataFrame()

    if not pivot.empty:
        pivot = pivot.loc[
            pivot.sum(axis=1).sort_values(ascending=False).index,
            pivot.sum(axis=0).sort_values(ascending=False).index,
        ]
        n_rows = len(pivot.index)
        fig_h  = max(320, n_rows * 42 + 140)

        fig = px.imshow(
            pivot,
            labels={"x": "Tool", "y": "Agent", "color": "Calls"},
            color_continuous_scale="RdYlGn_r",
            text_auto=True,
            aspect="auto",
        )
        fig.update_traces(textfont={"size": 11, "color": "white"}, xgap=2, ygap=2)
        fig.update_xaxes(tickangle=-40, tickfont={"size": 11, "color": "#e2e8f0"})
        fig.update_yaxes(tickfont={"size": 11, "color": "#e2e8f0"})
        fig.update_layout(
            height=fig_h,
            margin={"l": 140, "r": 20, "t": 50, "b": 100},
            coloraxis_colorbar={"title": "Calls", "thickness": 12, "tickfont": {"color": "#e2e8f0"}},
            paper_bgcolor="#1e293b",
            plot_bgcolor="#0f172a",
            font=dict(color="#e2e8f0"),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Not enough data for heatmap.")

    # High-risk destinations
    if "destination" in df.columns:
        risky = df[df["destination"].notna() & df["destination"].str.contains("169.254|metadata", na=False)]
        if not risky.empty:
            st.warning(f"⚠️ {len(risky)} calls to metadata/high-risk destinations!")
            st.dataframe(risky[["timestamp", "agent_name", "tool_name", "destination"]].head(20), use_container_width=True)
        else:
            st.success("No high-risk destinations detected in tool calls.")

    # Recent calls table
    st.subheader("Recent Tool Calls")
    display_cols = [c for c in ["timestamp", "agent_name", "tool_name", "destination", "trace_id"] if c in df.columns]
    st.dataframe(
        df[display_cols].sort_values("timestamp", ascending=False).head(200),
        use_container_width=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: ACCESS GRAPH
# ══════════════════════════════════════════════════════════════════════════════
with tab_topo:
    st.subheader("AI Agent Access Graph")
    st.caption(
        "Live force-directed graph of agent → tool → destination relationships.  \n"
        "Node colour = risk score. Use the controls to filter the view."
    )

    _HIGH_RISK_PREFIXES = ("169.254.", "metadata.google", "metadata.internal")

    def _risk_color(score: float) -> str:
        return "#e74c3c" if score >= 60 else "#f39c12" if score >= 30 else "#27ae60"

    def _is_risky_dest(dest: str) -> bool:
        return any(dest.startswith(p) for p in _HIGH_RISK_PREFIXES)

    if not principals and not usages:
        st.info("No data yet. Run `make demo-agent` or ingest some OTel spans.")
    else:
        # Build agent risk lookup from ALL principals (not filtered) so lab agents
        # that may appear via pid_map still get a risk score rather than showing 0.
        agent_risk = {p["name"]: p.get("risk_score", 0) or 0 for p in all_principals}

        tool_dest_count: dict[tuple[str, str, str], int] = {}
        for u in usages:
            agent_name = pid_map.get(u.get("principal_id"), "unknown")
            tool  = u.get("tool_name") or "unknown_tool"
            dest  = u.get("destination") or ""
            key   = (agent_name, tool, dest)
            tool_dest_count[key] = tool_dest_count.get(key, 0) + 1

        agent_options = sorted(
            {p["name"] for p in principals},
            key=lambda n: -agent_risk.get(n, 0),
        )

        # ── Top risky access paths (above graph) ──────────────────────────────
        st.subheader("Top Access Paths by Risk")
        st.caption("Highest-call agent → tool → destination triples, flagged for risk. Review 🔴 rows first.")
        top_rows = []
        for (an, tl, ds), cnt in sorted(tool_dest_count.items(), key=lambda x: -x[1])[:20]:
            if an == "unknown":
                continue
            rs = agent_risk.get(an, 0)
            risky = _is_risky_dest(ds) if ds else False
            flag  = "🔴" if risky else ("🟠" if rs >= 60 else "🟢")
            top_rows.append({"": flag, "Agent": an, "Tool": tl,
                              "Destination": ds or "-", "Calls": cnt, "Agent Risk": f"{rs:.0f}"})
        if top_rows:
            import pandas as _pd
            st.dataframe(_pd.DataFrame(top_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("No access paths yet.")

        st.divider()

        # ── Controls ──────────────────────────────────────────────────────────
        ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([3, 2, 1, 1])
        with ctrl1:
            selected_agents = st.multiselect(
                "Agents", agent_options,
                default=agent_options[:5],
                key="topo_agents",
                help="Select which agents to show in the graph.",
            )
        with ctrl2:
            min_edge_count = st.slider(
                "Min edge count", 1, 10, 2, key="topo_min_edge",
                help="Only show edges with at least this many calls.",
            )
        with ctrl3:
            show_destinations = st.toggle(
                "Destinations", True, key="topo_show_dest",
                help="Show or hide destination nodes.",
            )
        with ctrl4:
            privileged_only = st.toggle(
                "Privileged only", False, key="topo_priv_only",
                help="Show only tool calls with 'privileged_action' flag.",
            )

        # Filter usages for privileged_only mode
        build_usages = usages
        if privileged_only:
            build_usages = [
                u for u in usages
                if "privileged_action" in str(u.get("attributes", {}))
            ]
            tool_dest_count = {}
            for u in build_usages:
                agent_name = pid_map.get(u.get("principal_id"), "unknown")
                tool  = u.get("tool_name") or "unknown_tool"
                dest  = u.get("destination") or ""
                key   = (agent_name, tool, dest)
                tool_dest_count[key] = tool_dest_count.get(key, 0) + 1

        # ── Build pyvis graph ─────────────────────────────────────────────────
        try:
            from pyvis.network import Network  # type: ignore

            net = Network(
                height="580px", width="100%",
                directed=True, notebook=False,
                bgcolor="#0f172a", font_color="#e2e8f0",
            )
            net.set_options("""{
              "physics": {
                "barnesHut": {"gravitationalConstant": -4000, "springLength": 150}
              },
              "nodes": {"font": {"size": 13, "color": "#e2e8f0"}},
              "edges": {
                "arrows": {"to": {"enabled": true, "scaleFactor": 0.6}},
                "smooth": {"type": "curvedCW", "roundness": 0.1},
                "font": {"color": "#94a3b8", "size": 10, "strokeWidth": 0}
              }
            }""")

            added_nodes: set[str] = set()

            def _add_node(node_id: str, label: str, shape: str, color: str, title: str = ""):
                if node_id not in added_nodes:
                    net.add_node(node_id, label=label, shape=shape,
                                 color=color, title=title or label)
                    added_nodes.add(node_id)

            # Add selected agent nodes
            for p in principals:
                if p["name"] not in selected_agents:
                    continue
                color = _risk_color(p.get("risk_score", 0) or 0)
                _add_node(
                    f"a:{p['name']}", p["name"], "circle", color,
                    f"Agent: {p['name']}\nRisk score: {p.get('risk_score', 0):.0f}",
                )

            # Add edges: agent → tool → destination
            for (agent_name, tool, dest), count in tool_dest_count.items():
                if agent_name not in selected_agents:
                    continue
                if count < min_edge_count:
                    continue

                agent_id = f"a:{agent_name}"
                tool_id  = f"t:{tool}"
                _add_node(agent_id, agent_name, "circle",
                          _risk_color(agent_risk.get(agent_name, 0)))
                _add_node(tool_id, tool, "box", "#3b82f6",
                          f"Tool: {tool}\nCalls: {count}")
                net.add_edge(agent_id, tool_id, value=count,
                             title=f"{count} call{'s' if count > 1 else ''}",
                             color="#64748b")

                if dest and show_destinations:
                    dest_id    = f"d:{dest}"
                    dest_color = "#ef4444" if _is_risky_dest(dest) else "#64748b"
                    _add_node(dest_id, dest[:40], "diamond", dest_color,
                              f"Destination: {dest}\nConnections: {count}")
                    net.add_edge(
                        tool_id, dest_id,
                        color="#ef4444" if _is_risky_dest(dest) else "#475569",
                        title=f"{count} connection{'s' if count > 1 else ''}",
                    )

            with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
                tmp_path = f.name
            net.save_graph(tmp_path)
            # Inject dark body background so the iframe canvas matches the UI theme
            raw_html = open(tmp_path).read()
            dark_style = (
                "<style>body,html{background:#0f172a!important;margin:0;padding:0;}"
                "#mynetwork{background:#0f172a!important;}</style>"
            )
            dark_html = raw_html.replace("</head>", dark_style + "</head>", 1)
            components.html(dark_html, height=620, scrolling=False)

            st.markdown(
                "**Legend:** 🟢 Low risk &nbsp; 🟠 Medium risk &nbsp; 🔴 High risk &nbsp;"
                "| ⬛ Tool &nbsp; ◆ Destination &nbsp; 🔴◆ High-risk destination"
            )

        except ImportError:
            st.warning("pyvis not installed. Install with: `pip install pyvis`")

        st.divider()

        # ── Node inspector ────────────────────────────────────────────────────
        st.subheader("Node Inspector")
        st.caption("Select an agent to view its full access profile and related findings.")

        inspect_agent = st.selectbox(
            "Inspect agent", ["- select -"] + agent_options, key="inspect_sel",
        )

        if inspect_agent and inspect_agent != "- select -":
            principal = next((p for p in principals if p["name"] == inspect_agent), None)

            # Fetch intent summary for this agent
            intent_sums = safe_get(
                f"{DETECTIONS_URL}/api/intent/summary", [], {"hours": 24},
            ) or []
            summary = next(
                (s for s in intent_sums if s.get("principal_name") == inspect_agent), {}
            )

            if principal:
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Risk Score", f"{principal.get('risk_score', 0) or 0:.0f}")
                c2.metric("Drift Score", f"{summary.get('drift_score') or 0:.1f}")
                c3.metric("Blast Score", f"{summary.get('blast_radius_score') or 0:.1f}")
                c4.metric("Active Intent", summary.get("active_envelope") or "-")

                st.caption(
                    f"**Last seen:** {(principal.get('last_seen') or '-')[:19]}  |  "
                    f"**Namespace:** {principal.get('namespace') or '-'}  |  "
                    f"**Service account:** {principal.get('service_account') or '-'}"
                )

            # Tools and destinations used by this agent
            agent_usages = [u for u in usages if pid_map.get(u.get("principal_id")) == inspect_agent]
            tools_used   = sorted({u.get("tool_name", "?") for u in agent_usages if u.get("tool_name")})
            dests_used   = sorted({u.get("destination", "") for u in agent_usages if u.get("destination")})

            inf1, inf2 = st.columns(2)
            with inf1:
                st.write("**Tools used:**", ", ".join(tools_used) if tools_used else "-")
            with inf2:
                d_str = ", ".join(dests_used[:10]) + ("…" if len(dests_used) > 10 else "")
                st.write("**Destinations:**", d_str if dests_used else "-")

            # Related findings (last 72h), matched by agent name in title
            since_72h    = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
            all_findings = safe_get(
                f"{DETECTIONS_URL}/api/findings", [], {"since": since_72h, "limit": 100},
            ) or []
            agent_findings = [
                f for f in all_findings
                if inspect_agent.lower() in (f.get("title") or "").lower()
                or inspect_agent.lower() in str(f.get("payload") or {}).lower()
            ]
            if agent_findings:
                SEV_COLOR = {"critical": "red", "high": "orange", "medium": "blue",
                             "low": "gray", "info": "gray"}
                st.write(f"**Related findings ({len(agent_findings)}):**")
                for f in agent_findings[:5]:
                    sev   = f.get("severity", "info")
                    ts    = (f.get("created_at") or "")[:16]
                    color = SEV_COLOR.get(sev, "gray")
                    st.markdown(
                        f"- `{ts}` :{color}[**{sev.upper()}**] {f.get('title', '')} "
                        f"`{f.get('status', '')}`"
                    )
            else:
                st.caption("No recent findings directly linked to this agent.")

