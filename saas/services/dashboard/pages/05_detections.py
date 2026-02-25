"""
Dashboard Page 5: Detections
Tabbed: Security Findings | Runtime Pack (Injection / PII) | Cloud (IAM)

All security findings in one place - grouped by type, with remediation guidance
and a lightweight case workflow (status / owner / notes) per finding.
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import plotly.graph_objects as go
import streamlit as st
from utils.ui_narrative import render_narrative_header
from utils.data_snapshot import get_snapshot, DARK_LAYOUT

DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))
INGEST_URL     = os.getenv("INGEST_URL",     st.session_state.get("INGEST_URL",     "http://localhost:8100"))
RUNTIME_URL    = os.getenv("RUNTIME_URL",    st.session_state.get("RUNTIME_URL",    "http://localhost:8400"))
IDENTITY_URL   = os.getenv("IDENTITY_URL",   st.session_state.get("IDENTITY_URL",   "http://localhost:8300"))

st.set_page_config(page_title="Detections | AIAAP", layout="wide")
st.title("Detections")
render_narrative_header(
    outcome="What is your platform detecting? Correlated findings from all signal sources, grouped by scenario with actionable remediation guidance.",
    what=["Findings grouped by attack scenario with case workflow", "Severity bar chart (last 24h)", "Runtime Pack detections: injection + PII", "Cloud Coverage: IAM escalation events"],
    why=["One view across all signal types (OTel, eBPF, audit, cloud, runtime)", "Remediation guidance per scenario removes guesswork", "Case workflow tracks status from New → Closed"],
    next_steps=["Critical finding? → Follow remediation guidance and create a JIT grant if needed", "Runtime detections? → Submit content for manual analysis", "Coverage gap? → Validate in Assurance Labs"],
    primary_cta={"label": "Assurance Labs", "page": "pages/06_assurance_labs.py"},
    secondary_cta={"label": "Control Room", "page": "pages/00_control_room.py"},
)

# ── Sidebar: mode selector ─────────────────────────────────────────────────────
with st.sidebar:
    from utils.dashboard_utils import render_mode_selector
    _mode, _include_labs = render_mode_selector()

if st.button("Refresh"):
    st.cache_data.clear()
    st.session_state["refresh_token"] = st.session_state.get("refresh_token", 0) + 1
    st.rerun()


def safe_get(url, default=None, params=None):
    try:
        r = httpx.get(url, timeout=5.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


# ── Case workflow state ────────────────────────────────────────────────────────
# Persisted to /tmp/aiaap_cases.json so state survives page navigation.
_CASES_FILE = Path("/tmp/aiaap_cases.json")
CASE_STATUSES = ["New", "Triaged", "In Progress", "Contained", "Closed"]


def _load_cases() -> dict[str, dict]:
    if "cases" not in st.session_state:
        if _CASES_FILE.exists():
            try:
                st.session_state["cases"] = json.loads(_CASES_FILE.read_text())
            except Exception:
                st.session_state["cases"] = {}
        else:
            st.session_state["cases"] = {}
    return st.session_state["cases"]


def _save_cases(cases: dict) -> None:
    st.session_state["cases"] = cases
    try:
        _CASES_FILE.write_text(json.dumps(cases, indent=2))
    except Exception:
        pass


def _get_case(finding_id: int) -> dict:
    return _load_cases().get(str(finding_id), {"status": "New", "owner": "", "notes": ""})


def _set_case(finding_id: int, status: str, owner: str, notes: str) -> None:
    cases = _load_cases()
    cases[str(finding_id)] = {
        "status": status, "owner": owner, "notes": notes,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_cases(cases)


# ── Remediation guidance ───────────────────────────────────────────────────────
REMEDIATION = {
    "ssrf_metadata":             "Apply Cilium egress policy to block 169.254.0.0/16. Ensure follow_redirects=False in HTTP clients.",
    "overbroad_permissions":     "Create a JIT grant in Agents & Access → JIT Grants. Add SDK-level scope checks.",
    "confused_deputy":           "Verify aiaap.agent.id OTel attribute matches expected identity. Add identity validation at tool entry points.",
    "prompt_injection":          "Review prompt input source for adversarial instructions. Enable runtime content filtering.",
    "pii_leakage":               "Check tool outputs for PII. Enable PII masking via Runtime Pack analyze endpoint.",
    "behavioral_anomaly":        "Investigate tool usage deviation. Compare recent calls vs baseline. Consider JIT grant for anomalous actions.",
    "rbac_escalation_misconfig": "Remove wildcard RBAC permissions. Apply least-privilege via Kyverno admission control.",
    "stolen_token_usage":        "Rotate compromised SA token. Enable short-lived tokens (TokenRequest API). Check eBPF lateral movement events.",
    "iam_escalation":            "Review CloudTrail actor. Revoke overpermissive IAM roles. Enable AWS IAM Access Analyzer and SCP guardrails.",
    "intent_boundary":           "Review declared intent envelope for this agent. Check allowed_tools and allowed_destinations.",
    "intent_drift":              "Investigate spike in privileged_ratio or new tools. Compare recent vs baseline behaviour.",
    "blast_radius":              "Agent has reached an unusually large number of destinations/resources. Review access scope.",
    "shadow_route":              "Audit tool endpoint registry. Verify tool service DNS resolution. Apply CiliumNetworkPolicy egress allowlist.",
    "rag_data_exfil":            "Review RAG data sources for poisoned documents. Validate all external HTTP calls from agents.",
    "multi_agent_hijack":        "Audit cross-agent delegation patterns. Enforce identity attestation across agent boundaries.",
    "jit_grant_abuse":           "Review JIT grant scope. Implement scope-checking SDK wrapper for tool calls.",
    "credential_harvesting":     "Restrict file read access in container. Use projected volumes with short-lived tokens. Rotate exposed credentials.",
    "lateral_movement":          "Apply Cilium NetworkPolicy to restrict cross-namespace egress. Review service mesh RBAC.",
    "supply_chain_tool":         "Audit tool endpoint registry. Pin tool package versions. Verify tool service DNS resolution.",
    "gradual_privilege_creep":   "Audit agent's recent tool call history. Require JIT grant for any privileged actions.",
    "intent_mismatch_exfil":     "Review agent task assignment. Tighten intent envelope allowed_tools. Monitor external destination calls.",
}

# Recommended CTA button per scenario
REMEDIATION_ACTIONS = {
    "overbroad_permissions":     ("Create JIT Grant", "pages/02_agents_access.py"),
    "intent_boundary":           ("Define Intent Envelope", "pages/04_behavioral.py"),
    "intent_drift":              ("View Behavioral Intelligence", "pages/04_behavioral.py"),
    "blast_radius":              ("View Blast Radius", "pages/04_behavioral.py"),
    "behavioral_anomaly":        ("View Behavioral Intelligence", "pages/04_behavioral.py"),
    "ssrf_metadata":             ("View Activity Graph", "pages/03_activity.py"),
    "confused_deputy":           ("Review Agents", "pages/02_agents_access.py"),
    "jit_grant_abuse":           ("Manage JIT Grants", "pages/02_agents_access.py"),
    "gradual_privilege_creep":   ("View Behavioral Intelligence", "pages/04_behavioral.py"),
}

SEV_COLOR  = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray", "info": "gray"}
STATUS_ICON = {"prevented": "🟢", "detected": "🟡", "missed": "🔴"}

CASE_STATUS_COLOR = {
    "New": "🔴", "Triaged": "🟠", "In Progress": "🟡", "Contained": "🔵", "Closed": "🟢",
}

cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

# ── Load data via snapshot ─────────────────────────────────────────────────────
snap = get_snapshot(
    window_hours=24,
    include_labs=_include_labs,
    mode=_mode,
    _refresh_token=st.session_state.get("refresh_token", 0),
)
all_findings = snap["all_findings"]
rt_detections = safe_get(f"{RUNTIME_URL}/api/runtime/detections", [], {"limit": 300}) or []

_sig_label = "operational signals only" if not _include_labs else "all signals (lab + operational)"
st.caption(f"Showing findings from **{_sig_label}** · fetched {snap['fetched_at'][:19]} UTC")

# Global KPIs
open_count = len([f for f in all_findings if f.get("status") in ("detected", "prevented")])
high_count = len([f for f in all_findings if f.get("severity") in ("high", "critical") and f.get("created_at","") >= cutoff_24h])
rt_24h     = [d for d in rt_detections if (d.get("timestamp") or "") >= cutoff_24h]

k1, k2, k3, k4 = st.columns(4)
k1.metric("Total Open Findings", open_count)
k2.metric("High/Critical (24h)", high_count)
k3.metric("Runtime Detections (24h)", len(rt_24h))
k4.metric("Cloud Events", len([f for f in all_findings if f.get("scenario_id") == "iam_escalation"]))

st.divider()

tab_sec, tab_rt, tab_cloud, tab_beh, tab_enforce = st.tabs([
    "Security Findings", "Runtime Pack", "Cloud Coverage", "Behavioral Findings", "Enforcement"
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: SECURITY FINDINGS
# ══════════════════════════════════════════════════════════════════════════════
with tab_sec:
    # Severity bar chart (24h) with dark theme
    findings_24h = [f for f in all_findings if f.get("created_at","") >= cutoff_24h]
    if findings_24h:
        sev_counts: dict[str, int] = defaultdict(int)
        for f in findings_24h:
            sev_counts[f.get("severity", "info")] += 1
        ordered = ["critical", "high", "medium", "low", "info"]
        colors  = ["#6f42c1", "#dc3545", "#ffc107", "#17a2b8", "#6c757d"]
        labels  = [s for s in ordered if s in sev_counts]
        values  = [sev_counts[s] for s in labels]
        clrs    = [colors[ordered.index(s)] for s in labels]
        fig = go.Figure(go.Bar(
            x=labels, y=values, marker_color=clrs,
            text=values, textposition="outside",
            textfont={"color": "#e2e8f0"},
        ))
        fig.update_layout(
            height=260, margin=dict(t=20, b=40, l=20, r=20),
            yaxis_title="Count", xaxis_title=None,
            title="Findings by Severity (last 24h)",
            **DARK_LAYOUT,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No findings in the last 24 hours.")

    st.subheader("Findings by Scenario")
    status_filter = st.multiselect("Status", ["detected", "prevented", "missed"], default=[])
    sev_filter    = st.multiselect("Severity", ["critical", "high", "medium", "low", "info"], default=[])

    filtered = all_findings
    if status_filter:
        filtered = [f for f in filtered if f.get("status") in status_filter]
    if sev_filter:
        filtered = [f for f in filtered if f.get("severity") in sev_filter]

    # Group by scenario
    by_scenario: dict[str, list] = defaultdict(list)
    for f in filtered:
        by_scenario[f.get("scenario_id") or "other"].append(f)

    for scenario_id, s_findings in sorted(by_scenario.items(), key=lambda x: len(x[1]), reverse=True):
        sev_counts_s = defaultdict(int)
        for f in s_findings:
            sev_counts_s[f.get("severity","info")] += 1
        severity_label = " ".join([
            f"`{v}×{s}`" for s, v in sorted(sev_counts_s.items(),
            key=lambda x: ["critical","high","medium","low","info"].index(x[0])
            if x[0] in ["critical","high","medium","low","info"] else 99)
        ])

        # Count case statuses for this scenario group
        cases_this = {str(f["id"]): _get_case(f["id"]) for f in s_findings}
        closed_n   = sum(1 for c in cases_this.values() if c["status"] == "Closed")
        open_n     = len(cases_this) - closed_n

        with st.expander(
            f"**{scenario_id}** - {len(s_findings)} finding(s)  {severity_label}"
            f"  `{open_n} open / {closed_n} closed`"
        ):
            remediation = REMEDIATION.get(scenario_id)
            if remediation:
                st.info(f"**Remediation:** {remediation}")

            # CTA button
            action = REMEDIATION_ACTIONS.get(scenario_id)
            if action:
                label, page = action
                if st.button(f"→ {label}", key=f"cta_{scenario_id}"):
                    st.switch_page(page)

            st.divider()

            for f in s_findings[:10]:
                fid    = f.get("id", 0)
                sev    = f.get("severity", "info")
                status = f.get("status", "detected")
                ts     = (f.get("created_at") or "")[:19]
                icon   = STATUS_ICON.get(status, "⚪")
                color  = SEV_COLOR.get(sev, "gray")
                case   = _get_case(fid)
                case_icon = CASE_STATUS_COLOR.get(case["status"], "⚪")

                # Finding row + inline case status
                c_find, c_case = st.columns([3, 1])
                with c_find:
                    st.markdown(
                        f"{icon} `{ts}` :{color}[**{sev.upper()}**] {f.get('title','')} `{status}`"
                    )
                with c_case:
                    st.caption(f"{case_icon} {case['status']}")

                # Case workflow inline - Streamlit forbids nested expanders
                cc1, cc2, cc3, cc_btn = st.columns([2, 2, 4, 1])
                with cc1:
                    new_status = st.selectbox(
                        "Status", CASE_STATUSES,
                        index=CASE_STATUSES.index(case["status"]),
                        key=f"case_status_{fid}",
                        label_visibility="collapsed",
                    )
                with cc2:
                    new_owner = st.text_input(
                        "Owner", value=case.get("owner", ""),
                        key=f"case_owner_{fid}", placeholder="@analyst",
                        label_visibility="collapsed",
                    )
                with cc3:
                    new_notes = st.text_input(
                        "Notes", value=case.get("notes", ""),
                        key=f"case_notes_{fid}",
                        placeholder="Investigation notes…",
                        label_visibility="collapsed",
                    )
                with cc_btn:
                    if st.button("💾", key=f"case_save_{fid}", help="Save case"):
                        _set_case(fid, new_status, new_owner, new_notes)
                        st.success("Saved.")
                        st.rerun()
                if case.get("updated_at"):
                    st.caption(f"📋 Case #{fid} · last updated {case['updated_at'][:19]} UTC")
                st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: RUNTIME PACK
# ══════════════════════════════════════════════════════════════════════════════
with tab_rt:
    try:
        r = httpx.get(f"{RUNTIME_URL}/health", timeout=2.0)
        runtime_ok = r.status_code == 200
    except Exception:
        runtime_ok = False

    if not runtime_ok:
        st.warning("Runtime Pack service not reachable. Start with `make up`.")
        st.caption("The Runtime Pack analyzes agent message content for prompt injection and PII leakage.")
    else:
        st.success("Runtime Pack ✅ connected")

    if rt_24h:
        inj_count = len([d for d in rt_24h if d.get("detector_type") == "injection"])
        pii_count = len([d for d in rt_24h if d.get("detector_type") == "pii"])
        k1, k2, k3 = st.columns(3)
        k1.metric("Injections (24h)", inj_count)
        k2.metric("PII Leakages (24h)", pii_count)
        k3.metric("Total Analyzed (24h)", len(rt_24h))

        fig = go.Figure(go.Pie(
            labels=["Injection", "PII"],
            values=[inj_count, pii_count],
            hole=0.45,
            marker_colors=["#dc3545", "#fd7e14"],
            textfont={"color": "#e2e8f0"},
        ))
        fig.update_layout(
            height=280, margin=dict(t=20, b=20, l=20, r=20), showlegend=True,
            **DARK_LAYOUT,
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recent Detections")
        for d in rt_24h[:20]:
            dtype = d.get("detector_type", "?")
            sev   = d.get("severity", "info")
            conf  = d.get("confidence", 0)
            ts    = (d.get("timestamp") or "")[:19]
            agent = d.get("agent_id", "?")
            icon  = "💉" if dtype == "injection" else "🔒"
            color = SEV_COLOR.get(sev, "gray")
            with st.expander(f"{icon} `{ts}` {agent} - :{color}[**{sev.upper()}**] {dtype} (conf: {conf:.0%})"):
                sig = d.get("signal", {})
                if dtype == "injection":
                    st.write("**Categories matched:**", sig.get("categories_matched", []))
                    st.write("**Score:**", sig.get("score"))
                elif dtype == "pii":
                    st.write("**PII types:**", list(sig.get("types_found", {}).keys()))
                    masked = sig.get("masked_snippet") or sig.get("masked_content", "")
                    if masked:
                        st.code(masked[:500], language=None)
    else:
        st.info("No runtime detections in the last 24 hours.")

    st.divider()
    st.subheader("Analyze Content Manually")
    with st.expander("Submit content for injection / PII analysis"):
        direction = st.radio("Direction", ["request", "response"], horizontal=True)
        content   = st.text_area("Content", height=100, placeholder="Paste agent prompt or response here...")
        agent_id  = st.text_input("Agent ID (optional)", "manual-test")
        if st.button("Analyze") and content:
            if runtime_ok:
                try:
                    r = httpx.post(
                        f"{RUNTIME_URL}/api/runtime/analyze",
                        json={"tenant_id": "default", "agent_id": agent_id,
                              "direction": direction, "content": content},
                        timeout=10.0,
                    )
                    res = r.json()
                    if res.get("has_injection"):
                        st.error(f"**Injection detected** - severity: {res.get('max_severity')}")
                        st.write("Categories:", res.get("injection", {}).get("categories_matched", []))
                    elif res.get("has_pii"):
                        st.warning(f"**PII detected** - types: {list(res.get('pii',{}).get('types_found',{}).keys())}")
                        st.code(res.get("pii",{}).get("masked_content","")[:500])
                    else:
                        st.success("No injection or PII detected.")
                except Exception as e:
                    st.error(f"Analysis failed: {e}")
            else:
                st.error("Runtime service not running.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: CLOUD COVERAGE
# ══════════════════════════════════════════════════════════════════════════════
with tab_cloud:
    cloud_events = safe_get(f"{INGEST_URL}/api/events", [], {"source": "cloud", "limit": 100}) or []
    iam_findings = safe_get(f"{DETECTIONS_URL}/api/findings", [], {"scenario_id": "iam_escalation", "limit": 50}) or []

    cloud_24h = [e for e in cloud_events if (e.get("timestamp") or "") >= cutoff_24h]
    iam_24h   = [f for f in iam_findings  if (f.get("created_at") or "") >= cutoff_24h]

    if cloud_24h:
        st.success("🟢 **AWS CloudTrail Connector** - events received in last 24h")
    elif cloud_events:
        st.warning("🟡 **AWS CloudTrail Connector** - last event > 24h ago")
    else:
        st.info("⚪ **AWS CloudTrail Connector** - no cloud events received yet")
        st.caption("Deploy the CloudTrail forwarder: `cd connectors/aws/cloudtrail_forwarder && sam deploy --guided`")
        st.caption("Or inject a synthetic event: `make demo-ingest-iam`")

    k1, k2, k3 = st.columns(3)
    k1.metric("Cloud Events (24h)", len(cloud_24h))
    k2.metric("IAM Findings", len(iam_findings))
    k3.metric("IAM Findings (24h)", len(iam_24h))

    if iam_findings:
        st.subheader("IAM Escalation Findings")
        for f in iam_findings[:15]:
            sev   = f.get("severity", "info")
            ts    = (f.get("created_at") or "")[:19]
            color = SEV_COLOR.get(sev, "gray")
            with st.expander(f"🔐 `{ts}` :{color}[**{sev.upper()}**] {f.get('title','')}"):
                payload = f.get("payload") or {}
                if payload:
                    st.write("**Event Name:**", payload.get("eventName", "-"))
                    st.write("**Actor:**", payload.get("userIdentity", {}).get("arn", "-"))
                    st.write("**Region:**", payload.get("awsRegion", "-"))
                    req = payload.get("requestParameters") or {}
                    if req.get("roleName") or req.get("policyArn"):
                        st.write("**Affected Resource:**", req.get("roleName") or req.get("policyArn"))
                st.write("**Remediation:**", REMEDIATION.get("iam_escalation", "Review CloudTrail events."))

    if cloud_events:
        with st.expander(f"Recent Cloud Events ({len(cloud_events)})"):
            import pandas as pd
            df_c = pd.DataFrame([{
                "timestamp":  (e.get("timestamp") or "")[:19],
                "event_type": e.get("event_type"),
                "severity":   e.get("severity"),
                "dest":       e.get("dest"),
            } for e in cloud_events[:50]])
            st.dataframe(df_c, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4: BEHAVIORAL FINDINGS (baseline engine - no DB required)
# ══════════════════════════════════════════════════════════════════════════════
with tab_beh:
    import pandas as pd
    beh_findings: list[dict] = snap.get("behavioral_findings", [])

    n_crit = sum(1 for f in beh_findings if f["severity"] == "critical")
    n_high = sum(1 for f in beh_findings if f["severity"] == "high")
    bk1, bk2, bk3 = st.columns(3)
    bk1.metric("Total Behavioral Findings", len(beh_findings))
    bk2.metric("Critical / High", f"{n_crit} / {n_high}",
               delta=f"+{n_crit + n_high}" if n_crit + n_high else None,
               delta_color="inverse")
    bk3.metric("Agents Affected", len({f["agent"] for f in beh_findings}))

    st.caption(
        "Real-time behavioral analysis comparing the last 1 hour of activity to a 7-day baseline. "
        "These findings are computed client-side from the snapshot and complement the backend "
        "behavioral engine findings in Security Findings."
    )

    if not beh_findings:
        st.info(
            "No behavioral deviations detected in the current 1-hour window.  \n"
            "Findings appear when activity diverges from the 7-day baseline."
        )
    else:
        # ── Filters ──────────────────────────────────────────────────────────
        bf1, bf2, bf3 = st.columns(3)
        with bf1:
            b_agents = sorted({f["agent"] for f in beh_findings})
            b_sel_a  = st.multiselect("Filter by Agent", b_agents, key="bfind_agents")
        with bf2:
            b_types  = sorted({f["finding_type"] for f in beh_findings})
            b_sel_t  = st.multiselect("Filter by Type", b_types, key="bfind_types")
        with bf3:
            b_sel_s  = st.multiselect("Filter by Severity",
                                       ["critical", "high", "medium", "low"],
                                       key="bfind_sevs")

        bfilt = beh_findings
        if b_sel_a: bfilt = [f for f in bfilt if f["agent"] in b_sel_a]
        if b_sel_t: bfilt = [f for f in bfilt if f["finding_type"] in b_sel_t]
        if b_sel_s: bfilt = [f for f in bfilt if f["severity"] in b_sel_s]

        # ── Summary table ─────────────────────────────────────────────────
        st.subheader(f"Behavioral Findings ({len(bfilt)} shown)")
        SEV_ICON_B = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
        for fi in bfilt:
            sev  = fi["severity"]
            icon = SEV_ICON_B.get(sev, "⚪")
            tool_dest = fi.get("tool") or fi.get("destination") or "-"
            label = f"{icon} **{sev.upper()}** · `{fi['agent']}` · `{fi['finding_type']}` · `{tool_dest[:50]}`"

            # Include in case workflow
            case_id = f"beh_{fi['agent']}_{fi['finding_type']}_{(fi.get('tool') or fi.get('destination') or '')[:20]}"
            case    = _get_case(hash(case_id) % (10**9))

            with st.expander(f"{CASE_STATUS_COLOR.get(case['status'], '⚪')} {label}"):
                ev_col, action_col = st.columns([3, 2])

                with ev_col:
                    st.caption("**Evidence**")
                    for k, v in (fi.get("evidence") or {}).items():
                        if isinstance(v, list):
                            v = ", ".join(str(x) for x in v[:8]) + ("..." if len(v) > 8 else "")
                        st.markdown(f"- **{k}**: `{v}`")

                with action_col:
                    st.caption(f"**Confidence:** {fi['confidence']:.0%}")
                    st.markdown(f"**Action:**  \n{fi['recommended_action']}")
                    remediation = REMEDIATION.get(
                        "behavioral_anomaly" if "drift" in fi["finding_type"] or "privileged" in fi["finding_type"]
                        else fi.get("finding_type", ""),
                        None
                    )
                    if remediation:
                        st.caption(f"*{remediation}*")

                # Case workflow
                fhash = hash(case_id) % (10**9)
                c1, c2 = st.columns(2)
                with c1:
                    new_status = st.selectbox("Status", CASE_STATUSES,
                                              index=CASE_STATUSES.index(case["status"]),
                                              key=f"bst_{fhash}")
                    new_owner  = st.text_input("Owner", case["owner"], key=f"bow_{fhash}")
                with c2:
                    new_notes  = st.text_area("Notes", case["notes"],
                                              height=80, key=f"bnt_{fhash}")
                    if st.button("Save Case", key=f"bsave_{fhash}"):
                        _set_case(fhash, new_status, new_owner, new_notes)
                        st.success("Saved.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5: ENFORCEMENT (PDP decisions)
# ══════════════════════════════════════════════════════════════════════════════
with tab_enforce:
    st.subheader("Policy Enforcement Decisions")
    st.caption("Every tool-call pre-flight evaluation by the Policy Decision Point (PDP). Decisions are recorded for audit and incident response.")

    decisions: list = snap.get("enforcement_decisions", [])

    if not decisions:
        st.info("No enforcement decisions recorded yet. The PDP runs when the orchestrator is started with PDP_ENABLED=true.")
    else:
        # KPI row
        total_d   = len(decisions)
        blocked   = sum(1 for d in decisions if d.get("outcome") == "block")
        step_up   = sum(1 for d in decisions if d.get("outcome") == "step_up")
        sandboxed = sum(1 for d in decisions if d.get("outcome") == "sandbox")
        rate_ltd  = sum(1 for d in decisions if d.get("outcome") == "rate_limit")
        allowed_d = sum(1 for d in decisions if d.get("outcome") == "allow")

        kc1, kc2, kc3, kc4, kc5 = st.columns(5)
        kc1.metric("Total Decisions", total_d)
        kc2.metric("Blocked", blocked, delta=None,
                   help="High-risk destination, invalid JIT grant, or scope mismatch")
        kc3.metric("Step-Up Required", step_up,
                   help="Privileged tool called without JIT grant - agent must request one")
        kc4.metric("Sandboxed", sandboxed,
                   help="Intent envelope violation - tool/dest outside declared behaviour")
        kc5.metric("Rate Limited", rate_ltd)

        st.divider()

        # Group by outcome
        by_outcome: dict[str, list] = defaultdict(list)
        for d in decisions:
            by_outcome[d.get("outcome", "unknown")].append(d)

        OUTCOME_LABELS = {
            "block":      ("🚫 BLOCK",        "#dc3545"),
            "step_up":    ("⬆ STEP-UP",       "#fd7e14"),
            "sandbox":    ("📦 SANDBOX",       "#6f42c1"),
            "rate_limit": ("⏱ RATE LIMIT",    "#ffc107"),
            "allow":      ("✅ ALLOW",         "#28a745"),
        }
        OUTCOME_ORDER = ["block", "step_up", "sandbox", "rate_limit", "allow"]

        for outcome_key in OUTCOME_ORDER:
            rows = by_outcome.get(outcome_key, [])
            if not rows:
                continue
            label, _ = OUTCOME_LABELS.get(outcome_key, (outcome_key.upper(), "#6c757d"))
            with st.expander(f"{label} - {len(rows)} decision(s)", expanded=(outcome_key != "allow")):
                import pandas as pd
                table_rows = []
                for d in rows:
                    ts = (d.get("created_at") or "")[:19].replace("T", " ")
                    table_rows.append({
                        "Time (UTC)":    ts,
                        "Tool":          d.get("tool_name") or "-",
                        "Destination":   (d.get("destination") or "-")[:50],
                        "Reason":        (d.get("reason") or "")[:90],
                        "Rules Fired":   ", ".join(d.get("rules_fired") or []),
                        "Principal ID":  str(d.get("principal_id") or "-"),
                        "Trace":         (d.get("trace_id") or "-")[:12],
                    })
                st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
