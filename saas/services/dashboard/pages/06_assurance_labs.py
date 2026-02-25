"""
Dashboard Page 6: Assurance Labs
Tabbed: Scenario Catalogue | Run History | Coverage Matrix | Coverage Gaps

Adversarial lab scenarios for validating detection coverage and measuring
time-to-detect / time-to-contain. Operational monitoring runs continuously -
this page is for assurance testing and coverage validation.
"""

import os
from datetime import datetime, timezone, timedelta

import httpx
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from utils.data_snapshot import get_snapshot, DARK_LAYOUT

DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))
INGEST_URL     = os.getenv("INGEST_URL",     st.session_state.get("INGEST_URL",     "http://localhost:8100"))

st.set_page_config(page_title="Assurance labs | AIAAP", layout="wide")
st.title("Assurance labs")
st.info(
    "**Assurance Labs** validate your detection coverage and measure time-to-detect / time-to-contain.  \n"
    "Run scenarios to confirm the platform catches real attacks.  \n"
    "Operational monitoring runs continuously - this page is for validation and coverage analysis only."
)
st.caption(
    "14 attack simulations covering cloud, K8s, runtime, and multi-agent environments. "
    "Each scenario injects synthetic signals and evaluates whether the platform detected, prevented, or missed the threat."
)

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


# ── Scenario catalogue ────────────────────────────────────────────────────────
SCENARIOS = [
    {
        "id":          "ssrf_metadata",
        "title":       "SSRF - Cloud Metadata",
        "env":         "AWS / GCP / Azure",
        "category":    "Network",
        "severity":    "critical",
        "description": (
            "Agent calls `fetch_url` targeting the cloud IMDS endpoint (169.254.169.254). "
            "Signals: OTel span destination + eBPF blocked connection. "
            "Enforcement: Cilium NetworkPolicy."
        ),
        "signals":     ["OTel span", "eBPF network block"],
        "mitre":       "ATLAS T0011",
        "make_target": "demo-ssrf",
    },
    {
        "id":          "rbac_escalation_misconfig",
        "title":       "RBAC Escalation Misconfiguration",
        "env":         "Kubernetes",
        "category":    "Identity",
        "severity":    "high",
        "description": (
            "Misconfigured RoleBinding grants `secrets:list` across namespaces. "
            "Signals: K8s audit logs. Enforcement: Kyverno admission policy."
        ),
        "signals":     ["K8s audit log"],
        "mitre":       "ATLAS T0035",
        "make_target": "scenario-rbac",
    },
    {
        "id":          "stolen_token_usage",
        "title":       "Stolen Service Account Token",
        "env":         "Kubernetes",
        "category":    "Identity",
        "severity":    "critical",
        "description": (
            "Stolen SA token replayed from unexpected pod/IP. "
            "Signals: audit events showing unfamiliar source identity + eBPF lateral movement."
        ),
        "signals":     ["K8s audit log", "eBPF network"],
        "mitre":       "ATLAS T0025",
        "make_target": "scenario-stolen-token",
    },
    {
        "id":          "shadow_route",
        "title":       "Shadow Tool Route",
        "env":         "Kubernetes",
        "category":    "Network",
        "severity":    "high",
        "description": (
            "Agent bypasses approved tool service by calling internal host directly. "
            "Signals: eBPF DNS + network. Enforcement: CiliumNetworkPolicy egress allowlist."
        ),
        "signals":     ["OTel span", "eBPF DNS"],
        "mitre":       "ATLAS T0012",
        "make_target": "scenario-shadow-route",
    },
    {
        "id":          "overbroad_permissions",
        "title":       "Overbroad Permissions",
        "env":         "Multi-cloud",
        "category":    "Identity",
        "severity":    "high",
        "description": (
            "Agent performs privileged actions (secret write, admin reset) without a JIT grant. "
            "Signals: OTel attributes + JIT absence check."
        ),
        "signals":     ["OTel span"],
        "mitre":       "ATLAS T0033",
        "make_target": "scenario-overbroad",
    },
    {
        "id":          "confused_deputy",
        "title":       "Confused Deputy",
        "env":         "Multi-cloud",
        "category":    "Identity",
        "severity":    "critical",
        "description": (
            "Low-privilege agent induces a high-privilege downstream tool call within the same trace. "
            "Signals: OTel caller vs executor identity mismatch."
        ),
        "signals":     ["OTel span"],
        "mitre":       "ATLAS T0028",
        "make_target": "scenario-confused-deputy",
    },
    {
        "id":          "gradual_privilege_creep",
        "title":       "Gradual Privilege Creep",
        "env":         "Multi-cloud",
        "category":    "Behavioral",
        "severity":    "high",
        "description": (
            "Agent incrementally expands tool scope across 20 spans until privileged_ratio spikes. "
            "Signals: behavioral drift score exceeds alert threshold."
        ),
        "signals":     ["OTel spans", "Drift engine"],
        "mitre":       "ATLAS T0033",
        "make_target": "scenario-privilege-creep",
    },
    {
        "id":          "intent_mismatch_exfil",
        "title":       "Intent Mismatch - Exfiltration",
        "env":         "Multi-cloud",
        "category":    "Intent",
        "severity":    "high",
        "description": (
            "Agent declared as a doc-summarizer calls `fetch_url` to an external IP. "
            "Signals: intent envelope violation (disallowed tool + external destination)."
        ),
        "signals":     ["OTel span", "Intent envelope"],
        "mitre":       "ATLAS T0011",
        "make_target": "scenario-intent-mismatch",
    },
    {
        "id":          "rag_data_exfil",
        "title":       "RAG Data Exfiltration",
        "env":         "Multi-cloud",
        "category":    "Runtime",
        "severity":    "high",
        "description": (
            "RAG agent retrieves a poisoned KB document with embedded SSRF instruction. "
            "Agent then fetches external attacker IP. "
            "Signals: OTel retrieval span → fetch_url to external dest."
        ),
        "signals":     ["OTel span"],
        "mitre":       "ATLAS T0011",
        "make_target": "scenario-rag-exfil",
    },
    {
        "id":          "multi_agent_hijack",
        "title":       "Multi-Agent Prompt Hijack",
        "env":         "Multi-cloud",
        "category":    "Runtime",
        "severity":    "critical",
        "description": (
            "Orchestrator (Agent A) receives injected payload and delegates task to Worker (Agent B). "
            "Agent B executes privileged `exec_shell_command` and `read_secrets`. "
            "Signals: OTel confused-deputy across agent boundary."
        ),
        "signals":     ["OTel span"],
        "mitre":       "ATLAS T0028",
        "make_target": "scenario-multi-agent",
    },
    {
        "id":          "jit_grant_abuse",
        "title":       "JIT Grant Abuse",
        "env":         "SaaS Control Plane",
        "category":    "Identity",
        "severity":    "high",
        "description": (
            "Agent obtains narrow JIT grant (`secrets:read`) then exceeds scope "
            "(`write_secret`, `admin_reset`) + rapid burst of 10 read calls. "
            "Signals: overbroad_permissions + intent_drift."
        ),
        "signals":     ["OTel span", "JIT scope check"],
        "mitre":       "ATLAS T0033",
        "make_target": "scenario-jit-abuse",
    },
    {
        "id":          "credential_harvesting",
        "title":       "Credential Harvesting",
        "env":         "Kubernetes",
        "category":    "Runtime",
        "severity":    "critical",
        "description": (
            "Agent reads env vars, projected secrets volume, and AWS credentials file. "
            "Content submitted to runtime pack contains AWS AKIA key + GitHub token. "
            "Signals: overbroad_permissions + PII/credential leakage."
        ),
        "signals":     ["OTel span", "Runtime Pack PII"],
        "mitre":       "ATLAS T0025",
        "make_target": "scenario-credential-harvest",
    },
    {
        "id":          "lateral_movement",
        "title":       "Cross-Namespace Lateral Movement",
        "env":         "Kubernetes",
        "category":    "Network",
        "severity":    "high",
        "description": (
            "Agent probes 6 cross-namespace K8s services plus metadata IP, "
            "hitting the blast radius ceiling. "
            "Signals: blast_radius finding + ssrf_metadata."
        ),
        "signals":     ["OTel span", "Blast radius engine"],
        "mitre":       "ATLAS T0012",
        "make_target": "scenario-lateral",
    },
    {
        "id":          "supply_chain_tool",
        "title":       "Supply Chain - Shadow Tool Endpoint",
        "env":         "Multi-cloud",
        "category":    "Network",
        "severity":    "critical",
        "description": (
            "Malicious tool package intercepts approved tool calls and re-routes to attacker infra. "
            "Also injects unregistered tool `exfil_data_v2` uploading confidential data. "
            "Signals: shadow_route rule + blast_radius."
        ),
        "signals":     ["OTel span"],
        "mitre":       "ATLAS T0020",
        "make_target": "scenario-supply-chain",
    },
]

# ── Expected finding scenario_ids per scenario ────────────────────────────────
# What finding scenario_ids should appear after this scenario is run successfully.
EXPECTED_FINDINGS: dict[str, list[str]] = {
    "ssrf_metadata":             ["ssrf_metadata"],
    "rbac_escalation_misconfig": [],                             # K8s-only, no OTel findings in SaaS-local mode
    "stolen_token_usage":        [],                             # K8s-only
    "shadow_route":              [],                             # K8s-only (eBPF only)
    "overbroad_permissions":     ["overbroad_permissions"],
    "confused_deputy":           ["confused_deputy"],
    "gradual_privilege_creep":   ["behavioral_anomaly"],
    "intent_mismatch_exfil":     ["intent_boundary"],
    "rag_data_exfil":            ["ssrf_metadata"],
    "multi_agent_hijack":        ["confused_deputy"],
    "jit_grant_abuse":           ["overbroad_permissions"],
    "credential_harvesting":     ["overbroad_permissions"],
    "lateral_movement":          ["blast_radius", "ssrf_metadata"],
    "supply_chain_tool":         ["shadow_route"],
}

# ── Expected PDP enforcement outcomes per scenario ────────────────────────────
# Maps scenario_id → list of expected PDP outcome values (from enforcement_decisions)
ENFORCEMENT_EXPECTATIONS: dict[str, list[str]] = {
    "ssrf_metadata":         ["block"],
    "overbroad_permissions": ["step_up"],
    "jit_grant_abuse":       ["block"],
}

# Recommended fix for each gap type
GAP_FIX: dict[str, str] = {
    "ssrf_metadata":             "Verify eBPF sensor is deployed + Cilium NetworkPolicy active. Check `make scenario-ssrf` output.",
    "overbroad_permissions":     "Ensure OTel span has `aiaap.tool.privileged_action` attribute and no active JIT grant.",
    "confused_deputy":           "Ensure child span has mismatched `aiaap.agent.id` vs parent span.",
    "behavioral_anomaly":        "Behavioral baselines require ~5 min of baseline activity before drift is detectable.",
    "intent_boundary":           "Create an IntentEnvelope for the agent first, then run the scenario.",
    "shadow_route":              "Requires K8s + eBPF sensor. Not detectable in SaaS-local mode without connectors.",
    "blast_radius":              "Blast radius scoring requires the intent loop to have run for this agent first.",
    "pii_leakage":               "Ensure Runtime Pack service is running (`make up` includes it on port 8400).",
}

SEV_COLOR   = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray"}
CAT_ICON    = {"Network": "🌐", "Identity": "🪪", "Behavioral": "📈", "Intent": "🎯", "Runtime": "🔬"}
STATUS_COLOR = {"detected": "🟡", "prevented": "🟢", "missed": "🔴"}

# ── Load data via snapshot ─────────────────────────────────────────────────────
snap = get_snapshot(
    window_hours=24,
    include_labs=True,         # Labs page always shows all signals
    mode="Lab",
    _refresh_token=st.session_state.get("refresh_token", 0),
)
all_findings  = snap["all_findings"]
scenario_runs = snap["scenario_runs"]

cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

# Build lookups
findings_by_scenario = snap["findings_by_scenario"]
runs_by_scenario     = snap["runs_by_scenario"]

# ── KPIs ─────────────────────────────────────────────────────────────────────
total_scenarios = len(SCENARIOS)
run_ids         = {r.get("scenario_id") for r in scenario_runs}
detected_ids    = {f.get("scenario_id") for f in all_findings if f.get("status") in ("detected", "prevented")}
not_yet_run     = sum(1 for s in SCENARIOS if s["id"] not in run_ids)
coverage_pct    = int(100 * len(detected_ids & {s["id"] for s in SCENARIOS}) / total_scenarios)

# Coverage gap count
gap_count = sum(
    1 for s in SCENARIOS
    if s["id"] in run_ids                      # ran
    and EXPECTED_FINDINGS.get(s["id"])          # has expected findings
    and not any(                                # but none found
        ef in findings_by_scenario
        for ef in EXPECTED_FINDINGS[s["id"]]
    )
)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Scenarios", total_scenarios)
k2.metric("Run (all-time)", len(run_ids & {s["id"] for s in SCENARIOS}))
k3.metric("Detected / Prevented", len(detected_ids))
k4.metric("Platform Coverage", f"{coverage_pct}%")
k5.metric("Coverage Gaps", gap_count, delta=None,
          help="Scenarios that were run but expected detections were not observed.")

st.divider()

tab_run, tab_history, tab_coverage, tab_gaps = st.tabs(
    ["Scenario Catalogue", "Run History", "Coverage Matrix", "Coverage Gaps"]
)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: SCENARIO CATALOGUE
# ══════════════════════════════════════════════════════════════════════════════
with tab_run:
    st.caption(
        "Each card shows the attack pattern, environment, signals collected, and platform verdict. "
        "Run a scenario from the terminal with `make <target>` to generate live signals."
    )

    fc1, fc2 = st.columns(2)
    env_filter = fc1.multiselect("Environment", sorted({s["env"] for s in SCENARIOS}), default=[])
    cat_filter = fc2.multiselect("Category",    sorted({s["category"] for s in SCENARIOS}), default=[])

    shown = SCENARIOS
    if env_filter:
        shown = [s for s in shown if s["env"] in env_filter]
    if cat_filter:
        shown = [s for s in shown if s["category"] in cat_filter]

    for s in shown:
        sid     = s["id"]
        sev     = s["severity"]
        color   = SEV_COLOR.get(sev, "gray")
        cat_ico = CAT_ICON.get(s["category"], "📌")

        s_findings = findings_by_scenario.get(sid, [])
        s_runs     = runs_by_scenario.get(sid, [])
        if s_findings:
            statuses = [f.get("status") for f in s_findings]
            if "prevented" in statuses:
                verdict_chip = "🟢 PREVENTED"
            elif "detected" in statuses:
                verdict_chip = "🟡 DETECTED"
            else:
                verdict_chip = "🔴 MISSED"
        elif s_runs:
            expected = EXPECTED_FINDINGS.get(sid, [])
            if not expected:
                verdict_chip = "🔧 K8s/eBPF connector required"
            else:
                verdict_chip = "⏳ RAN - awaiting detection"
        else:
            verdict_chip = "⬛ NOT YET RUN"

        # TTD (time-to-detect)
        ttd_str = ""
        if s_findings and s_runs:
            latest_run   = sorted(s_runs, key=lambda r: r.get("start_at") or "", reverse=True)[0]
            first_find   = sorted(s_findings, key=lambda f: f.get("created_at") or "")[0]
            run_start    = latest_run.get("start_at") or ""
            find_created = first_find.get("created_at") or ""
            if run_start and find_created:
                try:
                    ts_run  = datetime.fromisoformat(run_start.replace("Z", "+00:00"))
                    ts_find = datetime.fromisoformat(find_created.replace("Z", "+00:00"))
                    ttd_sec = max(0, (ts_find - ts_run).total_seconds())
                    ttd_str = f"  ⏱ TTD: {int(ttd_sec)}s" if ttd_sec < 3600 else f"  ⏱ TTD: {int(ttd_sec/60)}m"
                except Exception:
                    pass

        header = (
            f"{cat_ico} **{s['title']}**  "
            f":{color}[`{sev.upper()}`]  "
            f"`{s['env']}`  "
            f"- {verdict_chip}{ttd_str}"
        )
        with st.expander(header):
            col_desc, col_meta = st.columns([3, 2])
            with col_desc:
                st.write(s["description"])
                st.write("**Signals collected:**", ", ".join(s["signals"]))
                st.write("**MITRE ATLAS:**", s["mitre"])
                st.caption(f"Run locally: `make {s['make_target']}`")
            with col_meta:
                if s_findings:
                    st.write(f"**{len(s_findings)} finding(s) on record**")
                    for f in s_findings[:3]:
                        ts      = (f.get("created_at") or "")[:19]
                        fstatus = f.get("status", "")
                        ficon   = STATUS_COLOR.get(fstatus, "⚪")
                        st.markdown(f"{ficon} `{ts}` {f.get('title','')}")
                else:
                    expected = EXPECTED_FINDINGS.get(sid, [])
                    if s_runs and not expected:
                        st.warning(
                            "Ran - requires K8s/eBPF connector for detection.  \n"
                            "No SaaS-local findings expected for this scenario."
                        )
                    elif s_runs:
                        st.info(
                            f"Ran - expected finding(s): `{'`, `'.join(expected)}`.  \n"
                            f"Check service logs or re-run: `make {s['make_target']}`"
                        )
                    else:
                        st.info(f"Not yet run - inject signals with `make {s['make_target']}`")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: RUN HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab_history:
    if not scenario_runs:
        st.info("No scenario runs recorded yet.")
        st.caption("Run `make scenario-all` to execute all 14 scenarios and populate this view.")
    else:
        import pandas as pd

        rows = []
        for r in scenario_runs:
            sid  = r.get("scenario_id", "")
            meta = next((s for s in SCENARIOS if s["id"] == sid), {})

            # TTD computation
            s_finds = findings_by_scenario.get(sid, [])
            run_start = r.get("start_at") or ""
            ttd_str = "-"
            if s_finds and run_start:
                first_find = sorted(s_finds, key=lambda f: f.get("created_at") or "")[0]
                try:
                    ts_run  = datetime.fromisoformat(run_start.replace("Z", "+00:00"))
                    ts_find = datetime.fromisoformat((first_find.get("created_at") or "").replace("Z", "+00:00"))
                    ttd_sec = max(0, (ts_find - ts_run).total_seconds())
                    ttd_str = f"{int(ttd_sec)}s" if ttd_sec < 3600 else f"{int(ttd_sec/60)}m"
                except Exception:
                    pass

            rows.append({
                "scenario":    sid,
                "title":       meta.get("title", sid),
                "status":      r.get("status", ""),
                "verdict":     r.get("verdict", ""),
                "time-to-detect": ttd_str,
                "started":     run_start[:19],
                "finished":    (r.get("end_at") or "")[:19],
            })

        df = pd.DataFrame(rows).sort_values("started", ascending=False)
        st.dataframe(df, use_container_width=True, hide_index=True)

        verdict_counts = df["verdict"].value_counts().to_dict()
        if verdict_counts:
            labels = list(verdict_counts.keys())
            values = list(verdict_counts.values())
            color_map = {"detected": "#ffc107", "prevented": "#28a745", "missed": "#dc3545", "pending": "#6c757d"}
            fig = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.4,
                marker_colors=[color_map.get(l, "#adb5bd") for l in labels],
                textfont={"color": "#e2e8f0"},
            ))
            fig.update_layout(height=280, margin=dict(t=20, b=20), title="Run Verdicts", **DARK_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: COVERAGE MATRIX
# ══════════════════════════════════════════════════════════════════════════════
with tab_coverage:
    st.subheader("Attack Surface Coverage")
    st.caption(
        "Each row is a scenario. Columns show which detection signals fired. "
        "Green = finding created, yellow = run but no finding, gray = not yet run."
    )

    SIGNAL_COLS = ["OTel span", "eBPF network", "K8s audit", "Runtime Pack", "Drift engine",
                   "Intent envelope", "Blast radius", "JIT scope"]

    matrix_rows = []
    for s in SCENARIOS:
        sid   = s["id"]
        has_f = bool(findings_by_scenario.get(sid))
        ran   = sid in run_ids
        row = {
            "Scenario":  s["title"],
            "Category":  s["category"],
            "Env":       s["env"],
            "Severity":  s["severity"].upper(),
            "Status":    "✅ Detected/Prevented" if has_f else ("⚪ Ran/No Finding" if ran else "⬛ Not Run"),
        }
        for sig in SIGNAL_COLS:
            row[sig] = "●" if sig in s["signals"] else ""
        matrix_rows.append(row)

    import pandas as pd
    df_m = pd.DataFrame(matrix_rows)
    st.dataframe(df_m, use_container_width=True, hide_index=True)

    st.divider()

    # Category distribution bar chart with dark theme
    cat_detected = {}
    cat_total    = {}
    for s in SCENARIOS:
        c = s["category"]
        cat_total[c] = cat_total.get(c, 0) + 1
        if findings_by_scenario.get(s["id"]):
            cat_detected[c] = cat_detected.get(c, 0) + 1

    cats   = sorted(cat_total.keys())
    totals = [cat_total[c] for c in cats]
    dets   = [cat_detected.get(c, 0) for c in cats]
    fig = go.Figure()
    fig.add_trace(go.Bar(name="Total Scenarios",    x=cats, y=totals, marker_color="#475569"))
    fig.add_trace(go.Bar(name="Detected/Prevented", x=cats, y=dets,   marker_color="#22c55e"))
    fig.update_layout(
        barmode="overlay", height=320,
        margin=dict(t=40, b=40, l=20, r=20),
        title="Coverage by Category",
        yaxis_title="Count",
        **DARK_LAYOUT,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Severity heatmap with dark theme
    st.subheader("Scenario Severity Distribution")
    envs = sorted({s["env"] for s in SCENARIOS})
    sevs = ["critical", "high", "medium", "low"]
    sev_env: dict[tuple, int] = {}
    for s in SCENARIOS:
        key = (s["env"], s["severity"])
        sev_env[key] = sev_env.get(key, 0) + 1

    heat_data = [[sev_env.get((e, sv), 0) for sv in sevs] for e in envs]
    fig2 = px.imshow(
        heat_data,
        x=[s.upper() for s in sevs],
        y=envs,
        color_continuous_scale="Reds",
        text_auto=True,
        labels={"color": "Count"},
        title="Scenarios: Severity × Environment",
    )
    fig2.update_traces(textfont={"color": "#ffffff"})
    fig2.update_layout(
        height=320, margin=dict(t=40, b=40),
        **DARK_LAYOUT,
        coloraxis_colorbar={"tickfont": {"color": "#e2e8f0"}},
    )
    st.plotly_chart(fig2, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4: COVERAGE GAPS
# ══════════════════════════════════════════════════════════════════════════════
with tab_gaps:
    st.subheader("Coverage Gap Analysis")
    st.caption(
        "Scenarios that were **run** but expected detections were **not observed**. "
        "These represent blind spots in your current detection coverage."
    )
    with st.expander("How does gap analysis work?", expanded=False):
        st.markdown("""
**Coverage gap** = scenario ran ✅  +  expected finding type not observed ❌

Each scenario maps to one or more `finding.scenario_id` values the correlation engine
should produce when attack signals arrive. A gap means those findings never appeared.

**Common root causes:**

| Cause | Fix |
|---|---|
| Correlator not fired yet | Wait ~15s and hit **Refresh** (findings are created on next loop) |
| Missing OTel span attribute | e.g. `aiaap.tool.privileged_action` absent → `overbroad_permissions` rule won't fire |
| No intent envelope for agent | `intent_boundary` requires an active IntentEnvelope; create one in Agents & Access |
| Behavioral baseline too small | `behavioral_anomaly` needs ≥5 baseline calls; run the scenario a second time |
| K8s/eBPF connector absent | eBPF and audit-log scenarios produce no SaaS-local findings without the connector |
| Runtime Pack not running | PII/injection scenarios require the Runtime Pack service on port 8400 |

**To close a gap:** follow the recommended fix in the gap card, re-run `make <make_target>`, then refresh.
        """)
    st.divider()

    gap_rows = []
    ok_rows  = []
    skip_rows = []

    for s in SCENARIOS:
        sid      = s["id"]
        expected = EXPECTED_FINDINGS.get(sid, [])
        ran      = sid in run_ids
        s_finds  = findings_by_scenario.get(sid, [])

        if not ran:
            skip_rows.append(s)
            continue

        if not expected:
            # K8s-only scenario; skip gap analysis
            skip_rows.append(s)
            continue

        # Check which expected finding types were observed
        observed_types = {f.get("scenario_id") for f in s_finds}
        missing = [ef for ef in expected if ef not in observed_types]

        # Time-to-detect
        s_runs    = runs_by_scenario.get(sid, [])
        ttd_str   = "-"
        if s_finds and s_runs:
            latest_run = sorted(s_runs, key=lambda r: r.get("start_at") or "", reverse=True)[0]
            first_find = sorted(s_finds, key=lambda f: f.get("created_at") or "")[0]
            try:
                ts_run  = datetime.fromisoformat((latest_run.get("start_at") or "").replace("Z", "+00:00"))
                ts_find = datetime.fromisoformat((first_find.get("created_at") or "").replace("Z", "+00:00"))
                ttd_sec = max(0, (ts_find - ts_run).total_seconds())
                ttd_str = f"{int(ttd_sec)}s" if ttd_sec < 3600 else f"{int(ttd_sec/60)}m"
            except Exception:
                pass

        row = {
            "id":       sid,
            "title":    s["title"],
            "expected": expected,
            "missing":  missing,
            "ttd":      ttd_str,
            "findings": len(s_finds),
            "fix":      GAP_FIX.get(missing[0], "Check service logs.") if missing else "",
        }
        if missing:
            gap_rows.append(row)
        else:
            ok_rows.append(row)

    # ── Gaps section ───────────────────────────────────────────────────────────
    if gap_rows:
        st.error(f"**{len(gap_rows)} gap(s) detected** - these scenarios ran but expected detections were missing.")
        for row in sorted(gap_rows, key=lambda r: len(r["missing"]), reverse=True):
            with st.expander(f"🔴 **{row['title']}** - missing: `{'`, `'.join(row['missing'])}`"):
                c1, c2 = st.columns(2)
                with c1:
                    st.write("**Expected finding type(s):**")
                    for ef in row["expected"]:
                        found = ef not in row["missing"]
                        st.markdown(f"{'✅' if found else '❌'} `{ef}`")
                    st.write(f"**Observed findings:** {row['findings']}")
                    if row["ttd"] != "-":
                        st.metric("Time-to-detect", row["ttd"])
                with c2:
                    st.warning(f"**Recommended fix:** {row['fix']}")
                    st.write(f"**Scenario ID:** `{row['id']}`")
                    st.caption(f"Re-run: `make scenario-{row['id'].replace('_', '-')}`")
    else:
        if any(s["id"] in run_ids and EXPECTED_FINDINGS.get(s["id"]) for s in SCENARIOS):
            st.success("✅ No coverage gaps detected - all run scenarios produced expected findings.")
        else:
            st.info("No scenarios with expected findings have been run yet. Run `make scenario-all` to populate this view.")

    st.divider()

    # ── Covered scenarios ──────────────────────────────────────────────────────
    if ok_rows:
        st.subheader(f"Covered Scenarios ({len(ok_rows)})")
        import pandas as pd
        df_ok = pd.DataFrame([{
            "Scenario":     r["title"],
            "Expected":     ", ".join(r["expected"]),
            "Status":       "✅ All observed",
            "Findings":     r["findings"],
            "Time-to-detect": r["ttd"],
        } for r in ok_rows])
        st.dataframe(df_ok, use_container_width=True, hide_index=True)

    # ── Skipped (not run or K8s-only) ─────────────────────────────────────────
    not_run = [s for s in skip_rows if s["id"] not in run_ids]
    k8s_only = [s for s in skip_rows if s["id"] in run_ids and not EXPECTED_FINDINGS.get(s["id"])]

    if not_run:
        with st.expander(f"⬛ Not yet run ({len(not_run)} scenarios)"):
            for s in not_run:
                st.markdown(f"- **{s['title']}** - `make {s['make_target']}`")

    if k8s_only:
        with st.expander(f"🔧 K8s connector required ({len(k8s_only)} scenarios - no SaaS-local findings expected)"):
            for s in k8s_only:
                st.markdown(f"- **{s['title']}** - requires eBPF sensor or K8s audit connector")

    # ── Enforcement Coverage (PDP Decisions) ──────────────────────────────────
    st.divider()
    st.markdown("#### Enforcement Coverage (PDP Decisions)")
    st.caption(
        "Validates that the Policy Decision Point (PDP) is actively blocking or stepping-up "
        "for scenarios that require enforcement - not just detection."
    )

    enf_decisions: list = snap.get("enforcement_decisions", [])
    if not enf_decisions:
        st.info("No PDP decisions recorded yet. Start the orchestrator with PDP_ENABLED=true and run scenarios.")
    else:
        # Build per-scenario outcome sets from decisions
        enf_outcomes_by_scenario: dict[str, set[str]] = {}
        for scenario_id, expected_outcomes in ENFORCEMENT_EXPECTATIONS.items():
            # Match decisions whose tool or trace relates to this scenario
            # We use a heuristic: find decisions where the scenario_id appears in the request payload
            matching_outcomes: set[str] = set()
            for d in enf_decisions:
                payload = d.get("request_payload") or {}
                if scenario_id in str(payload.get("agent_id", "")) or \
                   scenario_id in str(payload.get("trace_id", "")):
                    matching_outcomes.add(d.get("outcome", ""))
            enf_outcomes_by_scenario[scenario_id] = matching_outcomes

        enf_rows = []
        all_covered = True
        for scenario_id, expected_outcomes in ENFORCEMENT_EXPECTATIONS.items():
            observed = enf_outcomes_by_scenario.get(scenario_id, set())
            covered = any(eo in observed for eo in expected_outcomes)
            if not covered:
                all_covered = False
            enf_rows.append({
                "Scenario":          scenario_id,
                "Expected outcome":  ", ".join(expected_outcomes),
                "Observed outcomes": ", ".join(sorted(observed)) if observed else "none",
                "Coverage":          "✅ Covered" if covered else "❌ Gap",
            })

        import pandas as pd
        st.dataframe(pd.DataFrame(enf_rows), use_container_width=True, hide_index=True)

        if all_covered:
            st.success("✅ Enforcement coverage validated - PDP is actively enforcing all expected scenarios.")
        else:
            missing = [r["Scenario"] for r in enf_rows if r["Coverage"].startswith("❌")]
            st.warning(
                f"**{len(missing)} scenario(s)** have no matching PDP enforcement decisions: "
                f"{', '.join(missing)}. "
                "Run the orchestrator with PDP_ENABLED=true and trigger these scenarios."
            )
