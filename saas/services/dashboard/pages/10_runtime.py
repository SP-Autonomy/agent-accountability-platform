"""
Dashboard Page 10: Runtime Pack (AIRS)
---------------------------------------
Dedicated view for the AIRS Runtime Security Pack:
- Prompt injection detections (7 categories)
- PII leakage detections & masking (12 types)
- Trend chart over time
- Manual content analysis form
"""

import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import httpx
import plotly.graph_objects as go
import streamlit as st
from utils.ui_narrative import render_narrative_header
from utils.data_snapshot import DARK_LAYOUT

RUNTIME_URL    = os.getenv("RUNTIME_URL",    st.session_state.get("RUNTIME_URL",    "http://localhost:8400"))
DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))

st.set_page_config(page_title="Runtime Pack | AIAAP", layout="wide")
st.title("Runtime Pack (AIRS)")
render_narrative_header(
    outcome="Server-side prompt injection and PII detection - no inline proxy, no latency tax on the agent path.",
    what=["Injection detections: 7 categories (role manipulation, jailbreak, obfuscation, etc.)", "PII leakage: 12 types detected and masked", "Content analyzed server-side without storing raw prompts"],
    why=["Detect adversarial instructions before agents act on them", "Prevent sensitive data from leaking through tool responses", "Complement OTel/eBPF signals with content-layer visibility"],
    next_steps=["Injection detected? → Review prompt source, enable filtering in Detections", "PII found? → Mask at source and check tool response pipeline", "Coverage gap? → Submit content manually for analysis below"],
    primary_cta={"label": "Security Findings", "page": "pages/05_detections.py"},
    secondary_cta={"label": "Control Room", "page": "pages/00_control_room.py"},
)

if st.button("Refresh"):
    st.rerun()


def safe_get(url: str, default=None, params: dict | None = None):
    try:
        r = httpx.get(url, timeout=5.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


# ── Runtime service health check ─────────────────────────────────────────────
try:
    r = httpx.get(f"{RUNTIME_URL}/health", timeout=2.0)
    runtime_ok = r.status_code == 200
    health_data = r.json() if runtime_ok else {}
except Exception:
    runtime_ok = False
    health_data = {}

if not runtime_ok:
    st.error(
        "**Runtime Pack service not reachable.**  \n"
        "Start all services with `make up` - the runtime service runs on port 8400.  \n"
        "Check logs with `docker compose -f saas/docker-compose.yml logs runtime`."
    )
    st.info("The Runtime Pack analyzes agent prompt content and tool responses for adversarial patterns and sensitive data, without storing raw content.")
    st.stop()

st.success(f"✅ Runtime Pack connected - v{health_data.get('version', '?')} on {RUNTIME_URL}")
st.divider()

# ── Fetch runtime detections ─────────────────────────────────────────────────
cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
cutoff_7d  = datetime.now(timezone.utc) - timedelta(days=7)


def _after(ts_str: str | None, cutoff: datetime) -> bool:
    if not ts_str:
        return False
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt >= cutoff
    except ValueError:
        return False


all_detections = safe_get(f"{RUNTIME_URL}/api/runtime/detections", [], {"limit": 500}) or []
rt_24h = [d for d in all_detections if _after(d.get("timestamp"), cutoff_24h)]
rt_7d  = [d for d in all_detections if _after(d.get("timestamp"), cutoff_7d)]

inj_24h = [d for d in rt_24h if d.get("detector_type") == "injection"]
pii_24h = [d for d in rt_24h if d.get("detector_type") == "pii"]

# Correlated findings from detections service
rt_findings = safe_get(f"{DETECTIONS_URL}/api/findings", [], {"limit": 200}) or []
inj_findings = [f for f in rt_findings if f.get("scenario_id") == "prompt_injection"]
pii_findings = [f for f in rt_findings if f.get("scenario_id") == "pii_leakage"]

# ── KPI Cards ────────────────────────────────────────────────────────────────
k1, k2, k3, k4 = st.columns(4)
k1.metric("Injections (24h)",    len(inj_24h), delta=f"{len(inj_24h)} new" if inj_24h else None, delta_color="inverse")
k2.metric("PII Leakages (24h)", len(pii_24h), delta=f"{len(pii_24h)} new" if pii_24h else None, delta_color="inverse")
k3.metric("Content Analyzed (24h)", len(rt_24h))
k4.metric("Correlated Findings", len(inj_findings) + len(pii_findings))

st.divider()

# ── Charts ───────────────────────────────────────────────────────────────────
chart_l, chart_r = st.columns(2)

with chart_l:
    st.subheader("Detection Type Distribution (24h)")
    if rt_24h:
        fig = go.Figure(go.Pie(
            labels=["Injection", "PII"],
            values=[len(inj_24h), len(pii_24h)],
            hole=0.45,
            marker_colors=["#dc3545", "#fd7e14"],
            textinfo="label+value+percent",
        ))
        fig.update_layout(**DARK_LAYOUT, height=280, margin=dict(t=20, b=20, l=20, r=20), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No runtime detections in the last 24 hours.")

with chart_r:
    st.subheader("Severity Distribution (24h)")
    if rt_24h:
        sev_counts: dict[str, int] = defaultdict(int)
        for d in rt_24h:
            sev_counts[d.get("severity", "info")] += 1
        ordered = ["critical", "high", "medium", "low", "info"]
        colors  = ["#6f42c1", "#dc3545", "#ffc107", "#17a2b8", "#6c757d"]
        labels  = [s for s in ordered if s in sev_counts]
        values  = [sev_counts[s] for s in labels]
        clrs    = [colors[ordered.index(s)] for s in labels]
        fig2 = go.Figure(go.Bar(
            x=labels, y=values, marker_color=clrs,
            text=values, textposition="outside",
        ))
        fig2.update_layout(**DARK_LAYOUT, height=280, margin=dict(t=20, b=40, l=20, r=20),
                           yaxis_title="Count", xaxis_title=None)
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No severity data available.")

# ── Trend chart (last 7 days, hourly buckets) ─────────────────────────────────
if rt_7d:
    st.subheader("Detection Trend (last 7 days)")
    hourly_inj: dict[str, int] = defaultdict(int)
    hourly_pii: dict[str, int] = defaultdict(int)
    for d in rt_7d:
        ts = d.get("timestamp", "")[:13]  # "2024-01-15T14"
        if d.get("detector_type") == "injection":
            hourly_inj[ts] += 1
        else:
            hourly_pii[ts] += 1

    all_hours = sorted(set(hourly_inj) | set(hourly_pii))
    if all_hours:
        fig3 = go.Figure()
        fig3.add_trace(go.Scatter(
            x=all_hours, y=[hourly_inj.get(h, 0) for h in all_hours],
            mode="lines+markers", name="Injection",
            line=dict(color="#dc3545", width=2),
        ))
        fig3.add_trace(go.Scatter(
            x=all_hours, y=[hourly_pii.get(h, 0) for h in all_hours],
            mode="lines+markers", name="PII",
            line=dict(color="#fd7e14", width=2),
        ))
        fig3.update_layout(
            **DARK_LAYOUT,
            height=220, margin=dict(t=10, b=40, l=20, r=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            yaxis_title="Count", xaxis_title=None,
        )
        st.plotly_chart(fig3, use_container_width=True)

st.divider()

# ── Detection Table ───────────────────────────────────────────────────────────
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray", "info": "gray"}

tab_inj, tab_pii, tab_all = st.tabs(["Injection Detections", "PII Detections", "All"])

def _render_detections(dets: list, limit: int = 50):
    if not dets:
        st.info("No detections to display.")
        return
    for d in dets[:limit]:
        dtype = d.get("detector_type", "?")
        sev   = d.get("severity", "info")
        conf  = d.get("confidence", 0)
        ts    = (d.get("timestamp") or "")[:19]
        agent = d.get("agent_id", "unknown")
        direction = d.get("direction", "?")
        icon  = "💉" if dtype == "injection" else "🔒"
        color = SEV_COLOR.get(sev, "gray")

        with st.expander(
            f"{icon} `{ts}` &nbsp; **{agent}** &nbsp; `{direction}` &nbsp; "
            f":{color}[**{sev.upper()}**] &nbsp; conf: {conf:.0%}"
        ):
            sig = d.get("signal") or {}
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Agent ID:**", d.get("agent_id", "-"))
                st.write("**Trace ID:**", d.get("trace_id") or "-")
                st.write("**Direction:**", direction)
                st.write("**Severity:**", sev)
                st.write("**Confidence:**", f"{conf:.1%}")
            with col2:
                if dtype == "injection":
                    cats = sig.get("categories_matched", [])
                    st.write("**Categories matched:**")
                    for c in cats:
                        st.markdown(f"- `{c}`")
                    matches = sig.get("matches", [])
                    if matches:
                        st.write("**Matched patterns:**")
                        for m in matches[:3]:
                            # matches are dicts: {category, pattern, severity, confidence, location}
                            if isinstance(m, dict):
                                st.code(f"[{m.get('category')}] {m.get('pattern')} @ {m.get('location')}", language=None)
                            else:
                                st.code(str(m)[:120], language=None)
                elif dtype == "pii":
                    types_found = sig.get("types_found", {})
                    if types_found:
                        st.write("**PII types found:**")
                        for pii_type, count in types_found.items():
                            st.markdown(f"- `{pii_type}` × {count}")
                    # stored field is "masked_snippet" (truncated at 500 chars)
                    masked = sig.get("masked_snippet") or sig.get("masked_content", "")
                    if masked:
                        st.write("**Masked content preview:**")
                        st.code(masked[:400], language=None)


with tab_inj:
    st.caption(f"{len(inj_24h)} injection detections in last 24h, {len([d for d in all_detections if d.get('detector_type')=='injection'])} total")

    # Category breakdown
    if inj_24h:
        cat_counts: dict[str, int] = defaultdict(int)
        for d in inj_24h:
            for cat in (d.get("signal") or {}).get("categories_matched", []):
                cat_counts[cat] += 1
        if cat_counts:
            st.write("**Top injection categories (24h):**")
            for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1])[:7]:
                st.markdown(f"- `{cat}` - {cnt} detection(s)")
            st.divider()

    _render_detections(inj_24h)


with tab_pii:
    st.caption(f"{len(pii_24h)} PII detections in last 24h, {len([d for d in all_detections if d.get('detector_type')=='pii'])} total")

    # PII type breakdown
    if pii_24h:
        pii_type_counts: dict[str, int] = defaultdict(int)
        for d in pii_24h:
            for pii_type in (d.get("signal") or {}).get("types_found", {}):
                pii_type_counts[pii_type] += 1
        if pii_type_counts:
            st.write("**PII types detected (24h):**")
            for pii_t, cnt in sorted(pii_type_counts.items(), key=lambda x: -x[1])[:12]:
                st.markdown(f"- `{pii_t}` - {cnt} detection(s)")
            st.divider()

    _render_detections(pii_24h)


with tab_all:
    _render_detections(all_detections, limit=100)

st.divider()

# ── Correlated Findings ───────────────────────────────────────────────────────
if inj_findings or pii_findings:
    st.subheader("Correlated Security Findings")
    st.caption("Findings auto-promoted from RuntimeDetections by the correlation engine.")
    for f in (inj_findings + pii_findings)[:20]:
        sev    = f.get("severity", "info")
        status = f.get("status", "detected")
        ts     = (f.get("created_at") or "")[:19]
        icon   = "🟢" if status == "prevented" else ("🟡" if status == "detected" else "🔴")
        color  = SEV_COLOR.get(sev, "gray")
        sid    = f.get("scenario_id", "")
        st.markdown(
            f"{icon} `{ts}` :{color}[**{sev.upper()}**] {f.get('title', '')} "
            f"`{status}` `{sid}`"
        )
    st.divider()

# ── Manual Analysis Form ──────────────────────────────────────────────────────
st.subheader("Analyze Content Manually")
st.caption("Submit agent prompt or tool response content for real-time injection and PII analysis.")

with st.form("analyze_form"):
    direction = st.radio("Direction", ["request", "response"], horizontal=True)
    content   = st.text_area("Content", height=120,
                             placeholder="Paste agent prompt, user message, or tool response here…")
    col_a, col_b = st.columns(2)
    with col_a:
        agent_id  = st.text_input("Agent ID", "manual-test")
    with col_b:
        trace_id  = st.text_input("Trace ID (optional)", "")
    submitted = st.form_submit_button("Analyze", type="primary")

if submitted and content:
    payload = {
        "tenant_id": "default",
        "agent_id":  agent_id,
        "direction": direction,
        "content":   content,
    }
    if trace_id:
        payload["trace_id"] = trace_id

    try:
        r = httpx.post(
            f"{RUNTIME_URL}/api/runtime/analyze",
            json=payload,
            timeout=10.0,
        )
        res = r.json()

        has_inj = res.get("has_injection", False)
        has_pii = res.get("has_pii", False)
        max_sev = res.get("max_severity", "none")

        # Extract detector-specific signals from the detections list
        detections_list = res.get("detections", [])
        inj_det = next((d for d in detections_list if d.get("detector_type") == "injection"), {})
        pii_det = next((d for d in detections_list if d.get("detector_type") == "pii"), {})

        if has_inj:
            st.error(f"💉 **Prompt injection detected** - severity: `{inj_det.get('severity', max_sev)}`  confidence: {inj_det.get('confidence', 0):.0%}")
            inj_sig = inj_det.get("signal", {})
            st.write("**Categories:**", inj_sig.get("categories_matched", []))
            matches = inj_sig.get("matches", [])
            if matches:
                st.write("**Matched patterns:**")
                for m in matches[:3]:
                    if isinstance(m, dict):
                        st.code(f"[{m.get('category')}] {m.get('pattern')} @ {m.get('location')}", language=None)
                    else:
                        st.code(str(m)[:200], language=None)

        if has_pii:
            pii_sig = pii_det.get("signal", {})
            types_found = pii_sig.get("types_found", {})
            st.warning(f"🔒 **PII detected** - severity: `{pii_det.get('severity', max_sev)}`  types: {list(types_found.keys())}")
            masked = pii_sig.get("masked_snippet") or pii_sig.get("masked_content", "")
            if masked:
                st.write("**Masked content:**")
                st.code(masked[:600], language=None)

        if not has_inj and not has_pii:
            st.success("✅ No injection or PII detected in submitted content.")

        with st.expander("Raw API response"):
            st.json(res)

    except Exception as e:
        st.error(f"Analysis request failed: {e}")

elif submitted and not content:
    st.warning("Please enter content to analyze.")

# ── Reference ─────────────────────────────────────────────────────────────────
st.divider()
with st.expander("Detection capabilities reference"):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
**Injection categories (7)**
- `instruction_override` - "ignore previous instructions"
- `prompt_extraction` - asking model to repeat its system prompt
- `role_manipulation` - "act as", "pretend you are"
- `jailbreak` - DAN, developer mode, etc.
- `delimiter_attack` - `</s>`, `[INST]` injection
- `hypothetical_scenario` - "in a story where you…"
- `obfuscation` - base64, unicode homoglyphs
        """)
    with col2:
        st.markdown("""
**PII types (12)**
- SSN, Credit card, Email, Phone number
- IP address, Date of birth, Passport number
- Driver's license, Medical record number
- API keys (`sk-…`, `pk-…`)
- AWS access keys (`AKIA…`)
- Generic secrets (high-entropy strings)

Raw content is **never stored** - only SHA-256 hash + detection signals.
        """)
