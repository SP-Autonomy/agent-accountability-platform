"""
Dashboard Page 2: Agents & Access
Tabbed view: Agent Principals | JIT Grants | Compliance Posture
Tells the story of who your AI agents are, what access they have, and
whether that access is aligned with security frameworks.
"""

import os
from datetime import datetime, timezone, timedelta

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from utils.dashboard_utils import render_mode_selector, filter_principals
from utils.ui_narrative import render_narrative_header, render_filter_summary
from utils.data_snapshot import DARK_LAYOUT


@st.cache_data(ttl=60)
def load_risk_breakdown(identity_url: str, principal_id: int) -> dict | None:
    """Fetch the per-factor risk breakdown for a single principal (cached 60s)."""
    try:
        r = httpx.get(f"{identity_url}/api/principals/{principal_id}/risk-breakdown", timeout=5.0)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

IDENTITY_URL   = os.getenv("IDENTITY_URL",   st.session_state.get("IDENTITY_URL",   "http://localhost:8300"))
DETECTIONS_URL = os.getenv("DETECTIONS_URL", st.session_state.get("DETECTIONS_URL", "http://localhost:8200"))

st.set_page_config(page_title="Agents & Access | AIAAP", layout="wide")
st.title("Agents & Access")
render_narrative_header(
    outcome="Who are your AI agents, what access do they hold, and are grants properly scoped?",
    what=["Agent principal inventory with risk gauges", "JIT grants with time-until-expiry progress bars", "Compliance coverage mapping (EU AI Act, NIST, MITRE, OWASP)"],
    why=["Understand the full access surface of your agent fleet", "Ensure time-bound grants aren't silently expiring", "Demonstrate audit-readiness with framework mapping"],
    next_steps=["High-risk agents → Investigate drift in Behavioral Intelligence", "Missing JIT grants → Create them in the JIT Grants tab", "Critical findings → Review in Detections"],
    primary_cta={"label": "Behavioral Intelligence", "page": "pages/04_behavioral.py"},
    secondary_cta={"label": "Detections", "page": "pages/05_detections.py"},
)


def safe_get(url, default=None, params=None):
    try:
        r = httpx.get(url, timeout=5.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


if st.button("Refresh"):
    st.rerun()

with st.sidebar:
    mode, include_labs = render_mode_selector()

tab_agents, tab_jit, tab_approvals, tab_compliance = st.tabs(["Agent Principals", "JIT Grants", "Approvals", "Compliance Coverage"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: AGENT PRINCIPALS
# ══════════════════════════════════════════════════════════════════════════════
with tab_agents:
    with st.sidebar:
        st.subheader("Filters")
        ns_filter   = st.text_input("Namespace", "")
        sa_filter   = st.text_input("Service Account", "")
        tier_filter = st.multiselect("Risk Tier", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=[])

    all_principals_raw = safe_get(
        f"{IDENTITY_URL}/api/principals",
        [],
        {k: v for k, v in {"namespace": ns_filter, "service_account": sa_filter}.items() if v},
    ) or []
    principals = filter_principals(all_principals_raw, include_labs)
    render_filter_summary(all_principals_raw, principals, include_labs)

    intent_summary = safe_get(
        f"{DETECTIONS_URL}/api/intent/summary", [],
        {"tenant_id": "default", "hours": 24}
    ) or []
    intent_map = {row["principal_id"]: row for row in intent_summary}

    all_grants = safe_get(f"{IDENTITY_URL}/api/jit/grants", [], {"active_only": "true"}) or []
    jit_count_map: dict[int, int] = {}
    for g in all_grants:
        pid = g.get("principal_id")
        if pid is not None:
            jit_count_map[pid] = jit_count_map.get(pid, 0) + 1

    def risk_tier(score: float) -> tuple[str, str]:
        if score >= 75: return "CRITICAL RISK", "#6f42c1"
        elif score >= 50: return "HIGH RISK", "#dc3545"
        elif score >= 25: return "MEDIUM RISK", "#ffc107"
        return "LOW RISK", "#28a745"

    if tier_filter:
        principals = [p for p in principals if any(t in risk_tier(p.get("risk_score", 0) or 0)[0] for t in tier_filter)]

    if not principals:
        st.info("No agent principals observed. Ingest OTel spans to populate the registry.")
        st.stop()

    # Summary table
    st.subheader(f"All Agents ({len(principals)})")
    rows = []
    for p in principals:
        im = intent_map.get(p["id"], {})
        rows.append({
            "id":              p["id"],
            "name":            p.get("name"),
            "namespace":       p.get("namespace"),
            "risk_score":      round(p.get("risk_score", 0) or 0, 1),
            "risk_updated":    (p.get("risk_score_updated_at") or "-")[:19],
            "drift_score":     round(im.get("drift_score") or 0, 1) if im.get("drift_score") else "-",
            "blast_score":     round(im.get("blast_radius_score") or 0, 1) if im.get("blast_radius_score") else "-",
            "active_intent":   im.get("active_envelope") or "-",
            "jit_grants":      jit_count_map.get(p["id"], 0),
            "last_seen":       (p.get("last_seen") or "")[:19],
        })
    df = pd.DataFrame(rows)

    def _bg(val):
        if not isinstance(val, (int, float)): return ""
        if val >= 75: return "background-color: #f5e6ff"
        elif val >= 50: return "background-color: #ffcccc"
        elif val >= 25: return "background-color: #fff3cd"
        return "background-color: #d4edda"

    score_cols = ["risk_score", "drift_score", "blast_score"]
    styled_cols = [c for c in score_cols if c in df.columns]
    st.dataframe(
        df.style.map(_bg, subset=styled_cols),
        use_container_width=True, hide_index=True,
    )

    st.divider()
    st.subheader("Agent Risk Gauge Cards")
    col_iter = iter(principals)
    for p in col_iter:
        p2 = next(col_iter, None)
        for card_col, principal in zip(st.columns(2), [p, p2]):
            if principal is None: continue
            with card_col:
                score = float(principal.get("risk_score", 0) or 0)
                tier, color = risk_tier(score)
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={"suffix": " / 100", "font": {"size": 18}},
                    title={"text": principal.get("name", "unknown"), "font": {"size": 13}},
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": color},
                        "steps": [
                            {"range": [0, 25],   "color": "#d4edda"},
                            {"range": [25, 50],  "color": "#fff3cd"},
                            {"range": [50, 75],  "color": "#ffcccc"},
                            {"range": [75, 100], "color": "#f5e6ff"},
                        ],
                    },
                ))
                fig.update_layout(
                    margin=dict(t=40, b=10, l=20, r=20),
                    height=200,
                    paper_bgcolor="#1e293b",
                    plot_bgcolor="#1e293b",
                    font=dict(color="#e2e8f0"),
                )
                st.plotly_chart(fig, use_container_width=True, key=f"gauge_{principal['id']}")

                badge_col, jit_col = st.columns(2)
                with badge_col:
                    if "CRITICAL" in tier or "HIGH" in tier:
                        st.error(f"**{tier}**")
                    elif "MEDIUM" in tier:
                        st.warning(f"**{tier}**")
                    else:
                        st.success(f"**{tier}**")
                with jit_col:
                    cnt = jit_count_map.get(principal.get("id"), 0)
                    if cnt > 0:
                        st.info(f"**JIT:** {cnt} active")
                    else:
                        st.caption("No active JIT")

                # ── Inline top-3 risk drivers ──────────────────────────────
                bd = load_risk_breakdown(IDENTITY_URL, principal["id"])
                if bd and bd.get("factors"):
                    top3_active = [
                        f for f in sorted(bd["factors"], key=lambda x: -x.get("points", 0))[:3]
                        if f.get("points", 0) > 0
                    ]
                    if top3_active:
                        st.caption("**Top risk drivers:**")
                        for factor in top3_active:
                            pts     = factor.get("points", 0)
                            max_pts = max(factor.get("max_points", 1), 1)
                            filled  = int(pts / max_pts * 8)
                            bar     = "█" * filled + "░" * (8 - filled)
                            st.caption(f"\u00a0\u00a0`{factor['name']}`: {bar} {pts:.0f}/{max_pts}pt")

                with st.expander("Details & Actions"):
                    im = intent_map.get(principal["id"], {})
                    st.write(f"**Namespace:** `{principal.get('namespace')}`  |  **SA:** `{principal.get('service_account')}`")
                    risk_ts = (principal.get("risk_score_updated_at") or "never")[:19]
                    st.caption(f"Risk score computed from **operational signals only** · last updated: `{risk_ts} UTC`")
                    st.write(f"**Drift Score:** `{im.get('drift_score', '-')}`  |  **Blast Radius:** `{im.get('blast_radius_score', '-')}`")
                    st.write(f"**Active Envelope:** `{im.get('active_envelope', 'none')}`")

                    btn_col1, btn_col2 = st.columns(2)
                    with btn_col1:
                        if st.button("Refresh Risk Score", key=f"risk_{principal['id']}"):
                            try:
                                r = httpx.post(f"{IDENTITY_URL}/api/principals/{principal['id']}/refresh-risk", timeout=5.0)
                                if r.status_code == 200:
                                    data = r.json()
                                    st.success(f"Updated: {data.get('risk_score', 0):.1f}  (at {data.get('risk_score_updated_at','?')[:19]} UTC)")
                            except Exception as e:
                                st.error(str(e))
                    with btn_col2:
                        if st.button("Explain Score", key=f"explain_{principal['id']}"):
                            try:
                                r = httpx.get(f"{IDENTITY_URL}/api/principals/{principal['id']}/risk-breakdown", timeout=5.0)
                                if r.status_code == 200:
                                    bd = r.json()
                                    st.markdown(f"**Risk breakdown - {bd.get('total_score', 0):.1f} / 100** (operational signals only)")
                                    for factor in bd.get("factors", []):
                                        pts = factor.get("points", 0)
                                        max_pts = factor.get("max_points", 0)
                                        bar = "█" * int(pts / max(max_pts, 1) * 10) if pts > 0 else "░" * 10
                                        st.markdown(f"- **{factor['name']}**: `{pts:.0f}/{max_pts}` {bar} - {factor['description']}")
                                else:
                                    st.warning("Could not fetch breakdown.")
                            except Exception as e:
                                st.error(str(e))

                    with st.popover("Delete Agent"):
                        st.warning(f"Delete **{principal.get('name')}**? Cannot be undone.")
                        if st.button("Yes, delete", key=f"del_{principal['id']}"):
                            try:
                                r = httpx.delete(f"{IDENTITY_URL}/api/principals/{principal['id']}", timeout=5.0)
                                if r.status_code in (200, 204):
                                    st.success("Deleted.")
                                    st.rerun()
                            except Exception as e:
                                st.error(str(e))


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: JIT GRANTS
# ══════════════════════════════════════════════════════════════════════════════
with tab_jit:
    st.subheader("Just-In-Time Access Grants")
    st.caption("Time-bound, scope-bound access grants for AI agent principals.")

    principals_list = filter_principals(safe_get(f"{IDENTITY_URL}/api/principals", []) or [], include_labs)
    active_grants   = safe_get(f"{IDENTITY_URL}/api/jit/grants", [], {"active_only": "true"}) or []
    all_grants_hist = safe_get(f"{IDENTITY_URL}/api/jit/grants", [], {"active_only": "false"}) or []
    audit_log       = safe_get(f"{IDENTITY_URL}/api/audit", [], {"limit": 50}) or []

    # KPIs
    k1, k2, k3 = st.columns(3)
    k1.metric("Active Grants", len(active_grants))
    k2.metric("Total Grants (all time)", len(all_grants_hist))
    k3.metric("Audit Events", len(audit_log))

    st.divider()

    # Active grants with expiry bars
    st.subheader("Active Grants")
    now = datetime.now(timezone.utc)
    if active_grants:
        for g in active_grants:
            with st.container():
                c1, c2, c3 = st.columns([3, 2, 1])
                expires_raw = g.get("expires_at") or ""
                try:
                    expires_dt = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
                    expires_dt = expires_dt.replace(tzinfo=timezone.utc) if not expires_dt.tzinfo else expires_dt
                    ttl_total = (expires_dt - datetime.fromisoformat((g.get("created_at") or now.isoformat()).replace("Z", "+00:00")).replace(tzinfo=timezone.utc)).total_seconds()
                    remaining = (expires_dt - now).total_seconds()
                    fraction = max(0.0, min(1.0, remaining / max(ttl_total, 1)))
                    color = "🟢" if fraction > 0.5 else "🟡" if fraction > 0.2 else "🔴"
                except Exception:
                    fraction, color = 1.0, "⚪"

                with c1:
                    st.write(f"**{g.get('scope', '-')}** - {g.get('reason', '')[:60]}")
                    st.caption(f"Principal ID: {g.get('principal_id')} | Expires: {expires_raw[:19]}")
                with c2:
                    st.progress(fraction, text=f"{color} {fraction*100:.0f}% remaining")
                with c3:
                    if st.button("Revoke", key=f"revoke_{g.get('id')}"):
                        try:
                            r = httpx.delete(f"{IDENTITY_URL}/api/jit/grants/{g.get('id')}", timeout=5.0)
                            if r.status_code in (200, 204):
                                st.success("Revoked.")
                                st.rerun()
                        except Exception as e:
                            st.error(str(e))
                st.divider()
    else:
        st.info("No active JIT grants.")

    # Create new grant
    st.subheader("Create JIT Grant")
    with st.expander("Request new JIT access"):
        if not principals_list:
            st.warning("No agents registered yet.")
        else:
            p_options = {p["name"]: p["id"] for p in principals_list}
            sel_name = st.selectbox("Agent", list(p_options.keys()))
            scope    = st.text_input("Scope", "secrets:read", help="e.g. secrets:read, admin, k8s:exec")
            reason   = st.text_input("Reason", "manual grant for investigation")
            ttl      = st.slider("TTL (minutes)", 5, 1440, 60)
            if st.button("Create Grant"):
                try:
                    r = httpx.post(
                        f"{IDENTITY_URL}/api/jit/grants",
                        json={"principal_id": p_options[sel_name], "scope": scope,
                              "reason": reason, "ttl_minutes": ttl, "tenant_id": "default"},
                        timeout=5.0,
                    )
                    if r.status_code in (200, 201):
                        st.success(f"Grant created: id={r.json().get('id')}")
                        st.rerun()
                    else:
                        st.error(f"Error: {r.text}")
                except Exception as e:
                    st.error(str(e))

    # Grant history
    with st.expander("Grant History (all grants)"):
        if all_grants_hist:
            hist_df = pd.DataFrame([{
                "id": g.get("id"), "principal_id": g.get("principal_id"),
                "scope": g.get("scope"), "reason": (g.get("reason") or "")[:50],
                "created_at": (g.get("created_at") or "")[:19],
                "expires_at": (g.get("expires_at") or "")[:19],
            } for g in all_grants_hist])
            st.dataframe(hist_df, use_container_width=True, hide_index=True)
        else:
            st.info("No grant history.")

    # Audit log
    if audit_log:
        with st.expander("JIT Audit Log"):
            audit_df = pd.DataFrame([{
                "timestamp": (e.get("timestamp") or "")[:19],
                "action": e.get("action"), "actor": e.get("actor"),
                "resource": e.get("resource"),
            } for e in audit_log])
            st.dataframe(audit_df, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: APPROVALS
# ══════════════════════════════════════════════════════════════════════════════
with tab_approvals:
    st.subheader("JIT Approval Requests")
    st.caption("Review and act on pending JIT access requests. Approved requests auto-create time-bound JIT grants.")

    approvals_raw: list = safe_get(f"{IDENTITY_URL}/api/approvals", [], {"tenant_id": "default"}) or []

    pending_ap  = [a for a in approvals_raw if a.get("status") == "pending"]
    approved_ap = [a for a in approvals_raw if a.get("status") == "approved"]
    denied_ap   = [a for a in approvals_raw if a.get("status") == "denied"]
    expired_ap  = [a for a in approvals_raw if a.get("status") == "expired"]

    ac1, ac2, ac3, ac4 = st.columns(4)
    ac1.metric("Pending",  len(pending_ap))
    ac2.metric("Approved", len(approved_ap))
    ac3.metric("Denied",   len(denied_ap))
    ac4.metric("Expired",  len(expired_ap))

    st.divider()

    # Pending approvals - action buttons
    if pending_ap:
        st.markdown("#### Pending Requests")
        reviewer = st.text_input("Reviewer name (required for approve/deny)", value="admin",
                                 key="ap_reviewer", placeholder="@analyst")

        for ap in pending_ap:
            ap_id = ap["id"]
            col_info, col_approve, col_deny = st.columns([5, 1, 1])
            with col_info:
                exp_at = (ap.get("expires_at") or "")[:19].replace("T", " ")
                st.markdown(
                    f"**#{ap_id}** · Principal `{ap['principal_id']}` · "
                    f"Scope `{ap['scope']}` · TTL {ap['ttl_minutes']}m · "
                    f"by *{ap.get('requested_by', '?')}*"
                )
                if ap.get("reason"):
                    st.caption(f"Reason: {ap['reason']}")
                st.caption(f"Expires: {exp_at} UTC")
            with col_approve:
                if st.button("Approve", key=f"ap_approve_{ap_id}", type="primary"):
                    try:
                        r = httpx.post(
                            f"{IDENTITY_URL}/api/approvals/{ap_id}/approve",
                            json={"reviewed_by": reviewer or "admin"},
                            timeout=5.0,
                        )
                        if r.status_code == 200:
                            st.success(f"Approved #{ap_id} - JIT grant created.")
                            st.rerun()
                        else:
                            st.error(f"Error {r.status_code}: {r.text[:120]}")
                    except Exception as e:
                        st.error(str(e))
            with col_deny:
                if st.button("Deny", key=f"ap_deny_{ap_id}"):
                    try:
                        r = httpx.post(
                            f"{IDENTITY_URL}/api/approvals/{ap_id}/deny",
                            json={"reviewed_by": reviewer or "admin"},
                            timeout=5.0,
                        )
                        if r.status_code == 200:
                            st.info(f"Denied #{ap_id}.")
                            st.rerun()
                        else:
                            st.error(f"Error {r.status_code}: {r.text[:120]}")
                    except Exception as e:
                        st.error(str(e))
            st.divider()
    else:
        st.info("No pending approval requests.")

    # Manual request form
    with st.expander("Submit a new JIT approval request"):
        with st.form("new_ap_request"):
            ap_principal = st.number_input("Principal ID", min_value=1, step=1, key="ap_pid")
            ap_scope = st.text_input("Scope (e.g. secrets:read:production)", key="ap_scope")
            ap_reason = st.text_input("Reason (min 5 chars)", key="ap_reason")
            ap_ttl = st.slider("Grant TTL (minutes)", 5, 480, 60, key="ap_ttl")
            ap_requester = st.text_input("Requested by", value="dashboard-user", key="ap_requester")
            submitted = st.form_submit_button("Submit Request")
            if submitted:
                if len(ap_reason) < 5:
                    st.error("Reason must be at least 5 characters.")
                else:
                    try:
                        r = httpx.post(
                            f"{IDENTITY_URL}/api/approvals/request",
                            json={
                                "tenant_id": "default",
                                "principal_id": int(ap_principal),
                                "scope": ap_scope,
                                "reason": ap_reason,
                                "ttl_minutes": int(ap_ttl),
                                "requested_by": ap_requester,
                            },
                            timeout=5.0,
                        )
                        if r.status_code == 201:
                            st.success(f"Approval request created (id={r.json()['id']}).")
                            st.rerun()
                        else:
                            st.error(f"Error {r.status_code}: {r.text[:120]}")
                    except Exception as e:
                        st.error(str(e))

    # History table
    if approved_ap or denied_ap or expired_ap:
        st.markdown("#### History (reviewed + expired)")
        history_rows = []
        for a in approved_ap + denied_ap + expired_ap:
            history_rows.append({
                "ID":            a["id"],
                "Status":        a["status"].upper(),
                "Principal":     a["principal_id"],
                "Scope":         a["scope"],
                "TTL (m)":       a["ttl_minutes"],
                "Requested by":  a.get("requested_by", "-"),
                "Reviewed by":   a.get("reviewed_by") or "-",
                "JIT Grant":     a.get("jit_grant_id") or "-",
            })
        st.dataframe(pd.DataFrame(history_rows), use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4: COMPLIANCE COVERAGE
# ══════════════════════════════════════════════════════════════════════════════
with tab_compliance:
    st.subheader("Compliance Coverage")
    st.caption("How AIAAP detection controls map to EU AI Act, NIST AI RMF, MITRE ATLAS, and OWASP LLM Top 10.")

    try:
        from compliance import compliance_summary, controls_by_framework, controls_by_owasp

        summary = compliance_summary()
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total Controls", summary["total_controls"])
        k2.metric("EU AI Act Articles", len(summary["eu_articles_covered"]))
        k3.metric("NIST AI RMF Functions", len(summary["nist_functions"]))
        k4.metric("MITRE ATLAS Techniques", len(summary["atlas_techniques"]))
        k5.metric("OWASP LLM Items", len(summary["owasp_llm_items"]))

        st.divider()

        with st.expander("EU AI Act - Articles Covered", expanded=True):
            cols = st.columns(min(len(summary["eu_articles_covered"]), 6) or 1)
            for i, art in enumerate(sorted(summary["eu_articles_covered"])):
                cols[i % 6].success(art)

        with st.expander("NIST AI RMF - Functions Covered", expanded=True):
            funcs = sorted(summary["nist_functions"])
            if funcs:
                cols = st.columns(len(funcs))
                for i, fn in enumerate(funcs):
                    cols[i].info(fn)

        with st.expander("OWASP LLM Top 10 - Items Covered", expanded=True):
            items = sorted(summary["owasp_llm_items"])
            if items:
                cols = st.columns(min(len(items), 5))
                for i, item in enumerate(items):
                    cols[i % 5].warning(item)

        with st.expander("MITRE ATLAS - Techniques Mitigated"):
            techs = sorted(summary["atlas_techniques"])
            st.write(", ".join(techs) if techs else "None mapped")

    except ImportError:
        st.info("Compliance module not available in this environment.")
        st.caption("The compliance.py module is included in the dashboard Docker image.")
