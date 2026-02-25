"""
AIAAP Dashboard - Main Entry Point
Streamlit multi-page app with sidebar navigation.
"""

import os
import httpx
import streamlit as st

st.set_page_config(
    page_title="AIAAP - Agent Identity & Access Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Service URLs (from environment) ──────────────────────────────────────────
INGEST_URL     = os.getenv("INGEST_URL",     "http://localhost:8100")
DETECTIONS_URL = os.getenv("DETECTIONS_URL", "http://localhost:8200")
IDENTITY_URL   = os.getenv("IDENTITY_URL",   "http://localhost:8300")
RUNTIME_URL    = os.getenv("RUNTIME_URL",    "http://localhost:8400")

# Store URLs in session state so pages can access them
st.session_state["INGEST_URL"]     = INGEST_URL
st.session_state["DETECTIONS_URL"] = DETECTIONS_URL
st.session_state["IDENTITY_URL"]   = IDENTITY_URL
st.session_state["RUNTIME_URL"]    = RUNTIME_URL


# ── Health check helper ───────────────────────────────────────────────────────
def _health(url: str) -> dict | None:
    try:
        r = httpx.get(f"{url}/health", timeout=2.0)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🔐 AIAAP")
    st.caption("Agent Identity & Access Adversarial Playground")
    st.divider()

    st.subheader("Service Status")

    services = [
        ("Ingest",     INGEST_URL,     "8100"),
        ("Detections", DETECTIONS_URL, "8200"),
        ("Identity",   IDENTITY_URL,   "8300"),
        ("Runtime",    RUNTIME_URL,    "8400"),
    ]

    runtime_ok = False
    for name, url, port in services:
        h = _health(url)
        if h:
            version = h.get("version", "")
            label = f"✅ {name}"
            if version:
                label += f" v{version}"
            st.success(label)
            if name == "Runtime":
                runtime_ok = True
        else:
            st.error(f"❌ {name} (:{port})")

    st.divider()

    st.subheader("Capability Packs")
    identity_status = "✅ Active"
    runtime_status  = "✅ Active" if runtime_ok else "❌ Not deployed"

    st.markdown(f"**Identity Pack**  \n{identity_status}")
    st.markdown(f"**Runtime Pack**  \n{runtime_status}")

    st.divider()
    st.caption(f"`{INGEST_URL}`  \n`{DETECTIONS_URL}`  \n`{IDENTITY_URL}`  \n`{RUNTIME_URL}`")


# ── Main landing page ─────────────────────────────────────────────────────────
st.title("AIAAP Control Plane")
st.markdown(
    "**Telemetry-first agent identity and access security platform.** "
    "Multi-signal correlation across OTel spans, eBPF events, and audit logs."
)

st.divider()

# 4-service health grid
st.subheader("Service Health")
cols = st.columns(4)
for col, (name, url, port) in zip(cols, services):
    with col:
        h = _health(url)
        if h:
            st.success(f"**{name}**")
            st.caption(f"v{h.get('version', '?')} · :{port}")
        else:
            st.error(f"**{name}**")
            st.caption(f"Unreachable · :{port}")

st.divider()

# Pack overview cards
st.subheader("Capability Packs")
pack_l, pack_r = st.columns(2)

with pack_l:
    st.info(
        "**Identity Pack (AIAAP)** ✅\n\n"
        "- Agent principal inventory & posture scoring\n"
        "- Just-in-time access grants with audit trail\n"
        "- Behavioral baseline & anomaly detection\n"
        "- Adversarial scenarios: SSRF, confused deputy, privilege escalation"
    )

with pack_r:
    if runtime_ok:
        st.success(
            "**Runtime Pack (AIRS)** ✅\n\n"
            "- Server-side prompt injection detection (7 categories)\n"
            "- PII leakage detection & masking (12 types)\n"
            "- Content analyzed without storing raw data\n"
            "- Findings auto-promoted via correlation engine"
        )
    else:
        st.warning(
            "**Runtime Pack (AIRS)** ❌  Not deployed\n\n"
            "- Start the `runtime` service on port 8400\n"
            "- Enables injection + PII content inspection\n"
            "- `make up` includes the runtime service"
        )

st.info("Navigate using the **Pages** menu in the left sidebar.")

# Redirect to Control Room as the default landing page
try:
    st.switch_page("pages/00_control_room.py")
except Exception:
    pass  # Fallback: user navigates manually via sidebar
