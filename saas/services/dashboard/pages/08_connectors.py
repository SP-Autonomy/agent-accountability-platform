"""
Dashboard Page 8: Connectors
Shows all registered telemetry connector instances, their health status,
and coverage gaps - answering "which signals is AIAAP actually receiving?"
"""

import os
from datetime import datetime, timezone, timedelta

import httpx
import streamlit as st

INGEST_URL = os.getenv("INGEST_URL", st.session_state.get("INGEST_URL", "http://localhost:8100"))

st.set_page_config(page_title="Connectors | AIAAP", layout="wide")
st.title("Connectors")
st.caption(
    "Which telemetry connectors are active and what signals are they delivering? "
    "Connectors auto-register when they send their first event - no manual registration needed."
)

# ── Data fetch ─────────────────────────────────────────────────────────────────

def safe_get(url, default=None, params=None):
    try:
        r = httpx.get(url, timeout=4.0, params=params or {})
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default


if st.button("Refresh"):
    st.rerun()

connectors = safe_get(f"{INGEST_URL}/api/connectors", [], {"tenant_id": "default"}) or []

# ── Status classification ──────────────────────────────────────────────────────

def _status(last_seen_iso: str) -> str:
    if not last_seen_iso:
        return "inactive"
    try:
        last = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - last
        if age <= timedelta(minutes=5):
            return "healthy"
        if age <= timedelta(minutes=30):
            return "stale"
        return "inactive"
    except Exception:
        return "inactive"


STATUS_COLOR = {
    "healthy":  "🟢",
    "stale":    "🟡",
    "inactive": "🔴",
}

PRIMARY_CONNECTOR_TYPES = {"k8s_otel", "k8s_audit", "ebpf", "cloudtrail"}

# ── KPI row ────────────────────────────────────────────────────────────────────

now = datetime.now(timezone.utc)

total = len(connectors)
active = sum(
    1 for c in connectors
    if _status(c.get("last_seen", "")) in ("healthy", "stale")
)
inactive = total - active

col1, col2, col3 = st.columns(3)
col1.metric("Total Connectors", total)
col2.metric("Active (healthy / stale)", active, delta=None)
col3.metric("Inactive (>30 min)", inactive, delta=None)

st.divider()

# ── Connector table ────────────────────────────────────────────────────────────

if not connectors:
    st.info(
        "No connectors registered yet. Send an event to `POST /api/events` with "
        "`connector_type` and `connector_instance_id` fields, or let the OTel "
        "Collector forward spans to `/otlp/v1/traces`."
    )
else:
    st.subheader("Registered Connectors")
    rows = []
    for c in connectors:
        s = _status(c.get("last_seen", ""))
        last_seen_raw = c.get("last_seen", "")
        try:
            last_dt = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            age_mins = int((now - last_dt).total_seconds() / 60)
            last_seen_str = f"{age_mins}m ago"
        except Exception:
            last_seen_str = last_seen_raw or "never"

        rows.append({
            "Status":         f"{STATUS_COLOR[s]} {s}",
            "Type":           c.get("connector_type", "unknown"),
            "Instance ID":    c.get("instance_id", ""),
            "Label":          c.get("label") or "",
            "Last Seen":      last_seen_str,
            "Events / 1h":    c.get("events_1h", 0),
            "Version":        c.get("version") or "",
        })

    import pandas as pd
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

st.divider()

# ── Coverage gap callout ───────────────────────────────────────────────────────

st.subheader("Coverage Gaps")
st.caption("Primary connector types: k8s_otel, k8s_audit, ebpf, cloudtrail")

active_types = {
    c.get("connector_type")
    for c in connectors
    if _status(c.get("last_seen", "")) in ("healthy", "stale")
}

gaps = PRIMARY_CONNECTOR_TYPES - active_types

if not gaps:
    st.success("Full telemetry coverage - all 4 primary connector types have an active instance.")
else:
    for gap in sorted(gaps):
        CONNECTOR_HINTS = {
            "k8s_otel":   "Deploy the `aiaap-otel-collector` Helm chart: `helm install aiaap-otel-collector connectors/k8s/helm/aiaap-otel-collector`",
            "k8s_audit":  "Deploy the `aiaap-k8s-audit` Helm chart: `helm install aiaap-k8s-audit connectors/k8s/helm/aiaap-k8s-audit`",
            "ebpf":       "Deploy the `aiaap-ebpf-sensor` Helm chart (requires Tetragon): `helm install aiaap-ebpf-sensor connectors/k8s/helm/aiaap-ebpf-sensor`",
            "cloudtrail": "Deploy the CloudTrail Lambda forwarder: see `connectors/aws/cloudtrail_forwarder/` and `examples/customer_env_cloud/`",
        }
        hint = CONNECTOR_HINTS.get(gap, "See docs/connectors/README.md for setup instructions.")
        st.warning(f"**{gap}** - no active instance\n\n{hint}")

st.divider()

# ── Quick-start curl ───────────────────────────────────────────────────────────

with st.expander("Quick-start: register a CLI connector"):
    st.caption("Verify the ingest API can receive events and auto-register a connector:")
    st.code(
        f"""curl -sf -X POST {INGEST_URL}/api/events \\
  -H "Content-Type: application/json" \\
  -d '{{
    "source": "otel",
    "tenant_id": "default",
    "payload": {{"event_type": "tool_call_executed", "agent_id": "my-agent"}},
    "connector_type": "cli",
    "connector_instance_id": "my-cli-instance"
  }}'

# Then verify it appeared:
curl -sf "{INGEST_URL}/api/connectors?tenant_id=default" | python3 -m json.tool""",
        language="bash",
    )

with st.expander("Deployment guides"):
    st.markdown(
        """
| Connector | Guide |
|-----------|-------|
| **Python SDK** | `pip install -r connectors/code/otel_sdk_python/requirements.txt` - add `init_tracer(service_name=..., otlp_endpoint=...)` to your agent |
| **K8s OTel** | `helm install aiaap-otel-collector connectors/k8s/helm/aiaap-otel-collector` |
| **K8s Audit** | `helm install aiaap-k8s-audit connectors/k8s/helm/aiaap-k8s-audit` |
| **eBPF Sensor** | `helm install aiaap-ebpf-sensor connectors/k8s/helm/aiaap-ebpf-sensor` |
| **AWS CloudTrail** | `cd connectors/aws/cloudtrail_forwarder && sam build && sam deploy` |
| **CLI / Test** | `examples/customer_env_cli/send_events.sh` - zero infrastructure required |

See `docs/connectors/README.md` for full install and verify guides.
"""
    )
