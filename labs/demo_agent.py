"""
AIAAP Standalone Demo Agent
============================
A self-contained script that simulates a real AI coding assistant making
tool calls - and shows how AIAAP detects suspicious behaviour.

No Kubernetes or AWS needed. Just:
  make up          # start the control plane
  python labs/demo_agent.py

What it simulates
-----------------
  Step 1  Normal ops     - agent fetches docs, reads files, calls APIs
  Step 2  SSRF attempt   - agent tries to reach cloud metadata IP 169.254.169.254
                           → AIAAP creates a HIGH finding: "SSRF: Metadata IP Access"
  Step 3  Privileged tool - agent calls a secrets reader without a JIT grant
                           → AIAAP creates finding: "Privileged tool call without active JIT grant"
  Step 4  Confused deputy - two spans in one trace claim different agent IDs
                           → AIAAP creates finding: "Confused Deputy: agent identity mismatch"

This mirrors what would happen if you added the AIAAP SDK to Claude Code,
a LangChain agent, an AutoGen setup, or any other AI agent framework.

The spans are sent directly to the ingest service over OTLP/HTTP (JSON).
No OTel Collector required in this mode.
"""

import json
import time
import struct
import os
import sys
import random
import urllib.request
import urllib.error

# ── Config ────────────────────────────────────────────────────────────────────
INGEST_URL     = os.getenv("AIAAP_INGEST_URL",  "http://localhost:8100")
DETECTIONS_URL = os.getenv("AIAAP_DETECTIONS_URL", "http://localhost:8200")
TENANT_ID      = os.getenv("AIAAP_TENANT_ID",   "default")

OTLP_ENDPOINT  = f"{INGEST_URL}/otlp/v1/traces"
EVENTS_ENDPOINT = f"{INGEST_URL}/api/events"

AGENT_ID       = "demo-coding-agent"
NAMESPACE      = "demo"
SERVICE_ACCOUNT = "demo-agent-sa"


# ── Minimal OTLP JSON helpers (no opentelemetry package required) ─────────────

def _rand_hex(n: int) -> str:
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(n))


def _make_span(
    trace_id: str,
    span_id: str,
    name: str,
    attributes: dict,
    parent_span_id: str | None = None,
    start_offset_ms: int = 0,
) -> dict:
    now_ns = int(time.time() * 1e9)
    start  = now_ns + start_offset_ms * 1_000_000
    return {
        "traceId":           trace_id,
        "spanId":            span_id,
        "parentSpanId":      parent_span_id or "",
        "name":              name,
        "kind":              2,   # SPAN_KIND_CLIENT
        "startTimeUnixNano": str(start),
        "endTimeUnixNano":   str(start + 200_000_000),  # 200 ms duration
        "attributes": [
            {"key": k, "value": {"stringValue": str(v)}}
            for k, v in attributes.items()
        ],
        "status": {"code": 1},  # STATUS_CODE_OK
    }


def _otlp_payload(spans: list[dict], service_name: str = "demo-agent") -> dict:
    return {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name",                 "value": {"stringValue": service_name}},
                    {"key": "aiaap.agent.id",               "value": {"stringValue": AGENT_ID}},
                    {"key": "aiaap.k8s.namespace",          "value": {"stringValue": NAMESPACE}},
                    {"key": "aiaap.k8s.service_account",    "value": {"stringValue": SERVICE_ACCOUNT}},
                    {"key": "aiaap.tenant.id",              "value": {"stringValue": TENANT_ID}},
                ]
            },
            "scopeSpans": [{"spans": spans}],
        }]
    }


def _post_json(url: str, payload: dict) -> int:
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        print(f"  ⚠ POST failed: {e}")
        return 0


def _send_trace(spans: list[dict], label: str) -> None:
    payload = _otlp_payload(spans)
    status  = _post_json(OTLP_ENDPOINT, payload)
    mark    = "✅" if status in (200, 201) else f"⚠ HTTP {status}"
    print(f"  {mark}  {label}")


def _poll_findings(scenario_id: str, wait: int = 20) -> list[dict]:
    """Poll the detections API until a finding appears (correlation runs every 10 s)."""
    url = f"{DETECTIONS_URL}/api/findings?scenario_id={scenario_id}&tenant_id={TENANT_ID}"
    for _ in range(wait // 2):
        time.sleep(2)
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
                if data:
                    return data
        except Exception:
            pass
    return []


# ── Demo steps ────────────────────────────────────────────────────────────────

def step1_normal_ops():
    """Normal agent behaviour: reads code, searches docs, calls an API."""
    print("\n▶ Step 1: Normal agent operations (code search, doc lookup, API call)")

    trace_id = _rand_hex(16)
    root_id  = _rand_hex(8)

    spans = [
        _make_span(trace_id, root_id, "prompt_received", {
            "aiaap.agent.id":   AGENT_ID,
            "aiaap.agent.role": "coding-assistant",
            "aiaap.request.user_id": "developer-1",
        }),
        _make_span(trace_id, _rand_hex(8), "tool_call_executed", {
            "aiaap.tool.name":             "read_file",
            "aiaap.tool.destination_host": "localhost",
            "aiaap.agent.id":              AGENT_ID,
        }, parent_span_id=root_id, start_offset_ms=10),
        _make_span(trace_id, _rand_hex(8), "tool_call_executed", {
            "aiaap.tool.name":             "search_codebase",
            "aiaap.tool.destination_host": "localhost",
            "aiaap.agent.id":              AGENT_ID,
        }, parent_span_id=root_id, start_offset_ms=30),
        _make_span(trace_id, _rand_hex(8), "tool_call_executed", {
            "aiaap.tool.name":             "call_api",
            "aiaap.tool.destination_host": "api.github.com",
            "aiaap.agent.id":              AGENT_ID,
        }, parent_span_id=root_id, start_offset_ms=60),
        _make_span(trace_id, _rand_hex(8), "response_generated", {
            "aiaap.agent.id": AGENT_ID,
        }, parent_span_id=root_id, start_offset_ms=100),
    ]
    _send_trace(spans, "4 spans: read_file, search_codebase, call_api → no finding expected")
    print("  → Tool usage registered in dashboard (page 3)")


def step2_ssrf():
    """Agent tries to fetch the cloud metadata IP - SSRF detection."""
    print("\n▶ Step 2: SSRF - agent tool calls cloud metadata endpoint 169.254.169.254")
    print("  (This simulates a prompt-injected instruction telling the agent to 'fetch http://169.254.169.254/latest/meta-data/')")

    trace_id = _rand_hex(16)
    root_id  = _rand_hex(8)

    spans = [
        _make_span(trace_id, root_id, "prompt_received", {
            "aiaap.agent.id":            AGENT_ID,
            "aiaap.risk.suspected_injection": "true",
        }),
        _make_span(trace_id, _rand_hex(8), "tool_call_executed", {
            "aiaap.tool.name":             "fetch_url",
            "aiaap.tool.destination_host": "169.254.169.254",
            "aiaap.agent.id":              AGENT_ID,
            "aiaap.risk.flags":            '["metadata_ip_access"]',
        }, parent_span_id=root_id, start_offset_ms=20),
    ]
    _send_trace(spans, "Spans sent - waiting for correlator (up to 20 s)...")

    findings = _poll_findings("ssrf_metadata")
    if findings:
        f = findings[0]
        print(f"  🔴 FINDING CREATED: {f['title']} [{f['severity'].upper()} / {f['status'].upper()}]")
        print(f"     → Dashboard page 6 (Findings) to see evidence")
    else:
        print("  ⏳ No finding yet - correlator runs every 10 s, try refreshing the dashboard")


def step3_privileged_no_jit():
    """Agent calls a privileged tool without a JIT grant - overbroad permissions detection."""
    print("\n▶ Step 3: Privileged tool call without JIT grant")
    print("  (Simulates an agent calling 'read_secrets' without prior authorization)")

    trace_id = _rand_hex(16)
    root_id  = _rand_hex(8)

    spans = [
        _make_span(trace_id, root_id, "prompt_received", {
            "aiaap.agent.id": AGENT_ID,
        }),
        _make_span(trace_id, _rand_hex(8), "tool_call_executed", {
            "aiaap.tool.name":             "read_secrets",
            "aiaap.tool.destination_host": "vault.internal",
            "aiaap.agent.id":              AGENT_ID,
            "aiaap.risk.flags":            '["privileged_action"]',
            # Intentionally omitting aiaap.jit.grant_id to trigger the rule
        }, parent_span_id=root_id, start_offset_ms=15),
    ]
    _send_trace(spans, "Spans sent - waiting for correlator (up to 20 s)...")

    findings = _poll_findings("overbroad_permissions")
    if findings:
        f = findings[0]
        print(f"  🟡 FINDING CREATED: {f['title']} [{f['severity'].upper()} / {f['status'].upper()}]")
        print(f"     → To fix: create a JIT grant in the dashboard (page 4), then re-run")
    else:
        print("  ⏳ No finding yet - correlator runs every 10 s, try refreshing the dashboard")


def step4_confused_deputy():
    """Two different agent IDs on spans within the same trace - confused deputy."""
    print("\n▶ Step 4: Confused deputy - two agent IDs in the same trace")
    print("  (A low-privilege orchestrator induces a high-privilege tool execution)")

    trace_id = _rand_hex(16)
    root_id  = _rand_hex(8)

    spans = [
        _make_span(trace_id, root_id, "prompt_received", {
            "aiaap.agent.id":   "low-privilege-agent",
            "aiaap.agent.role": "orchestrator",
        }),
        _make_span(trace_id, _rand_hex(8), "tool_call_executed", {
            # Different agent_id on tool span - the mismatch triggers the rule
            "aiaap.tool.name":  "deploy_infrastructure",
            "aiaap.agent.id":   "high-privilege-agent",  # mismatch!
            "aiaap.risk.flags": '["identity_mismatch"]',
        }, parent_span_id=root_id, start_offset_ms=25),
    ]
    _send_trace(spans, "Spans sent - waiting for correlator (up to 20 s)...")

    findings = _poll_findings("confused_deputy")
    if findings:
        f = findings[0]
        print(f"  🟡 FINDING CREATED: {f['title']} [{f['severity'].upper()} / {f['status'].upper()}]")
    else:
        print("  ⏳ No finding yet - correlator runs every 10 s, try refreshing the dashboard")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("AIAAP Demo Agent")
    print(f"Control plane: {INGEST_URL}")
    print("=" * 60)

    # Quick health check
    try:
        with urllib.request.urlopen(f"{INGEST_URL}/health", timeout=3) as r:
            print(f"✅ Ingest healthy ({r.status})")
    except Exception:
        print(f"❌ Cannot reach ingest at {INGEST_URL}")
        print("   Run:  make up   (then wait ~30 s for services to start)")
        sys.exit(1)

    step1_normal_ops()
    step2_ssrf()
    step3_privileged_no_jit()
    step4_confused_deputy()

    print("\n" + "=" * 60)
    print("Done! Open the dashboard: http://localhost:8501")
    print("  Page 3 - Tool Usage      (heatmap from step 1)")
    print("  Page 4 - JIT Grants      (create a grant, re-run step 3)")
    print("  Page 6 - Findings        (SSRF, overbroad, confused deputy)")
    print("=" * 60)


if __name__ == "__main__":
    main()
