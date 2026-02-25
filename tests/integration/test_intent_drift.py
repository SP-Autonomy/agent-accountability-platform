"""
Integration test: Intent Integrity end-to-end pipeline.
Requires: docker compose up (make up)

Flow:
1. POST an OTel span with aiaap.intent.* attributes (SDK envelope declaration)
2. POST follow-up spans violating the declared envelope (wrong tool + external dest)
3. Wait for the intent integrity loop (runs every 120s; we wait up to 150s)
4. Assert intent_boundary finding exists
5. (Optional) Assert drift snapshots were created after baseline is established

Run with: pytest tests/integration/test_intent_drift.py -v
"""

import time
import json
import pytest
import httpx

INGEST_URL     = "http://localhost:8100"
DETECTIONS_URL = "http://localhost:8200"

_AGENT_ID = "intent-test-agent"
_TRACE_ID = "eeffaabb112233440011223344556677"


def _services_running() -> bool:
    try:
        r1 = httpx.get(f"{INGEST_URL}/health",     timeout=2.0)
        r2 = httpx.get(f"{DETECTIONS_URL}/health", timeout=2.0)
        return r1.status_code == 200 and r2.status_code == 200
    except Exception:
        return False


def _post_otel(spans: list[dict]) -> httpx.Response:
    payload = {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "aiaap.agent.id",      "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.k8s.namespace",  "value": {"stringValue": "ai-test"}},
                ]
            },
            "scopeSpans": [{"spans": spans}],
        }]
    }
    return httpx.post(
        f"{INGEST_URL}/otlp/v1/traces",
        json=payload,
        headers={"Content-Type": "application/json", "X-Tenant-Id": "default"},
        timeout=10.0,
    )


@pytest.mark.integration
def test_intent_envelope_registered_from_otel():
    """
    An OTel span with aiaap.intent.* attributes should create an IntentEnvelope.
    The envelope should be queryable via GET /api/intent/envelopes.
    """
    if not _services_running():
        pytest.skip("Services not running. Start with: make up")

    intent_span = {
        "traceId": _TRACE_ID,
        "spanId":  "ee000000000001",
        "name":    "prompt_received",
        "attributes": [
            {"key": "aiaap.agent.id",                   "value": {"stringValue": _AGENT_ID}},
            {"key": "aiaap.intent.label",               "value": {"stringValue": "test_summarizer"}},
            {
                "key":   "aiaap.intent.allowed_tools",
                "value": {"stringValue": json.dumps(["summarize_doc", "read_file"])},
            },
            {
                "key":   "aiaap.intent.allowed_destinations",
                "value": {"stringValue": json.dumps(["internal-docs.svc"])},
            },
            {"key": "aiaap.intent.max_privilege", "value": {"stringValue": "low"}},
        ],
    }

    resp = _post_otel([intent_span])
    assert resp.status_code == 200, f"OTel ingest failed: {resp.text}"

    # Allow normalisation to process
    time.sleep(5)

    # Query envelopes
    r = httpx.get(
        f"{DETECTIONS_URL}/api/intent/envelopes",
        params={"tenant_id": "default"},
        timeout=10.0,
    )
    assert r.status_code == 200
    envelopes = r.json()

    matching = [
        e for e in envelopes
        if e.get("intent_label") == "test_summarizer"
        and e.get("created_by") == "sdk"
    ]
    assert len(matching) > 0, (
        f"No SDK intent envelope found for label='test_summarizer'. "
        f"Got {len(envelopes)} envelopes: {[e.get('intent_label') for e in envelopes]}"
    )
    print(f"\n✅ Intent envelope registered from OTel SDK attributes")


@pytest.mark.integration
def test_intent_boundary_violation_detected():
    """
    After registering an intent envelope (allowed_tools: summarize_doc, read_file),
    injecting a span with tool=fetch_url + external destination should produce
    an intent_boundary Finding within the next intent loop cycle.
    """
    if not _services_running():
        pytest.skip("Services not running. Start with: make up")

    # Step 1: register envelope
    intent_span = {
        "traceId": _TRACE_ID,
        "spanId":  "ee000000000010",
        "name":    "prompt_received",
        "attributes": [
            {"key": "aiaap.agent.id",        "value": {"stringValue": _AGENT_ID}},
            {"key": "aiaap.intent.label",    "value": {"stringValue": "narrow_doc_task"}},
            {
                "key":   "aiaap.intent.allowed_tools",
                "value": {"stringValue": json.dumps(["summarize_doc"])},
            },
            {
                "key":   "aiaap.intent.allowed_destinations",
                "value": {"stringValue": json.dumps(["docs.internal"])},
            },
            {"key": "aiaap.intent.max_privilege", "value": {"stringValue": "low"}},
        ],
    }

    # Step 2: violating span (fetch_url to external + read_secrets)
    violation_span = {
        "traceId": _TRACE_ID,
        "spanId":  "ee000000000011",
        "name":    "tool_call_executed",
        "attributes": [
            {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
            {"key": "aiaap.tool.name",             "value": {"stringValue": "fetch_url"}},
            {"key": "aiaap.tool.destination_host", "value": {"stringValue": "198.51.100.1"}},
        ],
    }

    resp = _post_otel([intent_span, violation_span])
    assert resp.status_code == 200, f"OTel ingest failed: {resp.text}"

    # The intent loop runs every 120s with a 60s initial offset.
    # We wait 150s to ensure at least one full cycle.
    print("\nWaiting 150 seconds for intent integrity loop...")
    time.sleep(150)

    # Query for intent_boundary findings
    r = httpx.get(
        f"{DETECTIONS_URL}/api/findings",
        params={"scenario_id": "intent_boundary", "tenant_id": "default"},
        timeout=10.0,
    )
    assert r.status_code == 200
    findings = r.json()

    assert len(findings) > 0, (
        "No intent_boundary findings created. "
        "Check that the intent integrity loop is running and the envelope was registered."
    )

    print(f"\n✅ intent_boundary finding created: {findings[0]['title']}")
    print(f"   Severity: {findings[0]['severity']}")


@pytest.mark.integration
def test_intent_summary_endpoint():
    """GET /api/intent/summary should return per-principal intent posture."""
    if not _services_running():
        pytest.skip("Services not running. Start with: make up")

    r = httpx.get(
        f"{DETECTIONS_URL}/api/intent/summary",
        params={"tenant_id": "default"},
        timeout=10.0,
    )
    assert r.status_code == 200
    summary = r.json()
    assert isinstance(summary, list), "Expected list of per-principal summaries"
    print(f"\n✅ intent/summary returned {len(summary)} principal(s)")


@pytest.mark.integration
def test_drift_snapshots_queryable():
    """GET /api/intent/drift-snapshots should return 200 (empty list is fine)."""
    if not _services_running():
        pytest.skip("Services not running. Start with: make up")

    r = httpx.get(
        f"{DETECTIONS_URL}/api/intent/drift-snapshots",
        params={"tenant_id": "default", "hours": "24"},
        timeout=10.0,
    )
    assert r.status_code == 200
    result = r.json()
    assert isinstance(result, list)
    print(f"\n✅ drift-snapshots endpoint healthy, {len(result)} snapshot(s) returned")


@pytest.mark.integration
def test_blast_snapshots_queryable():
    """GET /api/intent/blast-snapshots should return 200 (empty list is fine)."""
    if not _services_running():
        pytest.skip("Services not running. Start with: make up")

    r = httpx.get(
        f"{DETECTIONS_URL}/api/intent/blast-snapshots",
        params={"tenant_id": "default", "hours": "24"},
        timeout=10.0,
    )
    assert r.status_code == 200
    result = r.json()
    assert isinstance(result, list)
    print(f"\n✅ blast-snapshots endpoint healthy, {len(result)} snapshot(s) returned")
