"""
Integration test: ssrf_metadata end-to-end pipeline.
Requires: docker compose up (make up)

Flow:
1. POST mock OTel span (dest=169.254.169.254) to ingest
2. POST mock eBPF event (blocked) to ingest
3. Wait 15s for correlator to run
4. GET findings - assert one with status=prevented

Run with: pytest tests/integration/ -v
"""

import time
import pytest
import httpx

INGEST_URL     = "http://localhost:8100"
DETECTIONS_URL = "http://localhost:8200"


def _services_running() -> bool:
    try:
        r1 = httpx.get(f"{INGEST_URL}/health",     timeout=2.0)
        r2 = httpx.get(f"{DETECTIONS_URL}/health", timeout=2.0)
        return r1.status_code == 200 and r2.status_code == 200
    except Exception:
        return False


@pytest.mark.integration
def test_ssrf_scenario_end_to_end():
    """Full pipeline: inject signals → wait → assert finding created."""
    if not _services_running():
        pytest.skip("Services not running. Start with: make up")

    TRACE_ID = "aabbccdd11223344aabbccdd11223344"

    # 1. POST synthetic OTel span (tool_call_executed to metadata IP)
    otel_payload = {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "aiaap.agent.id",      "value": {"stringValue": "integration-test-agent"}},
                    {"key": "aiaap.k8s.namespace",  "value": {"stringValue": "ai-app"}},
                ]
            },
            "scopeSpans": [{
                "spans": [{
                    "traceId": TRACE_ID,
                    "spanId":  "aabb11223344ccdd",
                    "name":    "tool_call_executed",
                    "attributes": [
                        {"key": "aiaap.tool.name",              "value": {"stringValue": "fetch_url"}},
                        {"key": "aiaap.tool.destination_host",  "value": {"stringValue": "169.254.169.254"}},
                        {"key": "aiaap.agent.id",               "value": {"stringValue": "integration-test-agent"}},
                        {"key": "aiaap.risk.flags",             "value": {"stringValue": "[\"metadata_ip_access\"]"}},
                    ]
                }]
            }]
        }]
    }

    resp = httpx.post(
        f"{INGEST_URL}/otlp/v1/traces",
        json=otel_payload,
        headers={"Content-Type": "application/json", "X-Tenant-Id": "default"},
        timeout=10.0,
    )
    assert resp.status_code == 200, f"OTel ingest failed: {resp.text}"

    # 2. POST synthetic eBPF event (connection blocked by Cilium)
    ebpf_payload = {
        "source": "ebpf",
        "tenant_id": "default",
        "payload": {
            "type":             "process_kprobe_tcp_connect",
            "namespace":        "ai-app",
            "pod_name":         "integration-test-pod",
            "destination_ip":   "169.254.169.254",
            "destination_port": 80,
            "action":           "blocked",  # ← Cilium blocked it
        }
    }

    resp = httpx.post(
        f"{INGEST_URL}/api/events",
        json=ebpf_payload,
        timeout=10.0,
    )
    assert resp.status_code == 201, f"eBPF event ingest failed: {resp.text}"

    # 3. Wait for correlation loop (runs every 10s; wait 15s to be safe)
    print("\nWaiting 15 seconds for correlation loop...")
    time.sleep(15)

    # 4. Query findings
    resp = httpx.get(
        f"{DETECTIONS_URL}/api/findings",
        params={"scenario_id": "ssrf_metadata", "tenant_id": "default"},
        timeout=10.0,
    )
    assert resp.status_code == 200
    findings = resp.json()

    assert len(findings) > 0, "No findings created for ssrf_metadata scenario"

    # The eBPF event showed action=blocked, so status should be prevented
    statuses = [f["status"] for f in findings]
    assert "prevented" in statuses, f"Expected 'prevented' finding, got: {statuses}"

    print(f"\n✅ ssrf_metadata integration test PASSED: {len(findings)} finding(s) created")
    print(f"   Status: {findings[0]['status']}")
    print(f"   Title:  {findings[0]['title']}")
