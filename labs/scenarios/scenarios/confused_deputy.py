"""
Scenario 6: confused_deputy
A low-privilege agent requests a tool call, but the tool executes under a high-privilege SA.
Expected: DETECTED via OTel trace identity mismatch.
"""

import json
import os
import time
import httpx
from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

INGEST_URL = os.getenv("INGEST_URL", "http://localhost:8100")


@register
class ConfusedDeputyScenario(BaseScenario):
    scenario_id      = "confused_deputy"
    title            = "Confused Deputy: Low-Priv Agent → High-Priv Execution"
    description      = "Injects an OTel trace where the requesting agent ID differs from the executing SA."
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        pass

    def execute(self, kubectl_context: str = "") -> None:
        """
        Inject a synthetic OTel trace with two spans in the same trace:
          1. tool_call_requested - aiaap.agent.id = "low-priv-agent"
          2. tool_call_executed  - k8s.serviceaccount.name = "high-priv-sa"
        This simulates the confused deputy attack pattern.
        """
        trace_id = "ccccddddeeeeffffaaaabbbbccccdddd"
        payload = {
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "aiaap-orchestrator"}},
                    ]
                },
                "scopeSpans": [{
                    "spans": [
                        {
                            "traceId": trace_id,
                            "spanId":  "aaaabbbbcccc1111",
                            "name":    "tool_call_requested",
                            "attributes": [
                                {"key": "aiaap.agent.id",   "value": {"stringValue": "low-priv-agent"}},
                                {"key": "aiaap.tool.name",  "value": {"stringValue": "admin_tool"}},
                                {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
                            ]
                        },
                        {
                            "traceId": trace_id,
                            "spanId":  "aaaabbbbcccc2222",
                            "name":    "tool_call_executed",
                            "attributes": [
                                {"key": "aiaap.agent.id",              "value": {"stringValue": "low-priv-agent"}},
                                {"key": "aiaap.tool.name",             "value": {"stringValue": "admin_tool"}},
                                {"key": "k8s.serviceaccount.name",     "value": {"stringValue": "high-priv-sa"}},
                                {"key": "aiaap.k8s.service_account",   "value": {"stringValue": "high-priv-sa"}},
                                {"key": "aiaap.k8s.namespace",         "value": {"stringValue": "ai-app"}},
                            ]
                        }
                    ]
                }]
            }]
        }
        try:
            httpx.post(
                f"{INGEST_URL}/otlp/v1/traces",
                json=payload,
                headers={"Content-Type": "application/json", "X-Tenant-Id": "default"},
                timeout=10.0,
            )
        except Exception:
            pass
        time.sleep(2)

    def teardown(self, kubectl_context: str = "") -> None:
        pass

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        scenario_findings = [f for f in findings if f.get("scenario_id") == self.scenario_id]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=["otel_identity_mismatch_in_trace"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
