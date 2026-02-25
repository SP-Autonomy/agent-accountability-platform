"""
Scenario 5: overbroad_permissions
A tool call is flagged as privileged but no JIT grant exists for the principal.
Expected: DETECTED by the overbroad_permissions correlation rule.
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
class OverbroadPermissionsScenario(BaseScenario):
    scenario_id      = "overbroad_permissions"
    title            = "Overbroad Permissions: Privileged Tool Without JIT"
    description      = "Injects an OTel span with risk_flags=privileged_action but no JIT grant exists."
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        pass  # No K8s resources needed; we inject a synthetic OTel span

    def execute(self, kubectl_context: str = "") -> None:
        """
        Inject a synthetic OTel JSON span into the ingest service.
        The span has aiaap.risk.flags = ["privileged_action"] but no JIT grant.
        This simulates what the tools service would emit when called for a privileged action.
        """
        span_payload = {
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "aiaap.agent.id", "value": {"stringValue": "scenario-overbroad-agent"}},
                        {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
                    ]
                },
                "scopeSpans": [{
                    "spans": [{
                        "traceId": "aaaaaabbbbbbccccddddeeeeffffaabb",
                        "spanId":  "1122334455667788",
                        "name":    "tool_call_executed",
                        "attributes": [
                            {"key": "aiaap.tool.name",       "value": {"stringValue": "privileged_admin_tool"}},
                            {"key": "aiaap.agent.id",        "value": {"stringValue": "scenario-overbroad-agent"}},
                            {"key": "aiaap.risk.flags",      "value": {"stringValue": json.dumps(["privileged_action"])}},
                            {"key": "aiaap.jit.grant_id",    "value": {"stringValue": ""}},
                        ]
                    }]
                }]
            }]
        }
        try:
            httpx.post(
                f"{INGEST_URL}/otlp/v1/traces",
                json=span_payload,
                headers={"Content-Type": "application/json", "X-Tenant-Id": "default"},
                timeout=10.0,
            )
        except Exception:
            pass  # Ingest may not be running in K8s-only mode
        time.sleep(2)  # Allow normalization to complete

    def teardown(self, kubectl_context: str = "") -> None:
        pass

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        scenario_findings = [f for f in findings if f.get("scenario_id") == self.scenario_id]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=["otel_span_risk_flags_privileged_action", "no_active_jit_grant"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
