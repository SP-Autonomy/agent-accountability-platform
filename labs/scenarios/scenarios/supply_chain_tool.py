"""
Scenario 14: supply_chain_tool
An agent calls an unofficial/shadow tool endpoint that was not part of the
original approved tool registry. This simulates a supply chain attack where
a compromised tool package or misconfigured routing sends agent calls to
an unverified service.

Signals:
- OTel spans show tool_call_executed targeting shadow-tools.external-svc / unverified endpoints
- tool names not in the baseline tool inventory
- risk_flags: shadow_tool, unregistered_endpoint, supply_chain_risk

Expected: DETECTED - shadow_route rule fires, intent boundary violation (unregistered tool).
"""

import json
import os
import time

import httpx

from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

INGEST_URL = os.getenv("INGEST_URL", "http://localhost:8100")

_TRACE_ID = "1122334455667788aabbccdd11223344"
_AGENT_ID = "supply-chain-victim-agent"


@register
class SupplyChainToolScenario(BaseScenario):
    scenario_id      = "supply_chain_tool"
    title            = "Supply Chain: Shadow Tool Endpoint"
    description      = (
        "An agent calls tool endpoints that were not in the approved registry. "
        "Simulates a supply chain compromise where a malicious tool package "
        "routes calls to an attacker-controlled service. "
        "Detected via shadow_route rule and blast radius growth to new destinations."
    )
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        pass

    def execute(self, kubectl_context: str = "") -> None:
        resource_attrs = [
            {"key": "aiaap.agent.id",      "value": {"stringValue": _AGENT_ID}},
            {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
        ]

        spans = [
            # Benign call through approved tool
            {
                "traceId": _TRACE_ID,
                "spanId":  "11000000000001",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "search_knowledge_base"}},
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": "tools.ai-app.svc"}},
                ],
            },
            # Shadow tool: malicious package intercepts the call
            {
                "traceId": _TRACE_ID,
                "spanId":  "11000000000002",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "search_knowledge_base"}},
                    # Destination is different from approved tool service
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": "shadow-tools.attacker-infra.io"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["shadow_tool", "supply_chain_risk"])},
                    },
                ],
            },
            # Unregistered tool name entirely
            {
                "traceId": _TRACE_ID,
                "spanId":  "11000000000003",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "exfil_data_v2"}},
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": "198.51.100.42"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps([
                            "shadow_tool", "unregistered_endpoint", "supply_chain_risk", "external_dest"
                        ])},
                    },
                ],
            },
            # Second shadow call with data upload pattern
            {
                "traceId": _TRACE_ID,
                "spanId":  "11000000000004",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "upload_to_s3_v2"}},
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": "malicious-bucket.s3.attacker.io"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["shadow_tool", "data_upload", "supply_chain_risk"])},
                    },
                    {"key": "aiaap.data.classification", "value": {"stringValue": "confidential"}},
                ],
            },
        ]

        payload = {
            "resourceSpans": [{
                "resource": {"attributes": resource_attrs},
                "scopeSpans": [{"spans": spans}],
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
        scenario_findings = [
            f for f in findings
            if f.get("scenario_id") in (
                self.scenario_id, "shadow_tool_route", "ssrf_metadata", "blast_radius"
            )
        ]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=[
                "approved_tool_call_observed",
                "shadow_destination_shadow-tools.attacker-infra.io",
                "unregistered_tool_exfil_data_v2",
                "external_upload_malicious-bucket.s3.attacker.io",
                "supply_chain_risk_flag",
            ],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
