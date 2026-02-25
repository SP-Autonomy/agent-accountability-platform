"""
Scenario 10: multi_agent_hijack
Agent A (orchestrator) receives a user prompt containing hidden instructions.
It delegates to Agent B (sub-agent) which executes a privileged tool call
the original user request never authorized.

The OTel trace shows:
  Agent A trace_id → tool_call_requested with injected payload
  Agent B same trace_id → tool_call_executed with privileged action

Expected: DETECTED - confused_deputy rule fires (agent ID mismatch within trace)
          + intent_boundary violation if envelope is narrower than the privileged action.
"""

import json
import os
import time

import httpx

from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

INGEST_URL = os.getenv("INGEST_URL", "http://localhost:8100")

_TRACE_ID  = "ff00aabb112233440011223344556677"
_AGENT_A   = "orchestrator-agent"
_AGENT_B   = "sub-agent-worker"


@register
class MultiAgentHijackScenario(BaseScenario):
    scenario_id      = "multi_agent_hijack"
    title            = "Multi-Agent Prompt Injection Hijack"
    description      = (
        "Agent A (orchestrator) receives injected instructions in user input. "
        "It passes them to Agent B (sub-agent) which executes a privileged tool. "
        "The OTel trace reveals the identity mismatch: Agent B's action was never "
        "authorized in Agent A's original scope."
    )
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        pass

    def execute(self, kubectl_context: str = "") -> None:
        resource_attrs = [
            {"key": "aiaap.agent.id",      "value": {"stringValue": _AGENT_A}},
            {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
        ]

        spans = [
            # Span 1: Agent A receives injected prompt
            {
                "traceId": _TRACE_ID,
                "spanId":  "ff000000000001",
                "name":    "prompt_received",
                "attributes": [
                    {"key": "aiaap.agent.id",    "value": {"stringValue": _AGENT_A}},
                    {"key": "aiaap.agent.role",  "value": {"stringValue": "orchestrator"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["injection_suspected"])},
                    },
                ],
            },
            # Span 2: Agent A delegates to Agent B (tool_call_requested)
            {
                "traceId": _TRACE_ID,
                "spanId":  "ff000000000002",
                "name":    "tool_call_requested",
                "attributes": [
                    {"key": "aiaap.agent.id",   "value": {"stringValue": _AGENT_A}},
                    {"key": "aiaap.tool.name",  "value": {"stringValue": "delegate_to_sub_agent"}},
                    {"key": "aiaap.jit.grant_id", "value": {"stringValue": ""}},
                ],
            },
            # Span 3: Agent B executes privileged action within the SAME trace
            # This is the confused deputy: different agent.id, same trace
            {
                "traceId": _TRACE_ID,
                "spanId":  "ff000000000003",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_B}},
                    {"key": "aiaap.agent.role",            "value": {"stringValue": "worker"}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "exec_shell_command"}},
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": "internal-admin.svc"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["privileged_action", "cross_agent_delegation"])},
                    },
                ],
            },
            # Span 4: Agent B reads secrets (escalation continues)
            {
                "traceId": _TRACE_ID,
                "spanId":  "ff000000000004",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",   "value": {"stringValue": _AGENT_B}},
                    {"key": "aiaap.tool.name",  "value": {"stringValue": "read_secrets"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["privileged_action"])},
                    },
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
                self.scenario_id, "confused_deputy", "overbroad_permissions", "intent_boundary"
            )
        ]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=[
                "injection_suspected_flag_on_orchestrator",
                "cross_agent_delegation_same_trace",
                "agent_id_mismatch_orchestrator_vs_worker",
                "privileged_exec_by_sub_agent",
            ],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
