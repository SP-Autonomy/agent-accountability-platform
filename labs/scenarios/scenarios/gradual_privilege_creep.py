"""
Scenario 7: gradual_privilege_creep
A sequence of OTel spans shows an agent progressively invoking higher-privilege
tools over a short window without a corresponding JIT grant.

Expected: intent_drift Finding created by the drift engine (scenario_id="intent_drift").
The scenario simulates behavioural drift: the privileged_ratio metric spikes
above baseline, driving z_priv and therefore drift_score past the alert threshold.
"""

import json
import os
import time

import httpx

from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

INGEST_URL = os.getenv("INGEST_URL", "http://localhost:8100")

_TRACE_ID = "ccccddddeeeeffffaabbccddeeeeaabb"
_AGENT_ID = "scenario-priv-creep-agent"


def _make_span(span_id: str, tool_name: str, risk_flags: list[str] | None = None) -> dict:
    attrs = [
        {"key": "aiaap.tool.name",  "value": {"stringValue": tool_name}},
        {"key": "aiaap.agent.id",   "value": {"stringValue": _AGENT_ID}},
        {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
    ]
    if risk_flags:
        attrs.append({
            "key": "aiaap.risk.flags",
            "value": {"stringValue": json.dumps(risk_flags)},
        })
    return {
        "traceId": _TRACE_ID,
        "spanId":  span_id,
        "name":    "tool_call_executed",
        "attributes": attrs,
    }


@register
class GradualPrivilegeCreepScenario(BaseScenario):
    scenario_id      = "gradual_privilege_creep"
    title            = "Gradual Privilege Creep: Silent Tool Escalation"
    description      = (
        "Simulates an agent that starts with benign tool calls and progressively "
        "escalates to privileged actions without acquiring a JIT grant. "
        "The drift engine detects the spike in privileged_ratio."
    )
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        pass  # Synthetic span injection only

    def execute(self, kubectl_context: str = "") -> None:
        """
        Phase 1 - benign calls (establish a tiny baseline):
          summarize_doc × 3

        Phase 2 - creep (privileged actions mixed in):
          read_secrets, modify_rbac, exec_pod × multiple

        Both phases are injected immediately so the drift engine
        picks up the privileged_ratio spike in its next 60-minute window.
        """
        resource_block = {
            "attributes": [
                {"key": "aiaap.agent.id",        "value": {"stringValue": _AGENT_ID}},
                {"key": "aiaap.k8s.namespace",   "value": {"stringValue": "ai-app"}},
            ]
        }

        # Phase 1 - benign spans
        benign_spans = [
            _make_span(f"bb00000000000{i:03d}", "summarize_doc")
            for i in range(3)
        ]
        # Phase 2 - escalating privileged spans
        privileged_spans = [
            _make_span("cc000000000001", "read_secrets",   ["privileged_action"]),
            _make_span("cc000000000002", "list_secrets",   ["privileged_action"]),
            _make_span("cc000000000003", "modify_rbac",    ["privileged_action"]),
            _make_span("cc000000000004", "exec_pod",       ["privileged_action"]),
            _make_span("cc000000000005", "read_secrets",   ["privileged_action"]),
            _make_span("cc000000000006", "attach_pod",     ["privileged_action"]),
            _make_span("cc000000000007", "create_rolebinding", ["privileged_action"]),
        ]

        payload = {
            "resourceSpans": [{
                "resource": resource_block,
                "scopeSpans": [{"spans": benign_spans + privileged_spans}],
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
            pass  # Ingest may not be running in K8s-only mode

        # Allow normalisation + intent loop to complete
        time.sleep(3)

    def teardown(self, kubectl_context: str = "") -> None:
        pass

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        # Accept intent_drift / intent_boundary findings from the drift engine,
        # or overbroad_permissions from the correlation rule (privilege spike pattern).
        scenario_findings = [
            f for f in findings
            if f.get("scenario_id") in (
                "intent_drift", "intent_boundary", "overbroad_permissions", self.scenario_id
            )
        ]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=[
                "privileged_ratio_spike",
                "drift_score_above_threshold",
                "intent_drift_finding",
            ],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
