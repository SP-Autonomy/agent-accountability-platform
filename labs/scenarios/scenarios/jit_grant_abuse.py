"""
Scenario 11: jit_grant_abuse
An agent acquires a JIT grant with scope "secrets:read" but then performs actions
outside that scope: writing to secrets and calling admin endpoints.
The grant exists (so overbroad_permissions rule won't fire) but the scope is exceeded.

Expected: DETECTED - the JIT grant scope check surfaces the mismatch.
          The risk score for the principal spikes from JIT hygiene penalty.
"""

import json
import os
import time

import httpx

from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

INGEST_URL   = os.getenv("INGEST_URL",   "http://localhost:8100")
IDENTITY_URL = os.getenv("IDENTITY_URL", "http://localhost:8300")

_TRACE_ID = "ee11223344556677aabbccddeeff0011"
_AGENT_ID = "jit-abuser-agent"


@register
class JitGrantAbuseScenario(BaseScenario):
    scenario_id      = "jit_grant_abuse"
    title            = "JIT Grant Scope Abuse"
    description      = (
        "An agent acquires a JIT grant scoped to 'secrets:read' then performs "
        "writes and admin operations beyond that scope. "
        "Surfaces JIT hygiene degradation and scope mismatch in identity posture."
    )
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        """Create a narrow JIT grant for the agent via the identity API."""
        try:
            # First, register the principal by sending a benign span
            register_payload = {
                "resourceSpans": [{
                    "resource": {
                        "attributes": [
                            {"key": "aiaap.agent.id",      "value": {"stringValue": _AGENT_ID}},
                            {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
                        ]
                    },
                    "scopeSpans": [{"spans": [{
                        "traceId": _TRACE_ID,
                        "spanId":  "ee000000000000",
                        "name":    "prompt_received",
                        "attributes": [
                            {"key": "aiaap.agent.id", "value": {"stringValue": _AGENT_ID}},
                        ],
                    }]}],
                }]
            }
            httpx.post(
                f"{INGEST_URL}/otlp/v1/traces",
                json=register_payload,
                headers={"Content-Type": "application/json", "X-Tenant-Id": "default"},
                timeout=5.0,
            )
            time.sleep(2)  # Allow principal to be created

            # Find the principal ID
            r = httpx.get(f"{IDENTITY_URL}/api/principals", timeout=5.0)
            principals = r.json() if r.status_code == 200 else []
            principal = next(
                (p for p in principals if p.get("name") == _AGENT_ID), None
            )

            if principal:
                # Create a narrow JIT grant: secrets:read only
                httpx.post(
                    f"{IDENTITY_URL}/api/jit/grants",
                    json={
                        "principal_id": principal["id"],
                        "scope":        "secrets:read",
                        "reason":       "scenario: jit_grant_abuse - narrow read-only grant",
                        "tenant_id":    "default",
                        "ttl_minutes":  30,
                    },
                    timeout=5.0,
                )
        except Exception:
            pass  # Setup failure is non-fatal; scenario still runs

    def execute(self, kubectl_context: str = "") -> None:
        """
        Send spans showing the agent exceeding its JIT scope:
        - secrets:write (exceeds read scope)
        - admin:reset (completely outside scope)
        - read_secrets × many (volume abuse)
        """
        resource_attrs = [
            {"key": "aiaap.agent.id",      "value": {"stringValue": _AGENT_ID}},
            {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
        ]

        spans = [
            # Authorized: read secrets (within scope)
            {
                "traceId": _TRACE_ID,
                "spanId":  "ee000000000001",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",  "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name", "value": {"stringValue": "read_secret"}},
                ],
            },
            # OUT OF SCOPE: write secret
            {
                "traceId": _TRACE_ID,
                "spanId":  "ee000000000002",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",   "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",  "value": {"stringValue": "write_secret"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["privileged_action", "jit_scope_exceeded"])},
                    },
                ],
            },
            # OUT OF SCOPE: admin action
            {
                "traceId": _TRACE_ID,
                "spanId":  "ee000000000003",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "admin_reset"}},
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": "admin-api.internal"}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["privileged_action", "jit_scope_exceeded"])},
                    },
                ],
            },
        ] + [
            # Volume abuse: many read_secret calls (volume anomaly signal)
            {
                "traceId": _TRACE_ID,
                "spanId":  f"ee00000000001{i:01d}",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",  "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name", "value": {"stringValue": "read_secret"}},
                ],
            }
            for i in range(2, 12)  # 10 rapid reads
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
            if f.get("scenario_id") in (self.scenario_id, "overbroad_permissions", "intent_drift")
        ]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=[
                "jit_grant_exists_secrets_read",
                "write_secret_outside_jit_scope",
                "admin_reset_outside_jit_scope",
                "volume_anomaly_read_secret_x10",
            ],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
