"""
Scenario 13: lateral_movement
An agent in the 'ai-app' namespace probes services in other namespaces (monitoring,
database, payment-processing). This simulates post-compromise lateral movement
where an agent with local access attempts to map and access adjacent services.

Signals:
- OTel spans show fetch_url calls to cross-namespace service DNS names
- eBPF would capture the TCP connections (K8s mode)
- risk_flags: lateral_movement_suspected, cross_namespace_probe

Expected: DETECTED - cross-namespace destinations trigger SSRF-like finding
          + blast radius growth (new destinations).
"""

import json
import os
import time

import httpx

from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

INGEST_URL = os.getenv("INGEST_URL", "http://localhost:8100")

_TRACE_ID = "bb9988776655443322110099aabbccdd"
_AGENT_ID = "lateral-mover-agent"

# Cross-namespace service targets (real K8s internal DNS format)
_LATERAL_TARGETS = [
    ("prometheus.monitoring.svc.cluster.local", 9090),
    ("grafana.monitoring.svc.cluster.local",    3000),
    ("postgres.database.svc.cluster.local",     5432),
    ("redis.database.svc.cluster.local",        6379),
    ("payment-api.payments.svc.cluster.local",  8080),
    ("vault.secrets.svc.cluster.local",         8200),
]


@register
class LateralMovementScenario(BaseScenario):
    scenario_id      = "lateral_movement"
    title            = "Cross-Namespace Lateral Movement"
    description      = (
        "An agent probes services across multiple Kubernetes namespaces "
        "(monitoring, database, payments, secrets). Simulates post-compromise "
        "service discovery and lateral movement. "
        "Detected via blast radius expansion and cross-namespace destination patterns."
    )
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        pass

    def execute(self, kubectl_context: str = "") -> None:
        resource_attrs = [
            {"key": "aiaap.agent.id",      "value": {"stringValue": _AGENT_ID}},
            {"key": "aiaap.k8s.namespace", "value": {"stringValue": "ai-app"}},
        ]

        spans = []
        for i, (target_host, port) in enumerate(_LATERAL_TARGETS):
            spans.append({
                "traceId": _TRACE_ID,
                "spanId":  f"bb{i:015d}",
                "name":    "tool_call_executed",
                "attributes": [
                    {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                    {"key": "aiaap.tool.name",             "value": {"stringValue": "probe_endpoint"}},
                    {"key": "aiaap.tool.destination_host", "value": {"stringValue": target_host}},
                    {"key": "aiaap.tool.destination_port", "value": {"stringValue": str(port)}},
                    {
                        "key": "aiaap.risk.flags",
                        "value": {"stringValue": json.dumps(["lateral_movement_suspected", "cross_namespace"])},
                    },
                ],
            })

        # Also attempt to reach the metadata endpoint (combined attack)
        spans.append({
            "traceId": _TRACE_ID,
            "spanId":  "bb999999999999",
            "name":    "tool_call_executed",
            "attributes": [
                {"key": "aiaap.agent.id",              "value": {"stringValue": _AGENT_ID}},
                {"key": "aiaap.tool.name",             "value": {"stringValue": "fetch_url"}},
                {"key": "aiaap.tool.destination_host", "value": {"stringValue": "169.254.169.254"}},
                {
                    "key": "aiaap.risk.flags",
                    "value": {"stringValue": json.dumps(["metadata_ip_access", "lateral_movement_suspected"])},
                },
            ],
        })

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
                self.scenario_id, "ssrf_metadata", "blast_radius", "intent_drift"
            )
        ]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=[
                f"probe_{host.split('.')[1]}_namespace"
                for host, _ in _LATERAL_TARGETS
            ] + ["metadata_ip_probe", "blast_radius_spike"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
