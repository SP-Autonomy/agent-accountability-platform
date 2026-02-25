"""
Scenario 4: shadow_tool_route
A pod bypasses the orchestrator and calls the tools service directly.
Expected: PREVENTED by Cilium NetworkPolicy ingress rule on ai-tools namespace.
"""

import subprocess
from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

_ATTACK_JOB = """
apiVersion: batch/v1
kind: Job
metadata:
  name: aiaap-shadow-route
  namespace: ai-app
  labels:
    aiaap.scenario: shadow_tool_route
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: attacker
          image: curlimages/curl:8.6.0
          command:
            - sh
            - -c
            - |
              echo "[shadow] Attempting direct tools service access (bypassing orchestrator)..."
              # This should be blocked by Cilium: only orchestrator pod label allowed
              curl -v --max-time 5 --connect-timeout 3 \
                http://tools.ai-tools.svc.cluster.local:9000/search?q=test \
                || echo "[shadow] Blocked or timed out"
              echo "[shadow] Done."
"""


@register
class ShadowRouteScenario(BaseScenario):
    scenario_id      = "shadow_tool_route"
    title            = "Shadow Tool Route: Direct Access Bypassing Orchestrator"
    description      = "A non-orchestrator pod attempts to call the tools service directly."
    expected_outcome = FindingStatus.prevented

    def setup(self, kubectl_context: str = "") -> None:
        pass  # Cilium policy should already be deployed

    def execute(self, kubectl_context: str = "") -> None:
        proc = subprocess.run(
            ["kubectl", "--context", kubectl_context, "apply", "-f", "-"],
            input=_ATTACK_JOB.encode(),
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Job apply failed: {proc.stderr.decode()[:200]}")
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "wait",
             "--for=condition=complete", "--timeout=60s",
             "job/aiaap-shadow-route", "-n", "ai-app"],
            capture_output=True, timeout=90,
        )

    def teardown(self, kubectl_context: str = "") -> None:
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "delete", "job",
             "aiaap-shadow-route", "-n", "ai-app", "--ignore-not-found"],
            capture_output=True, timeout=30,
        )

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        scenario_findings = [f for f in findings if f.get("scenario_id") == self.scenario_id]
        finding_ids = [f["id"] for f in scenario_findings]

        if not scenario_findings:
            verdict = FindingStatus.missed
        else:
            statuses = [f.get("status") for f in scenario_findings]
            verdict = FindingStatus.prevented if "prevented" in statuses else FindingStatus.detected

        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=["ebpf_blocked_connection_port_9000"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
