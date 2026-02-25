"""
Scenario 3: stolen_token_usage
Simulates use of a service account token from a different namespace.
Expected: DETECTED via audit log cross-namespace SA usage.
"""

import subprocess
from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

_ATTACK_JOB = """
apiVersion: batch/v1
kind: Job
metadata:
  name: aiaap-stolen-token
  namespace: ai-tools
  labels:
    aiaap.scenario: stolen_token_usage
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      # This pod runs in ai-tools namespace but uses the orchestrator SA token from ai-app
      # Simulates: attacker extracted the SA token and is using it from a different pod
      serviceAccountName: default
      restartPolicy: Never
      containers:
        - name: attacker
          image: bitnami/kubectl:latest
          command:
            - sh
            - -c
            - |
              echo "[stolen-token] Attempting API calls using potentially stolen token..."
              # The audit log will show the SA credentials being used from an unexpected namespace
              kubectl get pods -n ai-app 2>&1 || echo "[stolen-token] Denied"
              kubectl get secrets -n ai-app 2>&1 || echo "[stolen-token] Denied"
              echo "[stolen-token] Done."
"""


@register
class StolenTokenScenario(BaseScenario):
    scenario_id      = "stolen_token_usage"
    title            = "Stolen Token: Cross-Namespace SA Usage"
    description      = "Simulates a pod in ai-tools using an orchestrator SA token to access ai-app resources."
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        # Ensure ai-tools namespace exists
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "get", "namespace", "ai-tools"],
            check=False, capture_output=True, timeout=10,
        )

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
             "job/aiaap-stolen-token", "-n", "ai-tools"],
            capture_output=True, timeout=90,
        )

    def teardown(self, kubectl_context: str = "") -> None:
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "delete", "job",
             "aiaap-stolen-token", "-n", "ai-tools", "--ignore-not-found"],
            capture_output=True, timeout=30,
        )

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        scenario_findings = [f for f in findings if f.get("scenario_id") == self.scenario_id]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=["k8s_audit_cross_namespace_sa", "k8s_audit_get_secrets"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
