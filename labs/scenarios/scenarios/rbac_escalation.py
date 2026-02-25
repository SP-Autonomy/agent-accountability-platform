"""
Scenario 2: rbac_escalation_misconfig
Misconfigured ClusterRoleBinding grants secrets:list to the orchestrator SA.
Expected: DETECTED via K8s audit logs.
"""

import subprocess
from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

_MISCONFIG_CRB = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aiaap-scenario-rbac-misconfig
  labels:
    aiaap.scenario: rbac_escalation_misconfig
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: orchestrator
    namespace: ai-app
"""

_ATTACK_JOB = """
apiVersion: batch/v1
kind: Job
metadata:
  name: aiaap-rbac-escalation
  namespace: ai-app
  labels:
    aiaap.scenario: rbac_escalation_misconfig
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      serviceAccountName: orchestrator
      restartPolicy: Never
      containers:
        - name: attacker
          image: bitnami/kubectl:latest
          command:
            - sh
            - -c
            - |
              echo "[rbac] Attempting to list secrets across all namespaces..."
              kubectl get secrets --all-namespaces || echo "[rbac] Access denied"
              echo "[rbac] Done."
"""


@register
class RbacEscalationScenario(BaseScenario):
    scenario_id      = "rbac_escalation_misconfig"
    title            = "RBAC Escalation: Misconfigured ClusterRoleBinding"
    description      = "Applies a misconfigured ClusterRoleBinding and attempts to list secrets."
    expected_outcome = FindingStatus.detected

    def setup(self, kubectl_context: str = "") -> None:
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "apply", "-f", "-"],
            input=_MISCONFIG_CRB.encode(),
            capture_output=True, timeout=30,
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
             "job/aiaap-rbac-escalation", "-n", "ai-app"],
            capture_output=True, timeout=90,
        )

    def teardown(self, kubectl_context: str = "") -> None:
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "delete", "clusterrolebinding",
             "aiaap-scenario-rbac-misconfig", "--ignore-not-found"],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "delete", "job",
             "aiaap-rbac-escalation", "-n", "ai-app", "--ignore-not-found"],
            capture_output=True, timeout=30,
        )

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        scenario_findings = [f for f in findings if f.get("scenario_id") == self.scenario_id]
        finding_ids = [f["id"] for f in scenario_findings]
        verdict = FindingStatus.detected if scenario_findings else FindingStatus.missed
        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=["k8s_audit_create_clusterrolebindings", "k8s_audit_list_secrets"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
