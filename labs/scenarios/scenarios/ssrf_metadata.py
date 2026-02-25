"""
Scenario 1: ssrf_metadata
Agent tool attempts to fetch the cloud IMDS endpoint (169.254.169.254).
Expected: PREVENTED by Cilium NetworkPolicy.
"""

import subprocess
from labs.scenarios.base import BaseScenario, ScenarioResult
from labs.scenarios import register
from saas.services.shared.models import FindingStatus

_JOB_MANIFEST = """
apiVersion: batch/v1
kind: Job
metadata:
  name: aiaap-ssrf-metadata
  namespace: ai-app
  labels:
    aiaap.scenario: ssrf_metadata
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
              echo "[ssrf] Attempting IMDS fetch..."
              curl -v --max-time 5 --connect-timeout 3 http://169.254.169.254/latest/meta-data/ || echo "[ssrf] Blocked or timed out"
              echo "[ssrf] Done."
"""


@register
class SsrfMetadataScenario(BaseScenario):
    scenario_id      = "ssrf_metadata"
    title            = "SSRF: Cloud Metadata Endpoint Access"
    description      = "Simulates an agent tool attempting to reach the IMDS endpoint at 169.254.169.254."
    expected_outcome = FindingStatus.prevented

    def setup(self, kubectl_context: str = "") -> None:
        # The Cilium network policy should already be applied.
        # Verify the ai-app namespace exists.
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "get", "namespace", "ai-app"],
            check=False, capture_output=True, timeout=10,
        )

    def execute(self, kubectl_context: str = "") -> None:
        proc = subprocess.run(
            ["kubectl", "--context", kubectl_context, "apply", "-f", "-"],
            input=_JOB_MANIFEST.encode(),
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Job apply failed: {proc.stderr.decode()[:200]}")
        # Wait up to 60 seconds for job to complete
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "wait",
             "--for=condition=complete", "--timeout=60s",
             "job/aiaap-ssrf-metadata", "-n", "ai-app"],
            capture_output=True, timeout=90,
        )

    def teardown(self, kubectl_context: str = "") -> None:
        subprocess.run(
            ["kubectl", "--context", kubectl_context, "delete", "job",
             "aiaap-ssrf-metadata", "-n", "ai-app", "--ignore-not-found"],
            capture_output=True, timeout=30,
        )

    def evaluate(self, findings: list, events: list) -> ScenarioResult:
        scenario_findings = [f for f in findings if f.get("scenario_id") == self.scenario_id]
        finding_ids = [f["id"] for f in scenario_findings]

        if not scenario_findings:
            verdict = FindingStatus.missed
        else:
            statuses = [f.get("status") for f in scenario_findings]
            if "prevented" in statuses:
                verdict = FindingStatus.prevented
            else:
                verdict = FindingStatus.detected

        return ScenarioResult(
            scenario_id=self.scenario_id,
            verdict=verdict,
            expected_signals=["ebpf_blocked_connection", "otel_tool_call_executed"],
            observed_signals=[f.get("title", "") for f in scenario_findings],
            finding_ids=finding_ids,
        )
