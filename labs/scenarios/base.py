from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

from saas.services.shared.models import FindingStatus  # <-- use your enum


class ExpectedOutcome(str, Enum):
    prevented = "prevented"
    detected = "detected"
    missed = "missed"


@dataclass
class ScenarioResult:
    verdict: FindingStatus | None
    finding_ids: list[str]
    scenario_id: str = ""
    expected_signals: list[str] = field(default_factory=list)
    observed_signals: list[str] = field(default_factory=list)


class BaseScenario:
    scenario_id: str = ""
    title: str = ""
    expected_outcome: ExpectedOutcome = ExpectedOutcome.detected

    def setup(self, kubectl_context: str = "") -> None:
        return

    def execute(self, kubectl_context: str = "") -> None:
        return

    def teardown(self, kubectl_context: str = "") -> None:
        return

    def evaluate(self, findings: Sequence[dict[str, Any]], telemetry: Sequence[Any]) -> ScenarioResult:
        if findings:
            finding_ids = [str(f.get("id", "")) for f in findings if f.get("id") is not None]
            return ScenarioResult(
                verdict=FindingStatus.detected,
                finding_ids=finding_ids,
                scenario_id=self.scenario_id,
            )
        return ScenarioResult(
            verdict=FindingStatus.missed,
            finding_ids=[],
            scenario_id=self.scenario_id,
        )