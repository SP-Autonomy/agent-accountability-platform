"""
CLI entry point: python -m labs.scenarios <scenario_id>

Examples:
  python -m labs.scenarios multi_agent_hijack
  python -m labs.scenarios intent_mismatch_exfil

Environment:
  DATABASE_URL   - SQLAlchemy/psycopg2 DSN
  DETECTIONS_URL - Detections service base URL

Host defaults:
  DATABASE_URL defaults to localhost:5432 to support running from a venv on the host.
"""

from __future__ import annotations

import os
import sys

# Host-friendly defaults. We use setdefault so Makefile/env can override.
os.environ.setdefault("DATABASE_URL", "postgresql://aiaap:aiaap@localhost:5432/aiaap")
os.environ.setdefault("DETECTIONS_URL", "http://localhost:8200")

# Compatibility shim if any older scenarios import `from scenarios import register`
import labs.scenarios as _aiaap_scenarios_pkg
sys.modules.setdefault("scenarios", _aiaap_scenarios_pkg)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    scenario_id = sys.argv[1]

    from labs.scenarios import get_scenario_class
    from labs.scenarios.runner import ScenarioRunner

    cls = get_scenario_class(scenario_id)
    if not cls:
        print(f"Unknown scenario: '{scenario_id}'")
        try:
            from labs.scenarios import list_registered

            available = list_registered()
            if available:
                print("Available scenarios:")
                for s in available:
                    print(f"  - {s}")
        except Exception:
            pass
        return 1

    print(f"\nRunning scenario: {scenario_id}")
    print(f"  Title:    {getattr(cls, 'title', cls.__name__)}")
    print(f"  Expected: {getattr(cls, 'expected_outcome', 'unknown')}")
    print(f"  DB:       {os.getenv('DATABASE_URL')}")
    print(f"  Detect:   {os.getenv('DETECTIONS_URL')}\n")

    runner = ScenarioRunner(scenario=cls())
    run = runner.run()

    if run is None:
        print("Run failed. Check logs.")
        return 2

    verdict = getattr(run.verdict, "value", str(run.verdict))
    print(f"\nResult: {verdict.upper()} (status: {run.status})")

    if verdict.upper() == "PREVENTED":
        print("  ✅ Attack blocked at enforcement layer")
    elif verdict.upper() == "DETECTED":
        print("  🟡 Attack detected, not blocked")
    else:
        print("  🔴 Attack missed. Review detections and controls")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())