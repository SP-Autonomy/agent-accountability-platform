"""
AIAAP Adversarial Scenario Registry

This module provides:
- @register decorator for scenario classes
- get_scenario_class() which ensures all scenarios are imported so decorators run
"""

from __future__ import annotations

from typing import Dict, Optional, Type

from labs.scenarios.base import BaseScenario

_REGISTRY: Dict[str, Type[BaseScenario]] = {}


def register(cls: Type[BaseScenario]) -> Type[BaseScenario]:
    """
    Decorator to register a scenario class by its scenario_id.

    Scenario classes MUST define:
      - scenario_id: str
    """
    scenario_id = getattr(cls, "scenario_id", None)
    if not scenario_id or not isinstance(scenario_id, str):
        raise ValueError(f"{cls.__name__} must define scenario_id: str")

    _REGISTRY[scenario_id] = cls
    return cls


def get_scenario_class(scenario_id: str) -> Optional[Type[BaseScenario]]:
    """
    Returns a registered scenario class by ID.

    Important:
    We import the scenario modules to trigger @register decorators.
    Keep the import list updated when adding new scenario modules.
    """
    # Import modules to trigger @register decorators.
    # Do NOT import BaseScenario classes here directly from files in other ways.
    # This import list is the canonical inventory.
    from labs.scenarios.scenarios import (  # noqa: F401
        ssrf_metadata,
        rbac_escalation,
        stolen_token,
        shadow_route,
        overbroad_permissions,
        confused_deputy,
        gradual_privilege_creep,
        intent_mismatch_exfil,
        rag_data_exfil,
        multi_agent_hijack,
        jit_grant_abuse,
        credential_harvesting,
        lateral_movement,
        supply_chain_tool,
    )

    return _REGISTRY.get(scenario_id)


def list_registered() -> list[str]:
    """Returns scenario IDs currently registered (after imports happen)."""
    # Trigger import side effects
    _ = get_scenario_class("__nonexistent__")
    return sorted(_REGISTRY.keys())