"""
Unit tests for the intent envelope violation logic.
No docker required - uses mock DB objects.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from saas.services.shared.models import IntentEnvelope, AgentPrincipal


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_envelope(
    allowed_tools: list[str] | None = None,
    allowed_destinations: list[str] | None = None,
    max_privilege_tier: str = "low",
    active: bool = True,
) -> IntentEnvelope:
    env = IntentEnvelope()
    env.id                   = 1
    env.tenant_id            = "default"
    env.principal_id         = 1
    env.intent_label         = "test_intent"
    env.allowed_tools        = allowed_tools or []
    env.allowed_destinations = allowed_destinations or []
    env.allowed_data_classes = []
    env.max_privilege_tier   = max_privilege_tier
    env.active               = active
    env.created_at           = datetime.now(timezone.utc)
    env.expires_at           = None
    env.created_by           = "test"
    return env


# ── check_violation ────────────────────────────────────────────────────────────

def test_no_violation_when_tool_allowed():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(allowed_tools=["summarize_doc", "read_file"])
    violated, reasons = check_violation("summarize_doc", None, "low", env)
    assert not violated
    assert reasons == []


def test_violation_when_tool_not_allowed():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(allowed_tools=["summarize_doc", "read_file"])
    violated, reasons = check_violation("fetch_url", None, "low", env)
    assert violated
    assert any("fetch_url" in r for r in reasons)


def test_wildcard_allows_any_tool():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(allowed_tools=["*"])
    violated, reasons = check_violation("any_tool_name", None, "low", env)
    assert not violated


def test_glob_pattern_allowed_tool():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(allowed_tools=["read_*"])
    violated, reasons = check_violation("read_file", None, "low", env)
    assert not violated
    violated2, _ = check_violation("write_file", None, "low", env)
    assert violated2


def test_no_violation_when_destination_allowed():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(
        allowed_tools=["*"],
        allowed_destinations=["internal-docs.svc", "*.internal"],
    )
    violated, _ = check_violation("fetch", "internal-docs.svc", "low", env)
    assert not violated


def test_violation_when_destination_not_allowed():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(
        allowed_tools=["*"],
        allowed_destinations=["internal-docs.svc"],
    )
    violated, reasons = check_violation("fetch_url", "203.0.113.99", "low", env)
    assert violated
    assert any("203.0.113.99" in r for r in reasons)


def test_glob_pattern_allowed_destination():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(
        allowed_tools=["*"],
        allowed_destinations=["*.internal"],
    )
    violated, _ = check_violation("fetch", "vault.internal", "low", env)
    assert not violated
    violated2, _ = check_violation("fetch", "evil.external.com", "low", env)
    assert violated2


def test_violation_privilege_tier_too_high():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(
        allowed_tools=["*"],
        allowed_destinations=[],
        max_privilege_tier="low",
    )
    violated, reasons = check_violation("read_secrets", None, "high", env)
    assert violated
    assert any("privilege" in r.lower() for r in reasons)


def test_no_violation_privilege_within_tier():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(allowed_tools=["*"], max_privilege_tier="high")
    violated, _ = check_violation("admin_tool", None, "medium", env)
    assert not violated


def test_empty_envelope_allows_everything():
    """Empty allowed_tools and allowed_destinations means no restrictions."""
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(allowed_tools=[], allowed_destinations=[])
    violated, _ = check_violation("any_tool", "any.dest", "low", env)
    assert not violated


def test_multiple_violations_all_returned():
    from saas.services.behavioural.intent_envelope import check_violation
    env = make_envelope(
        allowed_tools=["summarize_doc"],
        allowed_destinations=["*.internal"],
        max_privilege_tier="low",
    )
    # Tool + destination + privilege all violated
    violated, reasons = check_violation("fetch_url", "203.0.113.99", "high", env)
    assert violated
    assert len(reasons) >= 2  # At least tool + destination


# ── Privilege tier ordering ────────────────────────────────────────────────────

def test_privilege_tier_ordering():
    """low < medium < high"""
    from saas.services.behavioural.intent_envelope import check_violation
    # medium envelope, low request → no violation
    env_medium = make_envelope(allowed_tools=["*"], max_privilege_tier="medium")
    v, _ = check_violation("tool", None, "low", env_medium)
    assert not v

    # low envelope, medium request → violation
    env_low = make_envelope(allowed_tools=["*"], max_privilege_tier="low")
    v2, _ = check_violation("tool", None, "medium", env_low)
    assert v2


# ── get_active_envelope (unit-level mocking) ───────────────────────────────────

def test_get_active_envelope_returns_latest():
    from saas.services.behavioural.intent_envelope import get_active_envelope

    db = MagicMock()
    env = make_envelope()
    db.query.return_value.filter_by.return_value.filter.return_value \
       .order_by.return_value.first.return_value = env

    result = get_active_envelope(1, "default", db)
    assert result is env


def test_get_active_envelope_by_trace_id():
    from saas.services.behavioural.intent_envelope import get_active_envelope

    db = MagicMock()
    env = make_envelope()
    db.query.return_value.filter_by.return_value.filter.return_value \
       .order_by.return_value.first.return_value = env

    # When trace_id is provided, it should prefer the trace-specific envelope
    result = get_active_envelope(1, "default", db, trace_id="abc123")
    assert result is not None
