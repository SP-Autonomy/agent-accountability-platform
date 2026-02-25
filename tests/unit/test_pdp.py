"""
Unit tests for Phase 6 PDP rule evaluation.

Tests the pure _evaluate() logic in routes_pdp.py using mock DB sessions.
No docker required - all DB queries are mocked.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from saas.services.shared.models import DecisionOutcome, JitGrant, IntentEnvelope
from saas.services.shared.schemas import PDPEvaluateRequest
from saas.services.identity.routes_pdp import (
    _evaluate, _scope_covers_tool, _check_envelope,
    HIGH_RISK_DEST_PREFIXES, PRIVILEGED_TOOLS,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_req(**kwargs) -> PDPEvaluateRequest:
    defaults = {
        "agent_id":   "test-agent",
        "tool_name":  "search_docs",
        "tenant_id":  "default",
    }
    defaults.update(kwargs)
    return PDPEvaluateRequest(**defaults)


def make_grant(
    scope: str = "secrets:read",
    expired: bool = False,
    revoked: bool = False,
    grant_id: int = 42,
) -> JitGrant:
    g = JitGrant()
    g.id         = grant_id
    g.scope      = scope
    g.revoked    = revoked
    g.expires_at = (
        datetime.now(timezone.utc) - timedelta(hours=1) if expired
        else datetime.now(timezone.utc) + timedelta(hours=1)
    )
    return g


def make_mock_db(grant: JitGrant | None = None, usage_count: int = 0, envelope: IntentEnvelope | None = None):
    """Create a mock DB session that returns configured objects."""
    db = MagicMock()

    # JitGrant lookup: db.query(JitGrant).filter_by(id=...).first()
    grant_query = MagicMock()
    grant_query.first.return_value = grant
    db.query.return_value.filter_by.return_value = grant_query

    # ToolUsage count: db.query(ToolUsage).filter(...).count()
    usage_query = MagicMock()
    usage_query.count.return_value = usage_count
    usage_query.filter.return_value = usage_query

    # IntentEnvelope query (for _get_active_envelope)
    envelope_q = MagicMock()
    envelope_q.filter.return_value = envelope_q
    envelope_q.first.return_value = envelope
    envelope_q.order_by.return_value = envelope_q

    def _query_side_effect(model):
        if hasattr(model, '__tablename__'):
            name = model.__tablename__
            if name == "jit_grants":
                return db.query.return_value
            elif name == "intent_envelopes":
                return envelope_q
        # default: return usage_query for ToolUsage count
        mock = MagicMock()
        mock.filter.return_value = usage_query
        return mock

    db.query.side_effect = _query_side_effect
    return db


# ── _scope_covers_tool ────────────────────────────────────────────────────────

class TestScopeCoversTool:
    def test_admin_wildcard(self):
        assert _scope_covers_tool("admin", "read_secrets") is True

    def test_star_wildcard(self):
        assert _scope_covers_tool("*", "any_tool") is True

    def test_exact_match(self):
        # "secrets" scope covers tool starting with "secrets"
        assert _scope_covers_tool("secrets", "secrets_read") is True

    def test_no_match(self):
        # "logs:read" does not cover "read_secrets"
        assert _scope_covers_tool("logs:read", "write_secrets") is False

    def test_first_segment_match(self):
        # scope "secrets" → tool starts with "secret"
        assert _scope_covers_tool("secrets", "secrets_read") is True


# ── _check_envelope ────────────────────────────────────────────────────────────

class TestCheckEnvelope:
    def _make_envelope(self, tools=None, dests=None):
        e = IntentEnvelope()
        e.allowed_tools        = tools or []
        e.allowed_destinations = dests or []
        return e

    def test_empty_lists_pass(self):
        env = self._make_envelope()
        ok, violations = _check_envelope("any_tool", "any_dest", env)
        assert ok is True
        assert violations == []

    def test_tool_in_allowed(self):
        env = self._make_envelope(tools=["search_docs", "get_customer"])
        ok, _ = _check_envelope("search_docs", None, env)
        assert ok is True

    def test_tool_not_in_allowed(self):
        env = self._make_envelope(tools=["search_docs"])
        ok, violations = _check_envelope("read_secrets", None, env)
        assert ok is False
        assert any("tool" in v for v in violations)

    def test_glob_pattern_tool(self):
        env = self._make_envelope(tools=["search_*"])
        ok, _ = _check_envelope("search_docs", None, env)
        assert ok is True

    def test_destination_not_allowed(self):
        env = self._make_envelope(dests=["api.internal.example.com"])
        ok, violations = _check_envelope("fetch_url", "169.254.169.254", env)
        assert ok is False
        assert any("destination" in v for v in violations)


# ── _evaluate ─────────────────────────────────────────────────────────────────

class TestEvaluate:
    def test_allow_safe_tool(self):
        db = make_mock_db()
        req = make_req(tool_name="search_docs")
        outcome, reason, rules, jit_id = _evaluate(req, db)
        assert outcome == DecisionOutcome.allow
        assert "default_allow" in rules

    def test_block_high_risk_destination(self):
        db = make_mock_db()
        req = make_req(tool_name="fetch_url", destination="169.254.169.254")
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.block
        assert "high_risk_destination" in rules

    def test_block_metadata_internal(self):
        db = make_mock_db()
        req = make_req(tool_name="fetch_url", destination="metadata.google.internal/computeMetadata/v1/")
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.block
        assert "high_risk_destination" in rules

    def test_step_up_privileged_no_jit(self):
        db = make_mock_db()
        req = make_req(tool_name="read_secrets")  # no jit_grant_id
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.step_up
        assert "no_jit_for_privileged_tool" in rules

    def test_block_privileged_expired_jit(self):
        expired_grant = make_grant(expired=True)
        db = MagicMock()
        grant_q = MagicMock()
        grant_q.first.return_value = expired_grant
        db.query.return_value.filter_by.return_value = grant_q
        db.query.return_value.filter.return_value = MagicMock(count=MagicMock(return_value=0))

        req = make_req(tool_name="read_secrets", jit_grant_id=42)
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.block
        assert "invalid_or_expired_jit_grant" in rules

    def test_block_privileged_revoked_jit(self):
        revoked_grant = make_grant(revoked=True)
        db = MagicMock()
        grant_q = MagicMock()
        grant_q.first.return_value = revoked_grant
        db.query.return_value.filter_by.return_value = grant_q
        db.query.return_value.filter.return_value = MagicMock(count=MagicMock(return_value=0))

        req = make_req(tool_name="read_secrets", jit_grant_id=42)
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.block
        assert "invalid_or_expired_jit_grant" in rules

    def test_block_scope_mismatch(self):
        """Grant has scope=logs:read but tool=read_secrets."""
        wrong_scope_grant = make_grant(scope="logs:read")
        db = MagicMock()
        grant_q = MagicMock()
        grant_q.first.return_value = wrong_scope_grant
        db.query.return_value.filter_by.return_value = grant_q
        db.query.return_value.filter.return_value = MagicMock(count=MagicMock(return_value=0))

        req = make_req(tool_name="read_secrets", jit_grant_id=42)
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.block
        assert "jit_scope_mismatch" in rules

    def test_allow_privileged_with_valid_admin_grant(self):
        """Admin-scoped grant should allow any privileged tool."""
        admin_grant = make_grant(scope="admin")
        db = MagicMock()
        grant_q = MagicMock()
        grant_q.first.return_value = admin_grant
        db.query.return_value.filter_by.return_value = grant_q
        usage_q = MagicMock()
        usage_q.filter.return_value = usage_q
        usage_q.count.return_value = 0

        def _side(model):
            from saas.services.shared.models import JitGrant as JG, IntentEnvelope as IE
            if model is JG:
                return db.query.return_value
            mock = MagicMock()
            mock.filter.return_value = usage_q
            return mock

        db.query.side_effect = _side

        req = make_req(tool_name="read_secrets", jit_grant_id=42)
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.allow
        assert "jit_grant_valid" in rules

    def test_rate_limit(self):
        """25 calls in rate-limit window → RATE_LIMIT."""
        db = MagicMock()
        # No JIT queries needed (safe tool)
        usage_q = MagicMock()
        usage_q.filter.return_value = usage_q
        usage_q.count.return_value = 25   # > RATE_LIMIT_MAX_CALLS (20)

        envelope_q = MagicMock()
        envelope_q.filter.return_value = envelope_q
        envelope_q.first.return_value = None
        envelope_q.order_by.return_value = envelope_q

        from saas.services.shared.models import ToolUsage, IntentEnvelope as IE
        def _side(model):
            if model is IE:
                return envelope_q
            mock = MagicMock()
            mock.filter.return_value = usage_q
            return mock

        db.query.side_effect = _side

        req = make_req(tool_name="search_docs", principal_id=1)
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.rate_limit
        assert "rate_limit_exceeded" in rules

    def test_high_risk_checked_before_privileged(self):
        """High-risk dest rule fires before privileged-tool rule (first-match wins)."""
        db = make_mock_db()
        req = make_req(
            tool_name="read_secrets",
            destination="169.254.169.254",
            # No jit_grant_id - but high-risk dest should fire first
        )
        outcome, reason, rules, _ = _evaluate(req, db)
        assert outcome == DecisionOutcome.block
        assert rules[0] == "high_risk_destination"

    def test_all_high_risk_prefixes(self):
        for prefix in HIGH_RISK_DEST_PREFIXES:
            db = make_mock_db()
            req = make_req(tool_name="fetch_url", destination=f"{prefix}something")
            outcome, _, rules, _ = _evaluate(req, db)
            assert outcome == DecisionOutcome.block, f"Expected block for prefix {prefix}"

    def test_all_privileged_tools_require_jit(self):
        for tool in list(PRIVILEGED_TOOLS)[:5]:  # test a sample
            db = make_mock_db()
            req = make_req(tool_name=tool)
            outcome, _, rules, _ = _evaluate(req, db)
            assert outcome == DecisionOutcome.step_up, f"Expected step_up for tool {tool}"
