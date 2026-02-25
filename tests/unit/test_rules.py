"""
Unit tests for all 6 correlation rules.
Uses in-memory NormalizedEvent objects - no docker required.
"""

import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone

from saas.services.shared.models import (
    NormalizedEvent, EventSource, Severity, FindingStatus,
)


def make_event(
    event_type: str = "tool_call_executed",
    source: EventSource = EventSource.otel,
    dest: str | None = None,
    payload: dict | None = None,
    trace_id: str | None = "trace-001",
    principal_id: int | None = None,
    tool_name: str | None = None,
    tenant_id: str = "default",
) -> NormalizedEvent:
    ev = NormalizedEvent()
    ev.id           = 1
    ev.event_type   = event_type
    ev.source       = source
    ev.dest         = dest
    ev.payload      = payload or {}
    ev.trace_id     = trace_id
    ev.principal_id = principal_id
    ev.tool_name    = tool_name
    ev.severity     = Severity.info
    ev.tenant_id    = tenant_id
    ev.timestamp    = datetime.now(timezone.utc)
    return ev


db_mock = MagicMock()


# ── Rule: ssrf_metadata ────────────────────────────────────────────────────────

def test_ssrf_rule_otel_hit_detected():
    """OTel span to metadata IP → DETECTED."""
    from saas.services.detections.rules.rule_ssrf import check

    events = [make_event(dest="169.254.169.254", source=EventSource.otel)]
    finding = check(events, db_mock)

    assert finding is not None
    assert finding.scenario_id == "ssrf_metadata"
    assert finding.status == FindingStatus.detected


def test_ssrf_rule_ebpf_blocked_prevented():
    """eBPF blocked connection to metadata IP → PREVENTED."""
    from saas.services.detections.rules.rule_ssrf import check

    events = [
        make_event(
            source=EventSource.ebpf,
            payload={"dest_ip": "169.254.169.254", "action": "blocked"},
            trace_id=None,
        )
    ]
    finding = check(events, db_mock)

    assert finding is not None
    assert finding.status == FindingStatus.prevented


def test_ssrf_rule_no_match():
    """Normal destination → no finding."""
    from saas.services.detections.rules.rule_ssrf import check

    events = [make_event(dest="api.example.com")]
    finding = check(events, db_mock)
    assert finding is None


# ── Rule: rbac_escalation ──────────────────────────────────────────────────────

def test_rbac_rule_clusterrolebinding_create():
    """Audit event for clusterrolebinding create → DETECTED finding."""
    from saas.services.detections.rules.rule_rbac import check

    events = [make_event(
        event_type="k8s_audit_create_clusterrolebindings",
        source=EventSource.audit,
        payload={"user": "admin", "resource": "clusterrolebindings", "verb": "create"},
        trace_id=None,
    )]
    finding = check(events, db_mock)

    assert finding is not None
    assert finding.scenario_id == "rbac_escalation_misconfig"
    assert finding.status == FindingStatus.detected


def test_rbac_rule_no_match():
    """Regular audit event → no finding."""
    from saas.services.detections.rules.rule_rbac import check

    events = [make_event(
        event_type="k8s_audit_get_pods",
        source=EventSource.audit,
        payload={"verb": "get", "resource": "pods"},
        trace_id=None,
    )]
    assert check(events, db_mock) is None


# ── Rule: stolen_token ─────────────────────────────────────────────────────────

def test_stolen_token_cross_namespace():
    """SA from ai-app used in ai-tools namespace → DETECTED."""
    from saas.services.detections.rules.rule_stolen_token import check

    events = [make_event(
        event_type="k8s_audit_get_secrets",
        source=EventSource.audit,
        payload={
            "user":      "system:serviceaccount:ai-app:orchestrator",
            "verb":      "get",
            "resource":  "secrets",
            "namespace": "ai-tools",  # different namespace!
        },
        trace_id=None,
    )]
    finding = check(events, db_mock)

    assert finding is not None
    assert finding.scenario_id == "stolen_token_usage"


def test_stolen_token_same_namespace():
    """SA used in its own namespace → no finding."""
    from saas.services.detections.rules.rule_stolen_token import check

    events = [make_event(
        event_type="k8s_audit_get_secrets",
        source=EventSource.audit,
        payload={
            "user":      "system:serviceaccount:ai-app:orchestrator",
            "verb":      "get",
            "resource":  "secrets",
            "namespace": "ai-app",  # same namespace - expected
        },
        trace_id=None,
    )]
    assert check(events, db_mock) is None


# ── Rule: shadow_route ────────────────────────────────────────────────────────

def test_shadow_route_non_orchestrator_blocked():
    """eBPF: non-orchestrator pod connects to port 9000 (blocked) → PREVENTED."""
    from saas.services.detections.rules.rule_shadow_route import check

    events = [make_event(
        source=EventSource.ebpf,
        payload={"dest_port": 9000, "pod_name": "rogue-pod-xyz", "action": "blocked"},
        trace_id=None,
    )]
    finding = check(events, db_mock)

    assert finding is not None
    assert finding.status == FindingStatus.prevented


def test_shadow_route_orchestrator_excluded():
    """eBPF: orchestrator pod connecting to port 9000 → no finding."""
    from saas.services.detections.rules.rule_shadow_route import check

    events = [make_event(
        source=EventSource.ebpf,
        payload={"dest_port": 9000, "pod_name": "orchestrator-abc123", "action": "observed"},
        trace_id=None,
    )]
    assert check(events, db_mock) is None


# ── Rule: overbroad ───────────────────────────────────────────────────────────

def test_overbroad_no_jit_grant(monkeypatch):
    """Privileged tool call with no JIT grant → DETECTED."""
    from saas.services.detections.rules import rule_overbroad

    # Mock: no active grants
    monkeypatch.setattr(rule_overbroad, "_has_active_jit_grant", lambda pid: False)

    import json
    events = [make_event(
        source=EventSource.otel,
        payload={"attributes": {"aiaap.risk.flags": json.dumps(["privileged_action"])}},
        principal_id=1,
        tool_name="admin_tool",
    )]
    finding = rule_overbroad.check(events, db_mock)

    assert finding is not None
    assert finding.scenario_id == "overbroad_permissions"


def test_overbroad_with_jit_grant(monkeypatch):
    """Privileged tool call WITH active JIT grant → no finding."""
    from saas.services.detections.rules import rule_overbroad

    monkeypatch.setattr(rule_overbroad, "_has_active_jit_grant", lambda pid: True)

    import json
    events = [make_event(
        source=EventSource.otel,
        payload={"attributes": {"aiaap.risk.flags": json.dumps(["privileged_action"])}},
        principal_id=1,
    )]
    assert rule_overbroad.check(events, db_mock) is None


# ── Rule: confused_deputy ─────────────────────────────────────────────────────

def test_confused_deputy_identity_mismatch():
    """Low-priv agent requesting, high-priv SA executing → DETECTED."""
    from saas.services.detections.rules.rule_confused_deputy import check

    req_span = make_event(
        event_type="tool_call_requested",
        source=EventSource.otel,
        payload={"attributes": {"aiaap.agent.id": "low-priv-agent", "aiaap.tool.name": "admin_tool"}},
        trace_id="shared-trace-001",
    )
    req_span.id = 1

    exe_span = make_event(
        event_type="tool_call_executed",
        source=EventSource.otel,
        payload={"attributes": {
            "aiaap.agent.id":            "low-priv-agent",
            "k8s.serviceaccount.name":   "high-priv-sa",
            "aiaap.k8s.service_account": "high-priv-sa",
        }},
        trace_id="shared-trace-001",
    )
    exe_span.id = 2

    finding = check([req_span, exe_span], db_mock)

    assert finding is not None
    assert finding.scenario_id == "confused_deputy"
    assert finding.status == FindingStatus.detected


def test_confused_deputy_no_mismatch():
    """Same agent ID as SA → no finding."""
    from saas.services.detections.rules.rule_confused_deputy import check

    req_span = make_event(
        event_type="tool_call_requested",
        source=EventSource.otel,
        payload={"attributes": {"aiaap.agent.id": "orchestrator"}},
        trace_id="trace-002",
    )
    req_span.id = 3

    exe_span = make_event(
        event_type="tool_call_executed",
        source=EventSource.otel,
        payload={"attributes": {
            "aiaap.agent.id":            "orchestrator",
            "k8s.serviceaccount.name":   "orchestrator",
        }},
        trace_id="trace-002",
    )
    exe_span.id = 4

    assert check([req_span, exe_span], db_mock) is None
