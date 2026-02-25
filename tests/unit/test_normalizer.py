"""
Unit tests for the ingest normalizer.
Uses SQLite in-memory database - no docker required.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from saas.services.shared.database import Base
from saas.services.shared.models import NormalizedEvent, ToolUsage, EventSource, Severity


def make_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


# ── OTel span normalizer ───────────────────────────────────────────────────────

def test_normalize_otel_span_basic():
    """Tool call span creates NormalizedEvent + ToolUsage."""
    from saas.services.ingest.normalizer import _normalize_otel_span
    db = make_db()

    span = {
        "traceId": "abc123",
        "spanId":  "def456",
        "name":    "tool_call_executed",
        "attributes": {
            "aiaap.tool.name":              "fetch_url",
            "aiaap.tool.destination_host":  "example.com",
            "aiaap.agent.id":               "agent-01",
            "aiaap.k8s.namespace":          "ai-app",
        },
    }

    ev = _normalize_otel_span(span, "test-tenant", raw_event_id=1, db=db)

    assert ev.event_type == "tool_call_executed"
    assert ev.tool_name  == "fetch_url"
    assert ev.dest       == "example.com"
    assert ev.source     == EventSource.otel
    assert ev.severity   == Severity.info  # not metadata IP

    # Should also create a ToolUsage record
    usages = db.query(ToolUsage).all()
    assert len(usages) == 1
    assert usages[0].tool_name == "fetch_url"


def test_normalize_otel_span_metadata_dest():
    """Span to metadata IP gets severity=HIGH."""
    from saas.services.ingest.normalizer import _normalize_otel_span
    db = make_db()

    span = {
        "traceId": "aaa",
        "spanId":  "bbb",
        "name":    "tool_call_executed",
        "attributes": {
            "aiaap.tool.name":             "fetch_url",
            "aiaap.tool.destination_host": "169.254.169.254",
            "aiaap.agent.id":              "evil-agent",
        },
    }

    ev = _normalize_otel_span(span, "default", 1, db)
    assert ev.severity == Severity.high
    assert ev.dest == "169.254.169.254"


# ── eBPF event normalizer ──────────────────────────────────────────────────────

def test_normalize_ebpf_event_basic():
    """Normal eBPF network event - severity info."""
    from saas.services.ingest.normalizer import normalize_ebpf_event
    db = make_db()

    payload = {
        "type":             "process_connect",
        "namespace":        "ai-app",
        "pod_name":         "orchestrator-abc",
        "destination_ip":   "10.0.0.5",
        "destination_port": 443,
        "action":           "observed",
    }

    ev = normalize_ebpf_event(payload, "default", 1, db)
    assert ev.source == EventSource.ebpf
    assert ev.severity == Severity.info
    assert "10.0.0.5" in ev.dest


def test_normalize_ebpf_event_metadata_ip():
    """eBPF event to metadata IP - severity HIGH."""
    from saas.services.ingest.normalizer import normalize_ebpf_event
    db = make_db()

    payload = {
        "type":             "process_connect",
        "namespace":        "ai-app",
        "pod_name":         "orchestrator-abc",
        "destination_ip":   "169.254.169.254",
        "destination_port": 80,
        "action":           "blocked",
    }

    ev = normalize_ebpf_event(payload, "default", 1, db)
    assert ev.severity == Severity.high
    assert ev.payload["action"] == "blocked"


# ── K8s audit normalizer ───────────────────────────────────────────────────────

def test_normalize_audit_event_secrets_list():
    """Audit event for secrets list - severity MEDIUM."""
    from saas.services.ingest.normalizer import normalize_audit_event
    db = make_db()

    payload = {
        "verb":           "list",
        "objectRef":      {"resource": "secrets", "namespace": "default"},
        "user":           {"username": "system:serviceaccount:ai-app:orchestrator"},
        "responseStatus": {"code": 200},
    }

    ev = normalize_audit_event(payload, "default", 1, db)
    assert ev.source == EventSource.audit
    assert ev.severity == Severity.medium
    assert "audit_list_secrets" in ev.event_type


def test_normalize_audit_event_rolebinding_create():
    """Audit event for clusterrolebinding create - severity HIGH."""
    from saas.services.ingest.normalizer import normalize_audit_event
    db = make_db()

    payload = {
        "verb":           "create",
        "objectRef":      {"resource": "clusterrolebindings", "namespace": ""},
        "user":           {"username": "admin"},
        "responseStatus": {"code": 201},
    }

    ev = normalize_audit_event(payload, "default", 1, db)
    assert ev.severity == Severity.high
