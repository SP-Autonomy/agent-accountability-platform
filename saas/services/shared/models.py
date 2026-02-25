"""
AIAAP SQLAlchemy ORM models - all data models in one file.
Uses SQLAlchemy 2.0 Mapped + mapped_column for full type-checker support.

Schema matches the spec in CLAUDE.md exactly:
  AgentPrincipal, ToolUsage, JitGrant, RawEvent,
  NormalizedEvent, Finding, ScenarioRun, TenantApiKey,
  BehavioralBaseline, AuditLog, RuntimeDetection,
  IntentEnvelope, DriftSnapshot, BlastRadiusSnapshot,
  EnforcementDecision, Approval,
  ConnectorInstance

Signal integrity invariant:
  signal_source = "lab"         → events/findings from adversarial lab scenarios (scenario-* agents)
  signal_source = "operational" → events/findings from real workloads
  Operational metrics (risk_score, drift, blast) are computed from operational signals only.
  Lab mode toggle changes visibility; it does NOT change how scores are computed.
"""

import enum
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    Boolean, DateTime, Enum as SAEnum, Float, ForeignKey,
    Index, Integer, JSON, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.services.shared.database import Base


# ── Enumerations ──────────────────────────────────────────────────────────────

class EventSource(str, enum.Enum):
    otel  = "otel"
    ebpf  = "ebpf"
    audit = "audit"
    cloud = "cloud"


class Severity(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"


class FindingStatus(str, enum.Enum):
    prevented = "prevented"
    detected  = "detected"
    missed    = "missed"


class ScenarioStatus(str, enum.Enum):
    pending  = "pending"
    running  = "running"
    complete = "complete"
    failed   = "failed"


class SignalSource(str, enum.Enum):
    operational = "operational"
    lab         = "lab"


class ConnectorType(str, enum.Enum):
    k8s_otel   = "k8s_otel"    # Helm aiaap-otel-collector
    k8s_audit  = "k8s_audit"   # Helm aiaap-k8s-audit
    ebpf       = "ebpf"        # Helm aiaap-ebpf-sensor
    cloudtrail = "cloudtrail"  # AWS Lambda/container forwarder
    sdk        = "sdk"         # Python SDK (in-process OTel)
    cli        = "cli"         # CLI / manual test submission


# ── Agent Identity ─────────────────────────────────────────────────────────────

class AgentPrincipal(Base):
    """
    Represents an observed agent workload identity.
    Populated by the ingest service when OTel spans arrive with aiaap.agent.id.
    Risk score updated by the identity service's posture engine.
    """
    __tablename__ = "agent_principals"

    id:                   Mapped[int]                  = mapped_column(Integer, primary_key=True, index=True)
    name:                 Mapped[str]                  = mapped_column(String(255), nullable=False, index=True)
    namespace:            Mapped[str]                  = mapped_column(String(255), nullable=False, default="default")
    service_account:      Mapped[str]                  = mapped_column(String(255), nullable=False, default="default")
    labels:               Mapped[dict[str, Any]]       = mapped_column(JSON, default=dict)
    first_seen:           Mapped[datetime]             = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen:            Mapped[Optional[datetime]]   = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=True)
    risk_score:           Mapped[float]                = mapped_column(Float, default=0.0)
    risk_score_updated_at: Mapped[Optional[datetime]]  = mapped_column(DateTime, nullable=True)
    tenant_id:            Mapped[str]                  = mapped_column(String(255), nullable=False, default="default", index=True)

    tool_usages: Mapped[List["ToolUsage"]] = relationship("ToolUsage", back_populates="principal", cascade="all, delete-orphan")
    jit_grants:  Mapped[List["JitGrant"]]  = relationship("JitGrant",  back_populates="principal", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_principal_tenant_name", "tenant_id", "name"),
    )


# ── Tool Access ───────────────────────────────────────────────────────────────

class ToolUsage(Base):
    """
    One record per tool_call_executed span received from OTel.
    Links back to AgentPrincipal via principal_id (resolved by ingest normalizer).
    """
    __tablename__ = "tool_usages"

    id:            Mapped[int]             = mapped_column(Integer, primary_key=True, index=True)
    principal_id:  Mapped[Optional[int]]   = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=True)
    tool_name:     Mapped[str]             = mapped_column(String(255), nullable=False, index=True)
    destination:   Mapped[Optional[str]]   = mapped_column(String(512), nullable=True)
    timestamp:     Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    attributes:    Mapped[dict[str, Any]]  = mapped_column(JSON, default=dict)
    trace_id:      Mapped[Optional[str]]   = mapped_column(String(64), nullable=True, index=True)
    span_id:       Mapped[Optional[str]]   = mapped_column(String(64), nullable=True)
    tenant_id:     Mapped[str]             = mapped_column(String(255), nullable=False, default="default", index=True)
    signal_source: Mapped[str]             = mapped_column(String(32), nullable=False, default="operational", server_default="operational")

    principal: Mapped[Optional["AgentPrincipal"]] = relationship("AgentPrincipal", back_populates="tool_usages")


# ── JIT Grants ────────────────────────────────────────────────────────────────

class JitGrant(Base):
    """
    Time-bound, scope-bound grant for a specific agent principal.
    Created by the identity service on request. Audited on every privileged tool call.
    """
    __tablename__ = "jit_grants"

    id:           Mapped[int]            = mapped_column(Integer, primary_key=True, index=True)
    principal_id: Mapped[int]            = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=False)
    scope:        Mapped[str]            = mapped_column(String(512), nullable=False)
    expires_at:   Mapped[datetime]       = mapped_column(DateTime, nullable=False)
    reason:       Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    created_by:   Mapped[str]            = mapped_column(String(255), nullable=False)
    created_at:   Mapped[datetime]       = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked:      Mapped[bool]           = mapped_column(Boolean, default=False)
    tenant_id:    Mapped[str]            = mapped_column(String(255), nullable=False, default="default", index=True)

    principal: Mapped["AgentPrincipal"] = relationship("AgentPrincipal", back_populates="jit_grants")


# ── Raw Events ────────────────────────────────────────────────────────────────

class RawEvent(Base):
    """
    Stores every incoming event payload before normalization.
    Provides an immutable audit trail and allows re-normalization if rules change.
    """
    __tablename__ = "raw_events"

    id:                   Mapped[int]                     = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:            Mapped[str]                     = mapped_column(String(255), nullable=False, index=True)
    source:               Mapped[EventSource]             = mapped_column(SAEnum(EventSource), nullable=False)
    timestamp:            Mapped[datetime]                = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    payload:              Mapped[Any]                     = mapped_column(JSON, nullable=False)
    connector_type:       Mapped[Optional[ConnectorType]] = mapped_column(SAEnum(ConnectorType), nullable=True)
    connector_instance_id: Mapped[Optional[str]]          = mapped_column(String(255), nullable=True)


# ── Normalized Events ─────────────────────────────────────────────────────────

class NormalizedEvent(Base):
    """
    Common event schema produced by the ingest normalizer from OTel/eBPF/audit.
    The correlation engine queries this table to apply detection rules.
    """
    __tablename__ = "normalized_events"

    id:            Mapped[int]               = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:     Mapped[str]               = mapped_column(String(255), nullable=False, index=True)
    event_type:    Mapped[str]               = mapped_column(String(255), nullable=False, index=True)
    principal_id:  Mapped[Optional[int]]     = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=True)
    tool_name:     Mapped[Optional[str]]     = mapped_column(String(255), nullable=True)
    dest:          Mapped[Optional[str]]     = mapped_column(String(512), nullable=True)
    severity:      Mapped[Severity]          = mapped_column(SAEnum(Severity), default=Severity.info)
    payload:       Mapped[Any]               = mapped_column(JSON, nullable=False)
    trace_id:      Mapped[Optional[str]]     = mapped_column(String(64), nullable=True, index=True)
    source:        Mapped[EventSource]       = mapped_column(SAEnum(EventSource), nullable=False)
    timestamp:     Mapped[datetime]          = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    raw_event_id:         Mapped[Optional[int]]               = mapped_column(Integer, ForeignKey("raw_events.id"), nullable=True)
    signal_source:        Mapped[str]                         = mapped_column(String(32), nullable=False, default="operational", server_default="operational")
    connector_type:       Mapped[Optional[ConnectorType]]     = mapped_column(SAEnum(ConnectorType), nullable=True)
    connector_instance_id: Mapped[Optional[str]]              = mapped_column(String(255), nullable=True, index=True)

    __table_args__ = (
        Index("ix_norm_event_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_norm_event_trace",     "trace_id"),
    )


# ── Findings ──────────────────────────────────────────────────────────────────

class Finding(Base):
    """
    A security finding produced by the correlation engine.
    status: prevented | detected | missed (per CLAUDE.md spec).
    evidence_refs: list of NormalizedEvent IDs that triggered this finding.
    """
    __tablename__ = "findings"

    id:            Mapped[int]                     = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:     Mapped[str]                     = mapped_column(String(255), nullable=False, index=True)
    title:         Mapped[str]                     = mapped_column(String(512), nullable=False)
    severity:      Mapped[Severity]                = mapped_column(SAEnum(Severity), nullable=False)
    status:        Mapped[FindingStatus]           = mapped_column(SAEnum(FindingStatus), nullable=False)
    evidence_refs: Mapped[list[Any]]               = mapped_column(JSON, default=list)
    scenario_id:   Mapped[Optional[str]]           = mapped_column(String(255), nullable=True, index=True)
    trace_id:      Mapped[Optional[str]]           = mapped_column(String(64),  nullable=True, index=True)
    payload:       Mapped[Optional[Any]]           = mapped_column(JSON, nullable=True)
    signal_source: Mapped[str]                     = mapped_column(String(32), nullable=False, default="operational", server_default="operational")
    created_at:    Mapped[datetime]                = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at:    Mapped[datetime]                = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


# ── Scenario Runs ─────────────────────────────────────────────────────────────

class ScenarioRun(Base):
    """
    Tracks a single execution of an adversarial scenario.
    verdict is set when the scenario completes and is compared to expected.
    """
    __tablename__ = "scenario_runs"

    id:            Mapped[int]                       = mapped_column(Integer, primary_key=True, index=True)
    scenario_id:   Mapped[str]                       = mapped_column(String(255), nullable=False, index=True)
    status:        Mapped[ScenarioStatus]            = mapped_column(SAEnum(ScenarioStatus), default=ScenarioStatus.pending)
    start_at:      Mapped[Optional[datetime]]        = mapped_column(DateTime, nullable=True)
    end_at:        Mapped[Optional[datetime]]        = mapped_column(DateTime, nullable=True)
    verdict:       Mapped[Optional[FindingStatus]]   = mapped_column(SAEnum(FindingStatus), nullable=True)
    expected:      Mapped[Optional[dict[str, Any]]]  = mapped_column(JSON, nullable=True)
    observed_refs: Mapped[list[Any]]                 = mapped_column(JSON, default=list)
    tenant_id:     Mapped[str]                       = mapped_column(String(255), nullable=False, default="default", index=True)


# ── Multi-Tenancy ──────────────────────────────────────────────────────────────

class TenantApiKey(Base):
    """
    Stores hashed API keys for tenant authentication.
    Plain-text keys are NEVER stored; only bcrypt hashes.
    The tenant_id is derived from this record - callers cannot spoof it.
    """
    __tablename__ = "tenant_api_keys"

    id:          Mapped[int]            = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:   Mapped[str]            = mapped_column(String(255), nullable=False, index=True)
    key_hash:    Mapped[str]            = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]]  = mapped_column(String(512), nullable=True)
    created_at:  Mapped[datetime]       = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    active:      Mapped[bool]           = mapped_column(Boolean, default=True)


# ── Behavioral Baselines ───────────────────────────────────────────────────────

class BehavioralBaseline(Base):
    """
    Stores a rolling statistical baseline for each agent principal.
    Updated periodically by the behavioral analysis background loop.
    Used by anomaly_scoring to detect deviations from normal behaviour.

    Metrics are computed from hourly buckets over a 7-day window.
    Graph edges (known_tools, known_destinations, known_namespaces) capture
    the historical identity graph for drift detection.
    """
    __tablename__ = "behavioral_baselines"

    id:           Mapped[int]      = mapped_column(Integer, primary_key=True, index=True)
    principal_id: Mapped[int]      = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=False)
    tenant_id:    Mapped[str]      = mapped_column(String(255), nullable=False, index=True)
    computed_at:  Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Frequency stats (per-hour rolling mean/std, last 7 days) ──────────────
    mean_calls_per_hour:   Mapped[float] = mapped_column(Float, default=0.0)
    std_calls_per_hour:    Mapped[float] = mapped_column(Float, default=1.0)

    # ── Resource diversity stats ───────────────────────────────────────────────
    mean_distinct_dest:    Mapped[float] = mapped_column(Float, default=0.0)
    std_distinct_dest:     Mapped[float] = mapped_column(Float, default=1.0)
    mean_entropy:          Mapped[float] = mapped_column(Float, default=0.0)
    std_entropy:           Mapped[float] = mapped_column(Float, default=0.5)
    mean_privileged_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    std_privileged_ratio:  Mapped[float] = mapped_column(Float, default=0.1)
    mean_new_tool_freq:    Mapped[float] = mapped_column(Float, default=0.0)
    std_new_tool_freq:     Mapped[float] = mapped_column(Float, default=0.1)

    # ── Identity graph edges (JSON lists) ─────────────────────────────────────
    known_tools:        Mapped[list[Any]] = mapped_column(JSON, default=list)
    known_destinations: Mapped[list[Any]] = mapped_column(JSON, default=list)
    known_namespaces:   Mapped[list[Any]] = mapped_column(JSON, default=list)
    baseline_degree:    Mapped[int]       = mapped_column(Integer, default=0)

    # ── Meta ──────────────────────────────────────────────────────────────────
    observations:  Mapped[int]   = mapped_column(Integer, default=0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)

    __table_args__ = (
        Index("ix_behavioral_baseline_principal_tenant", "principal_id", "tenant_id"),
    )


# ── Audit Log ──────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Immutable audit trail for all mutating operations (JIT create/revoke, principal delete, etc.).
    Actor is the human user or service that triggered the action.
    Resource is a short "type:id" reference (e.g. "jit_grant:42", "principal:7").
    """
    __tablename__ = "audit_logs"

    id:        Mapped[int]             = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[str]             = mapped_column(String(255), nullable=False, index=True)
    actor:     Mapped[str]             = mapped_column(String(255), nullable=False)
    action:    Mapped[str]             = mapped_column(String(255), nullable=False)
    resource:  Mapped[Optional[str]]   = mapped_column(String(255), nullable=True)
    detail:    Mapped[dict[str, Any]]  = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        Index("ix_audit_log_tenant_ts", "tenant_id", "timestamp"),
    )


# ── Runtime Detections ─────────────────────────────────────────────────────────

class RuntimeDetection(Base):
    """
    Records a single injection or PII detection from the runtime service.
    Raw content is NEVER stored - only a sha256 hash and the detection signals.
    Created by POST /api/runtime/analyze in the runtime service.
    Consumed by rule_runtime in the correlator to create Findings.
    """
    __tablename__ = "runtime_detections"

    id:            Mapped[int]             = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:     Mapped[str]             = mapped_column(String(255), nullable=False, index=True)
    trace_id:      Mapped[Optional[str]]   = mapped_column(String(64), nullable=True, index=True)
    agent_id:      Mapped[Optional[str]]   = mapped_column(String(255), nullable=True)
    detector_type: Mapped[str]             = mapped_column(String(64), nullable=False)
    severity:      Mapped[Severity]        = mapped_column(SAEnum(Severity), nullable=False)
    confidence:    Mapped[float]           = mapped_column(Float, default=0.0)
    signal:        Mapped[dict[str, Any]]  = mapped_column(JSON, default=dict)
    content_hash:  Mapped[Optional[str]]   = mapped_column(String(64), nullable=True)
    direction:     Mapped[Optional[str]]   = mapped_column(String(16), nullable=True)
    timestamp:     Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        Index("ix_runtime_tenant_ts", "tenant_id", "timestamp"),
    )


# ── Intent Integrity - Phase 3 ────────────────────────────────────────────────

class IntentEnvelope(Base):
    """
    Defines the declared behavioural intent for an agent principal session/task.
    Violations (tool/destination/privilege outside envelope) are detected by the
    behavioural intent engine and promote to intent_boundary_violation Findings.

    created_by values:
      "sdk"  - extracted from OTel span attributes (aiaap.intent.*)
      "ui"   - manually created via dashboard
      "auto" - auto-generated from baseline when no explicit envelope exists
    """
    __tablename__ = "intent_envelopes"

    id:                   Mapped[int]               = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:            Mapped[str]               = mapped_column(String(255), nullable=False, index=True)
    principal_id:         Mapped[int]               = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=False)
    trace_id:             Mapped[Optional[str]]     = mapped_column(String(64), nullable=True, index=True)
    session_id:           Mapped[Optional[str]]     = mapped_column(String(64), nullable=True)
    intent_label:         Mapped[str]               = mapped_column(String(512), nullable=False, default="unlabeled")
    allowed_tools:        Mapped[list[Any]]         = mapped_column(JSON, default=list)
    allowed_destinations: Mapped[list[Any]]         = mapped_column(JSON, default=list)
    allowed_data_classes: Mapped[list[Any]]         = mapped_column(JSON, default=list)
    max_privilege_tier:   Mapped[str]               = mapped_column(String(16), default="low")
    created_at:           Mapped[datetime]          = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    expires_at:           Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by:           Mapped[str]               = mapped_column(String(32), default="auto")
    active:               Mapped[bool]              = mapped_column(Boolean, default=True)

    principal: Mapped["AgentPrincipal"] = relationship("AgentPrincipal")

    __table_args__ = (
        Index("ix_intent_envelope_principal_tenant", "principal_id", "tenant_id"),
    )


class DriftSnapshot(Base):
    """
    A point-in-time snapshot of drift metrics for one agent principal.
    Written every INTENT_INTERVAL seconds by the intent integrity loop.
    Used to drive the Drift Timeline dashboard page.
    """
    __tablename__ = "drift_snapshots"

    id:           Mapped[int]             = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:    Mapped[str]             = mapped_column(String(255), nullable=False, index=True)
    principal_id: Mapped[int]             = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=False)
    window_start: Mapped[datetime]        = mapped_column(DateTime, nullable=False)
    window_end:   Mapped[datetime]        = mapped_column(DateTime, nullable=False)
    metrics:      Mapped[dict[str, Any]]  = mapped_column(JSON, default=dict)
    drift_score:  Mapped[float]           = mapped_column(Float, default=0.0)
    created_at:   Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        Index("ix_drift_snapshot_principal_ts", "principal_id", "created_at"),
    )


class BlastRadiusSnapshot(Base):
    """
    A point-in-time snapshot of blast-radius metrics for one agent principal.
    Tracks reach expansion vs the historical baseline stored in BehavioralBaseline.
    """
    __tablename__ = "blast_radius_snapshots"

    id:                        Mapped[int]      = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:                 Mapped[str]      = mapped_column(String(255), nullable=False, index=True)
    principal_id:              Mapped[int]      = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=False)
    window_start:              Mapped[datetime] = mapped_column(DateTime, nullable=False)
    window_end:                Mapped[datetime] = mapped_column(DateTime, nullable=False)
    unique_destinations_count: Mapped[int]      = mapped_column(Integer, default=0)
    unique_resources_count:    Mapped[int]      = mapped_column(Integer, default=0)
    privileged_edges_count:    Mapped[int]      = mapped_column(Integer, default=0)
    new_edges_count:           Mapped[int]      = mapped_column(Integer, default=0)
    blast_radius_score:        Mapped[float]    = mapped_column(Float, default=0.0)
    created_at:                Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        Index("ix_blast_radius_principal_ts", "principal_id", "created_at"),
    )


# ── Phase 6: Enforcement + Response ───────────────────────────────────────────

class DecisionOutcome(str, enum.Enum):
    allow      = "allow"
    block      = "block"
    step_up    = "step_up"
    redact     = "redact"
    sandbox    = "sandbox"
    rate_limit = "rate_limit"


class ApprovalStatus(str, enum.Enum):
    pending  = "pending"
    approved = "approved"
    denied   = "denied"
    expired  = "expired"


class EnforcementDecision(Base):
    """
    Persists every PDP evaluation call for audit and dashboard display.
    Created by routes_pdp.py on each POST /api/pdp/evaluate.
    """
    __tablename__ = "enforcement_decisions"

    id:              Mapped[int]             = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:       Mapped[str]             = mapped_column(String(255), nullable=False, index=True)
    principal_id:    Mapped[Optional[int]]   = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=True)
    tool_name:       Mapped[Optional[str]]   = mapped_column(String(255), nullable=True)
    destination:     Mapped[Optional[str]]   = mapped_column(String(512), nullable=True)
    outcome:         Mapped[DecisionOutcome] = mapped_column(SAEnum(DecisionOutcome), nullable=False)
    reason:          Mapped[str]             = mapped_column(String(512), nullable=False)
    rules_fired:     Mapped[list]            = mapped_column(JSON, default=list)
    jit_grant_id:    Mapped[Optional[int]]   = mapped_column(Integer, ForeignKey("jit_grants.id"), nullable=True)
    trace_id:        Mapped[Optional[str]]   = mapped_column(String(64), nullable=True, index=True)
    request_payload: Mapped[Optional[dict]]  = mapped_column(JSON, nullable=True)
    created_at:      Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    signal_source:   Mapped[str]             = mapped_column(String(32), default="operational")

    __table_args__ = (
        Index("ix_enforcement_decisions_tenant_ts", "tenant_id", "created_at"),
    )


class Approval(Base):
    """
    Approval request for a JIT grant.
    Created by POST /api/approvals/request or POST /api/jit/request.
    On approval, a JitGrant is auto-created and jit_grant_id is set.
    """
    __tablename__ = "approvals"

    id:           Mapped[int]            = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:    Mapped[str]            = mapped_column(String(255), nullable=False, index=True)
    principal_id: Mapped[int]            = mapped_column(Integer, ForeignKey("agent_principals.id"), nullable=False)
    scope:        Mapped[str]            = mapped_column(String(512), nullable=False)
    reason:       Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    ttl_minutes:  Mapped[int]            = mapped_column(Integer, default=60)
    requested_by: Mapped[str]            = mapped_column(String(255), default="agent")
    status:       Mapped[ApprovalStatus] = mapped_column(SAEnum(ApprovalStatus), default=ApprovalStatus.pending)
    reviewed_by:  Mapped[Optional[str]]  = mapped_column(String(255), nullable=True)
    reviewed_at:  Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    jit_grant_id: Mapped[Optional[int]]  = mapped_column(Integer, ForeignKey("jit_grants.id"), nullable=True)
    context:      Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at:   Mapped[datetime]       = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    expires_at:   Mapped[datetime]       = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_approvals_tenant_status", "tenant_id", "status"),
    )


# ── Connector Instances ────────────────────────────────────────────────────────

class ConnectorInstance(Base):
    """
    Tracks each telemetry connector that has reported to the ingest service.
    Auto-created/updated on every event received from a connector.
    Powers the Connectors dashboard page and coverage gap detection.
    """
    __tablename__ = "connector_instances"

    id:                   Mapped[int]             = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:            Mapped[str]             = mapped_column(String(255), nullable=False, index=True)
    connector_type:       Mapped[ConnectorType]   = mapped_column(SAEnum(ConnectorType), nullable=False)
    instance_id:          Mapped[str]             = mapped_column(String(255), nullable=False)
    label:                Mapped[Optional[str]]   = mapped_column(String(255), nullable=True)
    version:              Mapped[Optional[str]]   = mapped_column(String(64), nullable=True)
    first_seen:           Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen:            Mapped[datetime]        = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    events_1h:            Mapped[int]             = mapped_column(Integer, default=0)
    metadata_json:        Mapped[Optional[dict]]  = mapped_column(JSON, default=dict)

    __table_args__ = (
        UniqueConstraint("tenant_id", "instance_id", name="uq_connector_tenant_instance"),
        Index("ix_connector_tenant_type", "tenant_id", "connector_type"),
    )
