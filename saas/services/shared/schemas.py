"""
Pydantic request/response schemas for all AIAAP services.
All API responses use these schemas for type safety and documentation.
"""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field

from pydantic import ConfigDict
from saas.services.shared.models import (
    EventSource, Severity, FindingStatus, ScenarioStatus,
    DecisionOutcome, ApprovalStatus, ConnectorType,
)


# ── AgentPrincipal ────────────────────────────────────────────────────────────

class AgentPrincipalCreate(BaseModel):
    name: str
    namespace: str = "default"
    service_account: str = "default"
    labels: dict[str, str] = {}
    tenant_id: str = "default"


class AgentPrincipalOut(BaseModel):
    id: int
    name: str
    namespace: str
    service_account: str
    labels: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    risk_score: float
    risk_score_updated_at: Optional[datetime] = None
    tenant_id: str

    class Config:
        from_attributes = True


# ── ToolUsage ─────────────────────────────────────────────────────────────────

class ToolUsageOut(BaseModel):
    id: int
    principal_id: Optional[int]
    tool_name: str
    destination: Optional[str]
    timestamp: datetime
    attributes: dict[str, Any]
    trace_id: Optional[str]
    tenant_id: str
    signal_source: str = "operational"

    class Config:
        from_attributes = True


# ── JitGrant ──────────────────────────────────────────────────────────────────

class JitGrantCreate(BaseModel):
    principal_id: int
    scope: str = Field(..., example="secrets:read:production")
    expires_at: datetime
    reason: Optional[str] = None
    created_by: str = "admin"
    tenant_id: str = "default"


class JitGrantOut(BaseModel):
    id: int
    principal_id: int
    scope: str
    expires_at: datetime
    reason: Optional[str]
    created_by: str
    created_at: datetime
    revoked: bool
    tenant_id: str

    class Config:
        from_attributes = True


# ── RawEvent ──────────────────────────────────────────────────────────────────

class RawEventOut(BaseModel):
    id: int
    tenant_id: str
    source: EventSource
    timestamp: datetime
    payload: dict[str, Any]

    class Config:
        from_attributes = True


# ── NormalizedEvent ───────────────────────────────────────────────────────────

class NormalizedEventOut(BaseModel):
    id: int
    tenant_id: str
    event_type: str
    principal_id: Optional[int]
    tool_name: Optional[str]
    dest: Optional[str]
    severity: Severity
    payload: dict[str, Any]
    trace_id: Optional[str]
    source: EventSource
    timestamp: datetime
    raw_event_id: Optional[int]
    signal_source: str = "operational"

    class Config:
        from_attributes = True


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: int
    tenant_id: str
    title: str
    severity: Severity
    status: FindingStatus
    evidence_refs: list[int]
    scenario_id: Optional[str]
    trace_id: Optional[str] = None
    signal_source: str = "operational"
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ── ScenarioRun ───────────────────────────────────────────────────────────────

class ScenarioRunCreate(BaseModel):
    scenario_id: str
    tenant_id: str = "default"


class ScenarioRunOut(BaseModel):
    id: int
    scenario_id: str
    status: ScenarioStatus
    start_at: Optional[datetime]
    end_at: Optional[datetime]
    verdict: Optional[FindingStatus]
    expected: Optional[dict[str, Any]]
    observed_refs: list[int]
    tenant_id: str

    class Config:
        from_attributes = True


# ── JSON event ingestion (eBPF / audit) ───────────────────────────────────────

class IngestEventRequest(BaseModel):
    """
    Generic event payload for POST /api/events.
    Used by the eBPF forwarder and K8s audit collector.
    connector_type and connector_instance_id are optional - existing callers continue to work.
    """
    source: EventSource
    tenant_id: str = "default"
    payload: dict[str, Any]
    connector_type: Optional[str] = None         # string for cross-service compat; validated in ingest
    connector_instance_id: Optional[str] = None  # e.g. "otel-collector-prod" or hostname


# ── Phase 6: Enforcement + Response ───────────────────────────────────────────

class PDPEvaluateRequest(BaseModel):
    tenant_id:       str           = "default"
    principal_id:    Optional[int] = None
    agent_id:        str           = "unknown"
    tool_name:       str
    destination:     Optional[str] = None
    jit_grant_id:    Optional[int] = None
    trace_id:        Optional[str] = None
    request_purpose: Optional[str] = None
    signal_source:   str           = "operational"


class PDPEvaluateResponse(BaseModel):
    outcome:      str
    reason:       str
    rules_fired:  list[str]
    decision_id:  int
    jit_grant_id: Optional[int] = None


class EnforcementDecisionOut(BaseModel):
    id:              int
    tenant_id:       str
    principal_id:    Optional[int]
    tool_name:       Optional[str]
    destination:     Optional[str]
    outcome:         DecisionOutcome
    reason:          str
    rules_fired:     list
    jit_grant_id:    Optional[int]
    trace_id:        Optional[str]
    request_payload: Optional[dict]
    created_at:      datetime
    signal_source:   str

    class Config:
        from_attributes = True


class ApprovalRequest(BaseModel):
    tenant_id:    str           = "default"
    principal_id: int
    scope:        str
    reason:       Optional[str] = Field(None, min_length=5)
    ttl_minutes:  int           = Field(60, ge=5, le=1440)
    requested_by: str           = "agent"
    context:      Optional[dict[str, Any]] = None


class ApprovalOut(BaseModel):
    id:           int
    tenant_id:    str
    principal_id: int
    scope:        str
    reason:       Optional[str]
    ttl_minutes:  int
    requested_by: str
    status:       ApprovalStatus
    reviewed_by:  Optional[str]
    reviewed_at:  Optional[datetime]
    jit_grant_id: Optional[int]
    context:      Optional[dict]
    created_at:   datetime
    expires_at:   datetime

    class Config:
        from_attributes = True


class ApprovalReviewRequest(BaseModel):
    reviewed_by:          str
    override_ttl_minutes: Optional[int] = None


# ── Phase 7: Connectors ────────────────────────────────────────────────────────

class ConnectorInstanceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id:                   int
    tenant_id:            str
    connector_type:       str
    instance_id:          str
    label:                Optional[str]   = None
    version:              Optional[str]   = None
    first_seen:           datetime
    last_seen:            datetime
    events_1h:            int
    metadata_json:        Optional[dict]  = None
