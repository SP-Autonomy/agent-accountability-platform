# Project: AIAAP (Agent Identity & Access Adversarial Playground) - Telemetry-First + SaaS Control Plane

# ⚠️ Historical Plan - Phases 1–5 Completed
This document reflects original roadmap. Current codebase may diverge.
Claude should treat earlier phases as implemented and immutable.
Only Phase 6+ defines forward work.

# Phase 6: Enforcement + Response (Detect -> Contain -> Prove)

## Phase 5: Behavioral Baselines + Risk Graph Engine

### Goal
Replace static thresholds with contextual, explainable behavioral findings driven by per-agent baselines and access graph analysis.

### Principles
- Prefer findings over raw scores.
- Every score must be explainable: baseline vs observed evidence.
- All behavior analytics must be testable via Assurance Labs scenarios.

### Implementation checklist
1) Baseline engine
- Compute per-agent baseline for tools, destinations, call rate, burstiness, privileged ratio, unique destinations, and known edges.

2) Behavioral findings
- Generate explicit findings:
  - new tool, new destination, new edge
  - distribution drift (distance metric)
  - privileged ratio spike
  - burst anomaly
  - suspicious sequences (kill chain patterns)

3) Risk graph blast radius
- Compute blast radius from reachable high-risk nodes and privileged edges, with a “why” output.

4) Snapshot integration
- Snapshot must include behavioral_findings and derived drift/blast scores from baseline + graph.

5) Assurance Labs evaluation
- Each scenario declares expected_findings.
- Add `make behavior-smoke` to assert findings exist after scenario runs.

### Definition of done
- Running a scenario produces findings with baseline evidence.
- Behavioral page shows findings and explains why they triggered.
- Control Room highlights top anomalies with recommended actions.
- Assurance Labs validates expected_findings for scenarios.

## Current priorities (Enterprise-grade uplift)

### 1) Single source of truth for dashboard data
All pages must render from a shared snapshot (window + mode + include_labs) so scenario runs reflect consistently across:
- Risk gauges
- Tables
- Charts
- Access graph
Avoid per-page bespoke endpoint logic. Prefer `utils/data_snapshot.py::get_snapshot()`.

### 2) Refresh must never show stale data
If caching is used, it must be keyed correctly and support a force-refresh token when users click Refresh.

### 3) Assurance Labs must show coverage gaps
Add a “Coverage Gaps” panel: expected vs observed detections, miss reasons, and recommended fixes. Include time-to-detect when possible.

### 4) Detections must support minimal case workflow
Add finding lifecycle states (New → Closed), owner, notes, and action CTAs. This is required for SOC realism.

### 5) Risk scores must be explainable
Every risk score should show top drivers (feature contribution style). No black-box scores.

### 6) Visual consistency
Enforce one theme (dark) across Streamlit, plotly, and embedded HTML graphs.

## Phase 4 - Signal Integrity & Cohesion (Hard Requirement)

Before any UI polish/redesign, prioritize **trust**: metrics must be deterministic, explainable, and consistent across pages.

### Non-negotiables
1. **Deterministic metrics**
   - `risk_score`, `drift_score`, `blast_score`, intent violations, and runtime findings must be computed server-side only.
   - No client-side recomputation or mode-dependent math.

2. **Mode affects visibility only**
   - Operational vs Lab mode must not change how scores are calculated.
   - Mode only changes which agents/signals are *shown*.

3. **Lab signals must not contaminate operational**
   - Scenario-generated signals must be isolated from operational metrics by default.
   - Use either separate storage or an enforced `signal_source` / `environment` field (`operational|lab`) end-to-end in ingest + queries.
   - Default pages (Control Room, Overview, Agents & Access, Activity, Behavioral) use `operational`.
   - Assurance Labs uses `lab`.
   - The mode toggle switches query source consistently.

4. **Provenance and timestamps**
   - Every displayed score must include `computed_at` / `last_updated` in UTC.
   - Show “Last updated: <UTC>” wherever scores appear.

5. **Explainability endpoint**
   - Implement: `GET /api/agents/{agent_id}/risk-breakdown`
   - Must return component-level breakdown and key inputs (intent/drift/blast/runtime), including `computed_at` and `mode`.

### Verification gates (must pass)
- Running lab scenarios in Operational mode **must not** change operational metrics.
- In Lab mode, lab metrics **should** change appropriately.
- Repeated refresh without new ingest yields identical metric values (determinism check).
- Extend `make scenario-smoke` (or equivalent) to enforce the above and fail CI on violations.

### Design principle
If a CISO can’t explain “why this score is 31” in 30 seconds, the product is not ready. UI polish comes after signal integrity.

### Phase 4 Implementation (COMPLETED)

Signal integrity has been implemented end-to-end:

**signal_source field** - Added to `NormalizedEvent`, `ToolUsage`, and `Finding` models.
- Value: `”operational”` (default) or `”lab”` (scenario-generated signals)
- Classification enforced at ingest in `normalizer._classify_signal_source(agent_id)`
- Lab agents are identified by name prefix `scenario-` (see `_LAB_AGENT_PREFIXES` in normalizer)
- DB migration runs automatically on startup via `database._apply_column_migrations()`

**No contamination** - `posture.compute_risk_score()` filters `ToolUsage` and `Finding` by
`signal_source=’operational’`. Lab scenarios running against `scenario-*` agents will NEVER
change operational risk scores.

**Correlator** - `_derive_signal_source(events)` sets finding signal_source from triggering
events. If any event is lab, the finding is lab.

**risk_score_updated_at** - Added to `AgentPrincipal`. Updated by `refresh-risk` endpoint.
Exposed in API response and shown in dashboard agent cards.

**Explainability** - `GET /api/principals/{id}/risk-breakdown` returns per-factor breakdown
with provenance, inputs, and `signal_source_filter: “operational”`.

**Dashboard signal_source param** - All operational dashboard pages pass
`signal_source=operational` when `include_labs=False`. Detections, Behavioral, Activity,
Overview, Control Room all use the correct filter. Assurance Labs always shows lab findings.

**UI trust** - Agent cards show “Risk score computed from operational signals only · last
updated: UTC”. “Explain Score” button calls risk-breakdown and renders a factor-by-factor
breakdown inline. Control Room shows signal source label and refresh timestamp above KPIs.

**Invariants going forward:**
1. `_LAB_AGENT_PREFIXES = (“scenario-”,)` is the single classification gate - do NOT add
   signal_source overrides elsewhere.
2. `compute_risk_score()` and `compute_risk_breakdown()` must ALWAYS filter by
   `signal_source=’operational’` - this is not configurable.
3. The mode toggle (`include_labs`) changes UI visibility and API query params only.
   It does NOT change how scores are computed server-side.
4. Any new detection rule that creates Findings must NOT set `signal_source` explicitly -
   the correlator’s `_derive_signal_source()` handles it automatically from the events.

# Phase 3 – Intent Integrity (Enhancement Only)

AIAAP already includes `saas/services/behavioural` with baseline/anomaly/graph drift.

Phase 3 must enhance (not replace) the existing architecture by adding:
- Intent Envelope (per principal/session/trace)
- Intent boundary violation detection
- Drift scoring (baseline vs observed)
- Blast radius growth scoring (graph drift)

Constraints:
- No directory moves or renames.
- No deletion or rewrite of working logic.
- Additive changes only: new modules, new DB tables, new API endpoints, new UI pages.
- Keep existing 10s deterministic detections loop. Behavioural loop runs separately (60–300s).

# Phase 2 – SaaS-First Refactor and Vendor Positioning

The AIAAP MVP is complete and functional.

We are now evolving the architecture to be SaaS-first and vendor-style.

Kubernetes and Helm remain supported as optional connectors,
but SaaS control plane must be clearly the product center.

Do NOT rebuild working components.
Refactor structure and add connectors incrementally.
Preserve existing functionality and demos.

## Context
We already built AIRS-CP: a Kubernetes-native AI Runtime Security Control Plane with agentic apps + tools + Ollama in-cluster and runtime detections (injection, exfiltration, governance).

We are extending the platform with AIAAP: Agent Identity & Access adversarial lab capabilities.
IMPORTANT: Do NOT use an API gateway / inline proxy as the primary enforcement or telemetry path. Vendors are moving away from that due to latency and uncertainty that all calls traverse the gateway.

Instead, implement a telemetry-first architecture using multi-signal collection:
- Code-level telemetry (OpenTelemetry) for agent/tool workflow certainty
- Node/endpoint telemetry (eBPF sensor) for ground truth and bypass detection
- Kubernetes audit + cloud control-plane logs for RBAC/IAM truth
Enforcement should be selective and distributed:
- K8s admission policy (Kyverno or Gatekeeper) to prevent risky configs
- Network policies (Cilium recommended) to block SSRF/metadata and shadow routes
- Optional in-process SDK checks for fast local blocking (NOT a central proxy)

## Goal
Deliver a SaaS-style control plane that correlates identity + access + runtime behaviors:
- Agent identity posture and inventory
- Tool usage and access patterns (observed, not assumed)
- JIT grants (time-bound, scope-bound) with auditing
- Adversarial lab scenarios (privilege escalation, token misuse, RBAC abuse, SSRF to metadata)
- Evidence timeline and detections across signals

The end product must feel like a single holistic platform with “capability packs”:
1) AIRS Runtime Pack (existing): injection/exfil/governance detections
2) AIAAP Identity Pack (new): identity posture + access anomalies + JIT + adversarial scenarios

## Repo reference (use this)
Use the existing GitHub repo as the foundation. Reuse existing Helm, dashboard, and detections patterns.
- Identify existing services/charts that implement gateway-style interception; do not expand that model.
- Replace/augment with OpenTelemetry instrumentation + collectors + sensors + SaaS ingest.

## Architecture (high level)
### In customer cluster (customer-managed, lightweight)
1) OTel Collector (aiaap-otel-collector)
- Receives spans/logs/metrics from instrumented agentic apps/tools
- Enriches with k8s metadata
- Forwards to SaaS ingest via OTLP over mTLS

2) eBPF Sensor (aiaap-ebpf-sensor)
- Prefer Cilium Tetragon or Falco (choose one and implement)
- Captures process/network/DNS events
- Forwards normalized events to SaaS ingest

3) K8s Audit / Events Collector (aiaap-k8s-audit)
- Ingest Kubernetes audit logs (or managed control-plane audit where available)
- Focus: RBAC changes, secret reads, exec/attach, SA token usage, unusual API verbs
- Forwards to SaaS ingest

4) Optional: Policy Enforcers (distributed)
- Admission control: Kyverno (preferred for simplicity) or Gatekeeper
- Network: CiliumNetworkPolicy baseline + lab-specific policies
- These are configuration/policy components, not an inline API gateway.

### SaaS Control Plane (runs locally for MVP, cloud-ready)
5) Ingest API (aiaap-ingest)
- Accepts OTLP (from collector) and JSON events (from sensors)
- Performs auth (mTLS + tenant key)
- Stores raw + normalized events

6) Correlation + Detections Engine (aiaap-detections)
- Correlate across signals: OTel spans + eBPF + audit + cloud logs
- Emit Findings with evidence bundles
- Maintain “Prevented / Detected / Missed” status per scenario

7) Identity & JIT Service (aiaap-identity)
- Maintain AgentPrincipal records
- Support JIT grants (TTL + scope + reason + audit)
- Note: JIT is used for posture/audit and for demo narratives; enforcement is via distributed policies and/or in-process SDK checks, NOT a central gateway.

8) Dashboard (existing UI extended)
- Pages: Agents, Tool Usage, JIT Grants, Scenarios, Findings timeline
- Show capability pack toggles: runtime pack, identity pack

## Required deliverables
### A) SDK instrumentation (no proxy)
Add a small SDK package used by the agentic app/tools:
- Wrap key workflow steps with OpenTelemetry spans:
  - prompt_received
  - tool_call_requested
  - tool_call_executed
  - retrieval_query
  - retrieval_result
  - response_generated
- Add attributes:
  - agent_id, agent_role, tool_name, destination_host, destination_ip, data_classification
  - jit_context (grant_id if present), request_purpose
  - risk_flags (e.g., suspected_injection=true)
- Export to OTel Collector via OTLP

### B) OTel Collector deployment
- Helm chart that deploys OpenTelemetry Collector
- Receivers: OTLP gRPC/HTTP
- Processors: k8sattributes, batch
- Exporters: OTLP to SaaS ingest (mTLS)
- Configurable tenant_id

### C) eBPF sensor deployment
Pick one:
- Tetragon (preferred with Cilium ecosystem) OR Falco
Implement Helm chart and event forwarder:
- Normalize events into a common schema
- Send to SaaS ingest

### D) K8s audit collector
Implement a collector that ingests audit logs and forwards:
- Focus events: RBAC changes, secret reads, exec/attach, token usage
- Normalize to common schema and send to SaaS ingest

### E) SaaS services (MVP runs as docker-compose)
- Postgres for storage
- Ingest service
- Correlation/detections service
- Identity/JIT service
- Dashboard service

### F) Adversarial lab orchestrator
Implement scenario runner that deploys Kubernetes Jobs that simulate identity/access attacks.
Each scenario must produce:
- expected outcomes
- observed signals (OTel/eBPF/audit)
- a final verdict: prevented/detected/missed
- evidence artifacts linked from dashboard

## Data model (MVP)
- AgentPrincipal: id, name, namespace, serviceAccount, labels, firstSeen, lastSeen, riskScore
- ToolUsage: id, principalId, toolName, destination, timestamp, attributes (json)
- JitGrant: id, principalId, scope, expiresAt, reason, createdBy, createdAt
- RawEvent: id, tenantId, source (otel/ebpf/audit/cloud), timestamp, payload
- NormalizedEvent: id, tenantId, eventType, principalId, toolName, dest, severity, payload
- Finding: id, tenantId, title, severity, status(prevented/detected/missed), evidenceRefs, timestamps
- ScenarioRun: id, scenarioId, status, startAt, endAt, verdict, expected, observedRefs

## Scenarios to implement first (6)
1) ssrf_metadata
- Agent/tool attempts to call cloud metadata IP via URL fetch tool
- Expected: network policy blocks OR in-process SDK flags and blocks
- Observed: OTel span shows attempted dest + eBPF shows blocked connection + finding created

2) rbac_escalation_misconfig
- Misconfigured RoleBinding/ClusterRoleBinding allows secrets list
- Expected: detection via audit logs + finding with remediation

3) stolen_token_usage
- Simulate misuse of service account token from another pod
- Expected: audit events + eBPF + finding

4) shadow_tool_route
- Attempt to call tool service directly bypassing intended paths
- Expected: network policy blocks; eBPF confirms; finding created

5) overbroad_permissions
- Tool usage indicates privileged action without justification/JIT context
- Expected: detection (policy violation) and recommendation

6) confused_deputy
- Low-priv identity induces privileged downstream action
- Expected: correlated finding (requester vs executor mismatch) using OTel attributes + audit/eBPF

## Enforcement (distributed, not gateway)
- Kyverno policies for:
  - disable automountServiceAccountToken unless required
  - forbid privileged pods / hostNetwork / hostPID
  - restrict allowed service accounts for sensitive namespaces
- Cilium network policies for:
  - block metadata IP ranges
  - restrict egress to allowlist
  - prevent direct access to internal tool services (shadow route)

## Implementation order (do in this order)
1) Add SDK OTel spans to the existing agentic app and tools
2) Deploy OTel Collector and verify spans reach ingest
3) Implement ingest + storage + minimal dashboard “Tool Usage” page
4) Add eBPF sensor and normalize network events
5) Add K8s audit collector and normalize audit events
6) Implement correlation rules + findings timeline
7) Add scenario runner + first scenario (ssrf_metadata)
8) Add remaining 5 scenarios

## Testing
- Unit tests for normalization and correlation rules
- Integration test: run ssrf_metadata scenario and verify:
  - OTel span received
  - eBPF event received
  - finding created with status prevented/detected

## Output style
- Keep code explicit and readable
- Strong typing, minimal magic
- Document all schemas
- Helm charts must install cleanly on a fresh cluster
- Provide docs/demos/scripts/demo.md with a step-by-step demo walkthrough