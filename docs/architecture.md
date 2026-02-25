# AIAAP Architecture

## Design Principles

**Agent Accountability above the telemetry layer.**
AIAAP is not a detection platform with rules. Rules are one component. The core of the platform is the Agent Accountability Engine: three orthogonal signals that together answer whether an agent is behaving as declared.

- **Intent Integrity** - does the agent's runtime behavior match its declared capability envelope?
- **Drift Score** - is the agent's behavior diverging from its established baseline?
- **Blast Radius Index** - how large has the agent's access graph grown?

These three signals operate independently and are correlated in the same evidence bundle. A single finding can reference an intent violation, a high drift score, *and* a blast radius alert - all pointing to the same agent and trace.

**Telemetry-first, no inline proxy.**
AIAAP never sits in the critical path of agent inference. All signals are collected out-of-band via OTel spans (code-level certainty), eBPF network events (ground truth, bypass-resistant), Kubernetes audit logs (RBAC truth), and cloud control-plane events (IAM truth). Enforcement is distributed at the edges - Kyverno admission policies at deploy time, Cilium network policies at runtime, optional in-process SDK checks - never through a central API gateway.

This follows the same pattern as Sysdig, Lacework, and Paladin Cloud: observe everything, enforce selectively at the edge.

---

## Signal Collection Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Customer Environment A: Kubernetes                                            │
│                                                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐    │
│  │ ai-app namespace                                                       │    │
│  │  ┌─────────────────┐    HTTP     ┌──────────────────┐                 │    │
│  │  │  Orchestrator   │───────────►│   Tools Service  │                 │    │
│  │  │  (OTel SDK)     │            │   (OTel SDK)     │                 │    │
│  │  │  prompt_received│            │ tool_call_executed│                 │    │
│  │  │  tool_call_req  │            │                  │                 │    │
│  │  └────────┬────────┘            └────────┬─────────┘                 │    │
│  │           │ OTLP gRPC                    │ OTLP gRPC                 │    │
│  │           └──────────────┬───────────────┘                           │    │
│  └──────────────────────────┼───────────────────────────────────────────┘    │
│                             ▼                                                 │
│  ┌──────────────────────────────────┐                                         │
│  │ aiaap-system namespace           │                                         │
│  │  ┌─────────────────────────────┐ │                                         │
│  │  │  OTel Collector             │ │  ← k8sattributes enriches spans         │
│  │  │  (Helm: aiaap-otel-         │ │    with pod/namespace/SA metadata       │
│  │  │   collector)                │ │                                         │
│  │  │  :4317 gRPC / :4318 HTTP    │ │                                         │
│  │  └──────────────┬──────────────┘ │                                         │
│  │                 │ OTLP/HTTP      │                                         │
│  │  ┌──────────────▼──────────────┐ │                                         │
│  │  │  eBPF Sensor (DaemonSet)    │ │  ← Tetragon kprobe on tcp_connect       │
│  │  │  (Helm: aiaap-ebpf-sensor)  │ │    captures dest IP/port per process    │
│  │  │  Forwards → ingest /api/    │ │                                         │
│  │  │  events?source=ebpf         │ │                                         │
│  │  └─────────────────────────────┘ │                                         │
│  │  ┌─────────────────────────────┐ │                                         │
│  │  │  Audit Collector (Deployment│ │  ← Tails /var/log/kubernetes/audit      │
│  │  │  on control-plane node)     │ │    filters RBAC/secrets/exec verbs      │
│  │  │  (Helm: aiaap-k8s-audit)    │ │    Forwards → ingest /api/events        │
│  │  └─────────────────────────────┘ │    ?source=audit                        │
│  └──────────────────────────────────┘                                         │
└────────────────────────────────────────────────────────────────────────┬──────┘
                                                                          │
┌─────────────────────────────────────────────────────────────────────────┼──────┐
│ Customer Environment B: AWS Account                                      │      │
│  ┌──────────────────────┐  EventBridge  ┌────────────────────┐          │      │
│  │ IAM / Management API │──────────────►│  CloudTrail Event  │          │      │
│  │                      │               │  (detail-type:     │          │      │
│  │  AttachRolePolicy     │               │  "AWS API Call     │          │      │
│  │  CreatePolicyVersion  │               │   via CloudTrail") │          │      │
│  └──────────────────────┘               └─────────┬──────────┘          │      │
│                                                   │                     │      │
│                          ┌─────────────────────────▼──────────────────┐ │      │
│                          │  CloudTrail Forwarder                       │ │      │
│                          │  Option A: Lambda (serverless, event-driven)│ │      │
│                          │  Option B: Container (ECS/Fargate, polling) │ │      │
│                          │  Normalizes: actor ARN → principal           │ │      │
│                          │             affected resource → dest         │ │      │
│                          │             eventName → cloud.iam.action     │ │      │
│                          └────────────────────────┬───────────────────┘ │      │
└───────────────────────────────────────────────────┼─────────────────────┘      │
                                                    │ HTTPS                       │
                                                    │ POST /api/events            │
                                                    │ source=cloud                │
                                                    │                             │
                        ────────────────────────────┼─────────────────────────────
                                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ AIAAP SaaS Control Plane  (docker-compose locally, cloud-ready)               │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ Ingest Service :8100                                                     │  │
│  │  POST /otlp/v1/traces  ← OTel spans (JSON OTLP)                         │  │
│  │  POST /api/events      ← eBPF events, audit logs, CloudTrail events     │  │
│  │  GET  /api/events      ← dashboard queries (filtered by tenant_id)      │  │
│  │  GET  /api/tool-usages ← tool usage heatmap                             │  │
│  │                                                                         │  │
│  │  Normalizer: OTel span → NormalizedEvent + ToolUsage                    │  │
│  │             eBPF event → NormalizedEvent                                │  │
│  │             Audit log  → NormalizedEvent                                │  │
│  │             CloudTrail → NormalizedEvent (event_type: cloud.iam.*)      │  │
│  └──────────────────────────────┬──────────────────────────────────────────┘  │
│                                 │ Shared PostgreSQL 16                         │
│  ┌──────────────────────────────▼──────────────────────────────────────────┐  │
│  │ Detections Engine :8200                                                  │  │
│  │  10-second correlation loop over NormalizedEvents (last 60s)             │  │
│  │  Groups by trace_id (OTel) + ungrouped (eBPF/audit/cloud)               │  │
│  │                                                                         │  │
│  │  Rules (7):                                                             │  │
│  │    rule_ssrf            - metadata IP 169.254.169.254 access            │  │
│  │    rule_rbac            - ClusterRoleBinding create/patch               │  │
│  │    rule_stolen_token    - cross-namespace SA token usage                │  │
│  │    rule_shadow_route    - direct tool access bypassing orchestrator      │  │
│  │    rule_overbroad       - privileged tool call without JIT grant        │  │
│  │    rule_confused_deputy - agent ID mismatch within OTel trace           │  │
│  │    rule_iam_escalation  - AWS IAM privilege escalation (CloudTrail)     │  │
│  │                                                                         │  │
│  │  Dedup: same scenario_id within 5-minute window → suppress              │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ Identity & JIT Service :8300                                             │  │
│  │  GET/POST /api/principals     - agent inventory + risk scores           │  │
│  │  GET/POST/DELETE /api/jit/    - JIT grant lifecycle                     │  │
│  │  POST /api/jit/validate       - check active grant for principal        │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ Dashboard :8501 (Streamlit)                                             │  │
│  │  01 Overview       - KPI cards, capability pack status                 │  │
│  │  02 Agents         - principal inventory, risk score heatmap           │  │
│  │  03 Tool Usage     - agent×tool heatmap (Plotly)                       │  │
│  │  04 JIT Grants     - active grants, create/revoke                      │  │
│  │  05 Scenarios      - run adversarial labs, view PREVENTED/DETECTED     │  │
│  │  06 Findings       - evidence timeline, multi-signal detail            │  │
│  │  07 Cloud Coverage - CloudTrail connector status, IAM findings         │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow: OTel Span

```
Agentic app (instrumented)
  ↓ @trace_tool_call("fetch_url")
  ↓ span attributes: aiaap.tool.name, aiaap.tool.destination_host, aiaap.risk.flags
  ↓ OTLP gRPC to OTel Collector
  ↓ k8sattributes processor adds k8s.pod.name, k8s.namespace.name, k8s.serviceaccount.name
  ↓ OTLP HTTP to ingest /otlp/v1/traces
  ↓ RawEvent stored
  ↓ Background: normalize_otel_payload()
  ↓ NormalizedEvent: event_type=tool_call_executed, source=otel, trace_id=...
  ↓ ToolUsage: principal_id, tool_name=fetch_url, destination=169.254.169.254
  ↓ (10 seconds later) Correlator picks up event
  ↓ rule_ssrf.check(): dest contains metadata IP → Finding (severity=HIGH, status=DETECTED)
  ↓ Dashboard 06_findings shows finding with OTel span evidence
```

## Data Flow: AWS CloudTrail

```
IAM AttachRolePolicy call
  ↓ CloudTrail management event
  ↓ EventBridge rule: detail-type="AWS API Call via CloudTrail", detail.eventSource="iam.amazonaws.com"
  ↓ Lambda invoked with event.detail = CloudTrail record
  ↓ normalizer.normalize_cloudtrail_event():
      actor ARN (userIdentity.arn) → payload._aiaap_actor_arn
      affected resource (requestParameters.roleName) → payload._aiaap_dest
      "attach_role_policy" → event_type = cloud.iam.attach_role_policy
  ↓ POST /api/events {source: "cloud", payload: {...}}
  ↓ ingest: normalize_cloud_event() → NormalizedEvent (source=cloud, event_type=cloud.iam.attach_role_policy)
  ↓ Correlator: rule_iam_escalation.check() matches event_type in IAM_ESCALATION_EVENT_TYPES
  ↓ Finding: "IAM Privilege Escalation: AttachRolePolicy on prod-eks-node-role" (HIGH, DETECTED)
  ↓ Dashboard 07_cloud_coverage shows finding + connector status
```

---

## Enforcement (Edge-Distributed, Not Inline)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Enforcement is always at the edge - never through AIAAP as a central proxy  │
│                                                                             │
│  Kubernetes Admission (Kyverno)           K8s Cluster at deploy time        │
│    • disable-automount-sa-token.yaml    - pods must opt-in to SA token     │
│    • forbid-privileged-pods.yaml        - no privileged / hostNetwork pods  │
│    • restrict-allowed-sa.yaml           - SA allowlist per namespace        │
│                                                                             │
│  Network Policy (Cilium)                  K8s Cluster at runtime           │
│    • block-metadata-ip.yaml             - egress DENY to 169.254.0.0/16    │
│    • restrict-egress.yaml               - allowlist-based egress for tools  │
│    • prevent-shadow-routes.yaml         - tools only accept from orchestrator│
│                                                                             │
│  In-Process SDK Check (optional)          Agent application code            │
│    • JIT context attached to spans      - check active grant before action  │
│    • Risk flags on spans                - downstream rules can react        │
│                                                                             │
│  AWS (optional, customer-managed)                                          │
│    • IAM Service Control Policies (SCP) - prevent PassRole, CreateRole     │
│    • AWS CloudTrail + GuardDuty         - native detection                 │
│    • AIAAP finding → customer SOAR/SIEM - via webhook (future)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Multi-Tenancy

```
X-Api-Key: <tenant-key>   →  auth.get_tenant()  →  TenantApiKey.key_hash (bcrypt verify)
                                    │
                                    ▼
                               tenant_id  (from DB record - caller cannot spoof)
                                    │
                                    ▼
                         All DB queries filtered by tenant_id:
                           NormalizedEvent.tenant_id = ?
                           Finding.tenant_id = ?
                           AgentPrincipal.tenant_id = ?
```

REQUIRE_API_KEY=false (default for `make up` / local dev) - no auth, tenant="default".
REQUIRE_API_KEY=true (production) - bcrypt key verification, tenant derived from DB.

---

## Intent Integrity Capability (Phase 3 - Additive)

### Overview

Intent Integrity tracks the *declared intent* of an agent session and detects deviations from it.
Three orthogonal signals are produced:

| Signal | What it measures | Alert threshold |
|---|---|---|
| **Intent Boundary Violation** | Tool / destination / privilege outside the declared envelope | Any match |
| **Drift Score** (0–100) | Z-score deviation of 1-hour behaviour vs BehavioralBaseline | ≥ 60 |
| **Blast Radius Score** (0–100) | How far an agent's access graph has grown | ≥ 50 |

### Intent Envelope

An IntentEnvelope is a per-session or per-task declaration of what an agent is allowed to do.
It is created via three paths:

```
Path 1: SDK (OTel span attributes)
  span attributes:
    aiaap.intent.label                → human-readable task label
    aiaap.intent.allowed_tools        → JSON list, e.g. ["summarize_doc", "read_*"]
    aiaap.intent.allowed_destinations → JSON list, e.g. ["*.internal", "docs.svc"]
    aiaap.intent.max_privilege        → "low" | "medium" | "high"

  → normalizer.py extracts these → upsert_envelope_from_sdk()
  → IntentEnvelope stored with created_by="sdk"

Path 2: UI (Dashboard page 11)
  → POST /api/intent/envelopes with created_by="ui"

Path 3: Auto (from BehavioralBaseline)
  → auto_create_envelope_from_baseline() runs if no SDK/UI envelope exists
  → Uses existing tool/destination frequency data
  → IntentEnvelope stored with created_by="auto"
```

Violation checks use `fnmatch` glob patterns for both `allowed_tools` and `allowed_destinations`.

### Drift Score Computation

```
Input: BehavioralBaseline (mean + std per metric)
       compute_current_metrics() for the last 60 minutes

Components:
  z_calls    = (current calls_per_hour   - baseline mean) / std  → up to 20 pts
  z_dest     = (current distinct_dest    - baseline mean) / std  → up to 20 pts
  z_entropy  = (current tool entropy     - baseline mean) / std  → up to 20 pts
  z_priv     = (current privileged_ratio - baseline mean) / std  → up to 25 pts
  z_new_tool = (current new_tool_freq    - baseline mean) / std  → up to 15 pts

Points formula: min(|z| × (cap / 3.0), cap)   [sigmoid-like, smooth cap]
Total drift score = sum of components (max 100)

Stored in: DriftSnapshot
Finding created when score ≥ 60 (scenario_id="intent_drift")
Dedup window: 15 minutes per principal
```

### Blast Radius Score Computation

```
Input: ToolUsage records (last 1 hour for current window)
       ToolUsage records (last 7 days for baseline comparison)

Components:
  dest_pts     = min(unique_destinations / 20.0, 1.0) × 40   → up to 40 pts
  priv_pts     = min(privileged_edges × 10, 30)              → up to 30 pts
  new_edge_pts = min(new_destinations / 10.0, 1.0) × 30      → up to 30 pts

Total blast radius score = sum (max 100)

Stored in: BlastRadiusSnapshot
Finding created when score ≥ 50 (scenario_id="blast_radius")
Dedup window: 15 minutes per principal
```

### Scheduling

Three background loops run in the detections service:

```
Loop 1: Correlation (CORRELATION_INTERVAL=10s)
  → Applies 8 correlation rules against last 60s of NormalizedEvents

Loop 2: Behavioral Analysis (BEHAVIORAL_INTERVAL=300s)
  → Updates BehavioralBaseline, runs anomaly_scoring for all principals

Loop 3: Intent Integrity (INTENT_INTERVAL=120s, offset=60s)
  → run_envelope_violation_scan() - detects tool/dest/privilege violations
  → run_drift_analysis()          - computes drift scores, emits DriftSnapshots
  → run_blast_radius_analysis()   - computes blast scores, emits BlastRadiusSnapshots
```

### Data Model (new tables)

```sql
-- SDK/UI/auto-declared intent per session
CREATE TABLE intent_envelopes (
  id                   SERIAL PRIMARY KEY,
  tenant_id            TEXT NOT NULL,
  principal_id         INTEGER REFERENCES agent_principals(id),
  trace_id             TEXT,
  session_id           TEXT,
  intent_label         TEXT NOT NULL DEFAULT 'unlabeled',
  allowed_tools        JSONB DEFAULT '[]',        -- glob patterns
  allowed_destinations JSONB DEFAULT '[]',        -- glob patterns
  allowed_data_classes JSONB DEFAULT '[]',
  max_privilege_tier   TEXT DEFAULT 'low',        -- low | medium | high
  created_at           TIMESTAMPTZ NOT NULL,
  expires_at           TIMESTAMPTZ,
  created_by           TEXT DEFAULT 'auto',       -- sdk | ui | auto
  active               BOOLEAN DEFAULT TRUE
);

-- Point-in-time drift snapshot per principal
CREATE TABLE drift_snapshots (
  id            SERIAL PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  principal_id  INTEGER REFERENCES agent_principals(id),
  window_start  TIMESTAMPTZ,
  window_end    TIMESTAMPTZ,
  metrics       JSONB,          -- z-score components + raw values
  drift_score   FLOAT,          -- 0–100
  created_at    TIMESTAMPTZ NOT NULL
);

-- Point-in-time blast radius snapshot per principal
CREATE TABLE blast_radius_snapshots (
  id                        SERIAL PRIMARY KEY,
  tenant_id                 TEXT NOT NULL,
  principal_id              INTEGER REFERENCES agent_principals(id),
  window_start              TIMESTAMPTZ,
  window_end                TIMESTAMPTZ,
  unique_destinations_count INTEGER DEFAULT 0,
  unique_resources_count    INTEGER DEFAULT 0,
  privileged_edges_count    INTEGER DEFAULT 0,
  new_edges_count           INTEGER DEFAULT 0,
  blast_radius_score        FLOAT,              -- 0–100
  created_at                TIMESTAMPTZ NOT NULL
);
```

### Dashboard Pages

| Page | URL | Content |
|---|---|---|
| 11 Intent Integrity | `/Intent_Integrity` | KPIs, per-principal posture table, active envelopes, violation list, envelope creator |
| 12 Drift Timeline | `/Drift_Timeline` | Drift score line chart (24h), z-score feature breakdown bar chart, snapshot table |
| 13 Blast Radius | `/Blast_Radius` | Platform KPIs, blast score bar chart per agent, growth timeline, component bar chart, alert list |

### New Lab Scenarios

| Scenario ID | Description | Expected finding |
|---|---|---|
| `gradual_privilege_creep` | Agent starts benign, escalates to 7× privileged tool calls without JIT | `intent_drift` (privileged_ratio spike) |
| `intent_mismatch_exfil` | Agent declares `document_summarizer` envelope, then calls `fetch_url` (external) + `read_secrets` | `intent_boundary` (tool + destination + privilege violations) |

Run with:
```bash
make scenario-priv-creep
make scenario-intent-mismatch
```
