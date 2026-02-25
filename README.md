# AIAAP - AI Agent Accountability Platform

> **The observability and accountability layer for AI agent identity, intent, and access.**
>
> *Telemetry-first. No inline proxy. No added latency. 14 adversarial scenarios. Production-grade.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## The Three Questions

Every team deploying AI agents in production must eventually answer:

- **Who are your agents?** - which principals exist, what service accounts they use, what risk posture they carry
- **What are they accessing?** - which tools, destinations, secrets, and resources agents touch at runtime
- **Are they behaving as declared?** - do agent actions stay within their stated intent, or are they drifting?

Traditional monitoring answers the first two. AIAAP answers all three.

---

## What Makes AIAAP Different

Most security platforms detect *events*. AIAAP measures *accountability* - whether each agent's runtime behavior is consistent with its declared purpose.

**Intent Envelope**
Every agent session can declare a capability boundary: which tools are allowed, which destinations are reachable, what privilege tier is permitted. Violations fire immediately, before any behavioral baseline is needed.

**Behavioral Drift**
AIAAP builds a behavioral baseline per agent and computes a z-score across five dimensions every 2 minutes: call rate, destination diversity, tool entropy, privileged action ratio, and new tool frequency. Gradual privilege creep registers as drift before it becomes an incident.

**Blast Radius**
The Blast Radius Index measures how far an agent's access graph has expanded - unique destinations reached, privileged edges traversed, new edges added since the last window. High blast radius is a pre-incident signal, not a post-incident finding.

**Multi-Signal Correlation**
Signals from four independent sources are correlated against the same principal:

| Source | Certainty | What it captures |
|---|---|---|
| OTel spans | High (SDK-level) | Agent intent, tool calls, destinations, risk flags |
| eBPF network | Very High (kernel-level, bypass-resistant) | TCP connections, DNS, packet metadata |
| K8s audit logs | Very High (RBAC truth) | RBAC changes, secret reads, exec/attach, SA token usage |
| CloudTrail | Very High (IAM truth) | IAM privilege escalation, resource modifications |

**Edge-Distributed Enforcement**
AIAAP never sits in the inference path. No API gateway. No proxy. No added latency. Enforcement is distributed at the edges: Kyverno admission policies at deploy time, Cilium network policies at runtime, optional in-process SDK checks. The control plane observes everything; it enforces nothing centrally.

---

## Design Decisions

### No inline proxy
Most platforms intercept at the API gateway. That model adds latency, creates a single point of failure, and breaks silently when agents call tools directly over TCP. AIAAP captures telemetry at the edges - code, kernel, control plane - and enforces at the edges. The control plane never touches the hot path.

### Why Blast Radius
Traditional alerts fire after a bad event. Blast Radius is a *pre-incident* signal: it measures how far an agent's access graph has expanded before any specific bad action is detected. High blast radius + low intent conformance = intervention candidate.

### Why Intent Envelopes
Behavioral baselines require days of data to stabilize. Intent Envelopes provide immediate accountability: the agent declares which tools and destinations are expected, and any deviation fires instantly. The envelope is the contract; the baseline is the insurance.

### Why Drift Detection
Gradual privilege creep is the most common real-world agent risk: each individual call looks benign, but the trajectory is not. A z-score across 5 behavioral dimensions catches the trajectory before the incident.

### Why JIT Grants
Always-on permissions mean any compromise = full blast radius access. JIT grants are time-bound (TTL), scope-bound (specific tool + destination), reason-linked, and audit-logged. The platform's Policy Decision Point can auto-require a JIT grant for privileged actions, creating a natural forcing function for least-privilege.

### Why UX Narrative
Each dashboard page answers three questions in the header: *what am I seeing*, *why does it matter*, *what should I do next*. Agent security is operationally new territory - without narrative context, operators dismiss alerts they don't understand. The UX is designed to build intuition, not just surface data.

---

## Flagship Metrics

| Metric | Definition |
|---|---|
| **Agent Accountability Score** (0–100) | Composite of intent adherence, drift stability, blast radius containment, and privilege discipline. The single-number posture for an agent. |
| **Intent Conformance Rate** (%) | Percentage of tool calls and destinations within the declared or auto-derived intent envelope over a rolling 24h window. |
| **Drift Score** (0–100) | Z-score deviation of the last hour's behaviour vs the BehavioralBaseline across 5 dimensions. |
| **Blast Radius Index** (0–100) | Weighted score of unique reachable destinations, privileged edges, and new-edge growth rate in the current window. |

---

## Architecture

```
  Customer Environments
  ─────────────────────────────────────────────────────────────────────
  Kubernetes Cluster          AWS Account           Any Environment
  ┌──────────────────┐        ┌────────────────┐    ┌─────────────────┐
  │  Agentic App     │        │  CloudTrail    │    │  OTel-instrumented│
  │  + AIAAP SDK     │        │  IAM events    │    │  app (any lang) │
  └────────┬─────────┘        └───────┬────────┘    └───────┬─────────┘
           │                          │                      │
  ┌────────▼─────────┐        ┌───────▼────────┐             │
  │  OTel Collector  │        │  Lambda +      │             │
  │  (Helm chart)    │        │  EventBridge   │             │
  └────────┬─────────┘        └───────┬────────┘             │
           │                          │                      │
  ┌────────▼─────────┐                │                      │
  │  eBPF Sensor     │                │                      │
  │  (Tetragon)      │                │                      │
  └────────┬─────────┘                │                      │
           │ OTLP/HTTPS               │ HTTPS                │ OTLP/HTTPS
           └──────────────────────────┴──────────────────────┘
                                      │
  AIAAP SaaS Control Plane  (docker-compose locally, cloud-ready)
  ─────────────────────────────────────────────────────────────────────
  ┌──────────┐   ┌──────────────────────────────────────────────────────┐
  │  Ingest  │──►│  Correlation + Agent Accountability Engine            │
  │  :8100   │   │                                                       │
  │ OTel +   │   │  Intent Integrity   - envelope vs actual              │
  │ eBPF +   │   │  Drift Analysis     - z-score vs baseline             │
  │ Cloud    │   │  Blast Radius       - access graph expansion          │
  │          │   │  Deterministic detections  :8200                      │
  └──────────┘   └──────────────────────────────────────────────────────┘
                 ┌──────────────────────┐    ┌──────────────────────────┐
                 │ Identity + JIT :8300 │    │  Runtime Pack     :8400  │
                 │ Posture · PDP ·      │    │  Injection · PII         │
                 │ Audit log · Approvals│    │  Content masking         │
                 └──────────────────────┘    └──────────────────────────┘
                        PostgreSQL 16 (shared schema · 18 ORM models)
                        Streamlit Dashboard :8501 (9 pages)
```

---

## Quickstart

Start code-only (no Kubernetes, no AWS required), then add connectors as needed.

### Step 1 - Start the control plane

```bash
git clone https://github.com/SP-Autonomy/agent-accountability-platform.git
cd agent-accountability-platform
cp .env.example .env
make up            # all 5 SaaS services + Postgres
```

Dashboard: http://localhost:8501

### Step 2 - Prove the pipeline (zero infrastructure)

```bash
# Inject a synthetic SSRF event → finding in ~10s
make demo-ingest-ssrf

# Inject a cloud IAM escalation event → finding in ~10s
make demo-ingest-iam

# Test the Runtime Pack (injection + PII detection)
make demo-runtime

# Run all 14 adversarial scenarios
make scenario-all
```

### Step 3 - Zero-infrastructure POV

```bash
make pov-cli   # sends 3 events via curl, verifies connector registers
```

### Kubernetes Connector (optional)

```bash
make k8s-up        # creates 'aiaap' kind cluster
make k8s-cilium    # Cilium CNI + NetworkPolicy enforcement
make k8s-tetragon  # Tetragon eBPF sensor
make k8s-kyverno   # Kyverno admission control
make k8s-deploy    # OTel Collector + eBPF sensor + audit collector
make k8s-enforce   # Kyverno + Cilium policies

make scenario-ssrf  # live K8s scenario
```

### AWS CloudTrail Connector (optional)

```bash
make tenant-bootstrap TENANT=myorg   # → AIAAP_API_KEY=<key>

cd connectors/aws/cloudtrail_forwarder
sam build && sam deploy --guided \
  --parameter-overrides \
    AiAAPIngestUrl=https://<your-ingest> \
    AiAAPApiKey=<key> \
    AiAAPTenantId=myorg
```

IAM escalation events (AttachRolePolicy, CreateRole, PassRole) produce findings within seconds of occurring in your AWS account.

---

## Capability Packs

| Pack | What it provides |
|---|---|
| **Identity Pack** | Agent identity posture · JIT grant governance · behavioral drift · blast radius · intent integrity violations · tool usage heatmaps · audit log · connector health tracking |
| **Runtime Pack** | Prompt injection detection (7 pattern categories) · PII leakage detection (12 data types) · masked content preview · per-agent detection history |

Both packs share the same ingest pipeline, correlation engine, and dashboard. The Policy Decision Point (PDP) provides enforcement outcomes (allow / block / step\_up / redact / sandbox / rate\_limit) across both.

---

## Connectors

Connectors are optional and additive. Any environment that can send events to the ingest API is supported.

| Connector | Path | Install | Type |
|---|---|---|---|
| Kubernetes (OTel Collector) | `connectors/k8s/helm/aiaap-otel-collector/` | `make k8s-deploy` | `k8s_otel` |
| Kubernetes (eBPF / Tetragon) | `connectors/k8s/helm/aiaap-ebpf-sensor/` | `make k8s-deploy` | `ebpf` |
| Kubernetes (Audit logs) | `connectors/k8s/helm/aiaap-k8s-audit/` | `make k8s-deploy` | `k8s_audit` |
| AWS CloudTrail | `connectors/aws/cloudtrail_forwarder/` | SAM deploy or container | `cloudtrail` |
| Python SDK (code-level) | `connectors/code/otel_sdk_python/` | `pip install -e` | `sdk` |
| CLI / curl | `examples/customer_env_cli/` | Zero install | `cli` |

Each connector self-registers on first event. The Connectors dashboard page shows health (healthy / stale / inactive), events-per-hour, and coverage gaps.

See [docs/connectors/README.md](docs/connectors/README.md) for detailed install guides.

---

## Dashboard

Nine story-driven pages - each with a *what / why / next* narrative header:

| Page | What it answers |
|---|---|
| **Control Room** | Single pane of glass - Accountability Score, intent violations, drift alerts, blast radius alerts |
| **Overview** | Are any agents in a critical risk state right now? |
| **Agents & Access** | What is each agent's Accountability Score, JIT posture, and compliance mapping? |
| **Activity** | What tools and destinations are agents actually using? (heatmap + topology graph) |
| **Behavioral Intelligence** | Is agent behavior conformant with declared intent? Has drift been detected? How large is the blast radius? |
| **Detections** | What findings exist, grouped by scenario, with remediation guidance and enforcement history? |
| **Lab Scenarios** | What is our time-to-detect for each of the 14 attack patterns? |
| **Connectors** | Which telemetry connectors are active? What signals are they delivering? Any coverage gaps? |
| **Runtime** | What injection and PII detections have fired? What content was masked? |

---

## Adversarial Labs

14 attack simulations for continuous AI agent resilience testing:

| # | Scenario | Environment | Category | Severity |
|---|---|---|---|---|
| 1 | SSRF - Cloud Metadata | AWS / GCP / Azure | Network | Critical |
| 2 | RBAC Escalation Misconfiguration | Kubernetes | Identity | High |
| 3 | Stolen Service Account Token | Kubernetes | Identity | Critical |
| 4 | Shadow Tool Route | Kubernetes | Network | High |
| 5 | Overbroad Permissions | Multi-cloud | Identity | High |
| 6 | Confused Deputy | Multi-cloud | Identity | Critical |
| 7 | Gradual Privilege Creep | Multi-cloud | Behavioral | High |
| 8 | Intent Mismatch - Exfiltration | Multi-cloud | Intent | High |
| 9 | RAG Data Exfiltration | Multi-cloud | Runtime | High |
| 10 | Multi-Agent Prompt Hijack | Multi-cloud | Runtime | Critical |
| 11 | JIT Grant Abuse | SaaS Control Plane | Identity | High |
| 12 | Credential Harvesting | Kubernetes | Runtime | Critical |
| 13 | Cross-Namespace Lateral Movement | Kubernetes | Network | High |
| 14 | Supply Chain - Shadow Tool Endpoint | Multi-cloud | Network | Critical |

```bash
make scenario-all      # run all 14 sequentially
make scenario-ssrf     # run a single scenario
```

---

## Deterministic Controls

8 correlation rules run against every event window, in parallel with the behavioral accountability engine:

| Rule | Signal sources | Fires on |
|---|---|---|
| `rule_ssrf` | OTel + eBPF | Cloud metadata IP access (169.254.x.x) |
| `rule_rbac` | K8s audit | ClusterRoleBinding create/patch |
| `rule_stolen_token` | K8s audit | Cross-namespace SA token usage |
| `rule_shadow_route` | eBPF | Direct tool host access bypassing orchestrator |
| `rule_overbroad` | OTel + JIT DB | Privileged action without active JIT grant |
| `rule_confused_deputy` | OTel | Caller agent ID ≠ executor within same trace |
| `rule_iam_escalation` | CloudTrail | IAM privilege escalation API calls |
| `rule_runtime` | Runtime Pack DB | High/critical injection or PII detections |

---

## Repository Layout

```
agent-accountability-platform/
├── saas/                            # SaaS Control Plane (the product)
│   ├── services/
│   │   ├── shared/                  # SQLAlchemy models, schemas, auth, DB session
│   │   ├── ingest/                  # Multi-signal ingest API (:8100)
│   │   ├── detections/              # Correlator + behavioral accountability (:8200)
│   │   ├── identity/                # Agent identity, JIT grants, PDP, audit (:8300)
│   │   ├── runtime/                 # Injection + PII detection (:8400)
│   │   ├── dashboard/               # Streamlit UI (:8501, 9 pages)
│   │   └── behavioural/             # Shared lib: drift engine, blast radius, intent envelope
│   ├── configs/                     # OTel Collector config (compose mode)
│   ├── scripts/                     # bootstrap_tenant.py
│   └── docker-compose.yml
│
├── connectors/                      # Customer-side connectors (optional, lightweight)
│   ├── k8s/helm/                    # OTel Collector, eBPF sensor, audit, enforcement charts
│   ├── aws/cloudtrail_forwarder/    # Lambda + container CloudTrail forwarder (SAM)
│   └── code/otel_sdk_python/        # Python OTel SDK for instrumenting agentic apps
│
├── labs/
│   ├── scenarios/                   # 14 scenario classes + runner
│   └── agentic_app/                 # Reference orchestrator + tools app (demo workload)
│
├── examples/
│   ├── customer_env_cli/            # Zero-infra POV: curl events + verify connector
│   ├── customer_env_k8s/            # K8s POV: kind + OTel collector + sample agent
│   └── customer_env_cloud/          # AWS POV: SAM deploy + CloudTrail events + verify
│
├── tests/
│   ├── unit/                        # Drift engine, intent envelope, normalizer, rules, PDP
│   └── integration/                 # SSRF pipeline, intent drift, end-to-end
│
├── docs/
│   ├── architecture.md
│   ├── demo.md
│   └── connectors/README.md
│
└── Makefile                         # 45+ targets: up, test, scenarios, k8s, pov, demo
```

> **Note on `saas/services/behavioural/`:** This is a shared Python library, not a standalone service. It runs inside the detections container - this is intentional.

---

## Multi-Tenancy

Dev mode (default): no auth, all events tagged `tenant_id="default"`. Start with `make up`.

Production mode:
```bash
REQUIRE_API_KEY=true  # in docker-compose or .env

python saas/scripts/bootstrap_tenant.py --tenant-id acme
# → AIAAP_API_KEY=<printed once, not stored>
```

When `REQUIRE_API_KEY=true`, `tenant_id` is derived from the verified API key record. The caller-supplied `X-Tenant-Id` header is ignored to prevent spoofing.

---

## Running Tests

```bash
pytest tests/unit/ -v                          # no docker required
pytest tests/integration/ -v -m integration    # requires: make up

make scenario-smoke       # scenario → finding pipeline
make behavior-smoke       # drift + behavioral accountability
make enforcement-smoke    # PDP: block SSRF, step_up privileged, allow safe
```

---

## Docs

- [Architecture](docs/architecture.md) - signal flow, behavioral accountability engine design
- [Demo walkthrough](docs/demo.md) - step-by-step for all quickstart paths
- [Connectors guide](docs/connectors/README.md) - install and verify each connector
- [RESULTS.md](RESULTS.md) - what was built, detection coverage, threat model
