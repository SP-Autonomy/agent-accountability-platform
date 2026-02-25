# AIAAP - Build Results

This document captures what was built, key design decisions, detection coverage, and threat model mapping for the AI Agent Accountability Platform.

---

## What Was Built

| Phase | Capability | Key Deliverables |
|---|---|---|
| **Phase 1** | Foundation | FastAPI ingest service, PostgreSQL schema, Docker Compose stack, OTel span normalization |
| **Phase 2** | SaaS-First + Identity | Agent principal inventory, JIT grant lifecycle, 8 correlation rules, 6-page Streamlit dashboard, multi-tenancy with bcrypt API keys |
| **Phase 3** | Intent Integrity | Intent Envelope (declared tool/destination boundaries), 5-dimension behavioral baseline (z-score drift), Blast Radius Index, Control Room dashboard, 2 new scenarios |
| **Phase 4** | Signal Expansion | Behavioral signal tagging (`signal_source`), risk score timestamps, multi-signal correlation improvements |
| **Phase 5** | Runtime Pack | Prompt injection detection (7 pattern categories), PII detection (12 data types), content masking, Runtime dashboard page |
| **Phase 6** | Enforcement + Response | Policy Decision Point (PDP) with 6 outcomes, approval workflow, EnforcementDecision audit trail, orchestrator PDP pre-flight hook, 22 unit tests for PDP |
| **Phase 7** | Connectors Productization | ConnectorInstance model (auto-registration), `GET /api/connectors` endpoint, Connectors dashboard page, 3 POV customer environments, `make pov-*` targets |

---

## Architecture by the Numbers

| Component | Count |
|---|---|
| Microservices | 5 (ingest :8100, detections :8200, identity :8300, runtime :8400, dashboard :8501) |
| SQLAlchemy ORM models | 18 |
| Dashboard pages | 9 (story-driven, with what/why/next narrative) |
| Adversarial lab scenarios | 14 |
| Deterministic correlation rules | 8 |
| Behavioral drift dimensions | 5 (call rate, destination diversity, tool entropy, privilege ratio, new tool frequency) |
| PDP enforcement outcomes | 6 (allow / block / step\_up / redact / sandbox / rate\_limit) |
| Telemetry signal sources | 4 (OTel, eBPF, K8s audit, CloudTrail) |
| Connector types | 6 (k8s\_otel, k8s\_audit, ebpf, cloudtrail, sdk, cli) |
| Injection detection pattern categories | 7 |
| PII data types detected | 12 |
| Unit test files | 5 |
| Integration test files | 2 |
| Smoke test suites (Makefile) | 4 |
| Makefile targets | 45+ |
| Helm charts (customer-side) | 4 (otel-collector, ebpf-sensor, k8s-audit, enforcement) |

---

## Detection Coverage Matrix

| # | Scenario | Expected Verdict | Primary Signal | Detection Mechanism |
|---|---|---|---|---|
| 1 | SSRF - Cloud Metadata | **PREVENTED** | OTel + eBPF | `rule_ssrf`: destination IP in 169.254.0.0/16; Cilium network policy blocks TCP |
| 2 | RBAC Escalation Misconfiguration | **DETECTED** | K8s audit | `rule_rbac`: ClusterRoleBinding create/patch verb |
| 3 | Stolen Service Account Token | **DETECTED** | K8s audit + eBPF | `rule_stolen_token`: cross-namespace SA token usage |
| 4 | Shadow Tool Route | **PREVENTED** | eBPF + network policy | `rule_shadow_route`: direct host access; Cilium blocks non-orchestrator path |
| 5 | Overbroad Permissions | **DETECTED** | OTel + JIT DB | `rule_overbroad`: privileged action without active JIT grant |
| 6 | Confused Deputy | **DETECTED** | OTel | `rule_confused_deputy`: caller agent ID ≠ executor within same trace context |
| 7 | Gradual Privilege Creep | **DETECTED** | OTel (behavioral) | Drift engine: z-score on privilege ratio + new tool frequency crosses threshold |
| 8 | Intent Mismatch - Exfiltration | **DETECTED** | OTel (intent) | Intent Envelope violation: destination outside declared `allowed_destinations` |
| 9 | RAG Data Exfiltration | **DETECTED** | Runtime Pack | PII detector fires on response content (12 data type patterns) |
| 10 | Multi-Agent Prompt Hijack | **DETECTED** | OTel + Runtime | Injection detector + OTel trace analysis (agent ID switching mid-trace) |
| 11 | JIT Grant Abuse | **DETECTED** | OTel + JIT DB | `rule_overbroad`: grant expired or scope mismatch |
| 12 | Credential Harvesting | **DETECTED** | Runtime + eBPF | Injection detector (credential-extraction patterns) + eBPF network capture |
| 13 | Cross-Namespace Lateral Movement | **PREVENTED** | K8s policy + eBPF | Kyverno admission denial + Cilium network policy; eBPF confirms blocked TCP |
| 14 | Supply Chain - Shadow Tool Endpoint | **DETECTED** | eBPF + network policy | eBPF detects connection to non-allowlisted endpoint; `rule_shadow_route` fires |

---

## Threat Model Coverage

### Attack Surface: Agent Identity

| Threat | Coverage |
|---|---|
| Impersonation of agent principal | AgentPrincipal inventory + behavioral baseline; anomalous behavior from known principal raises drift score |
| Stolen service account token | `rule_stolen_token` (K8s audit cross-namespace detection) |
| JIT grant abuse (reuse after expiry, scope escape) | `rule_overbroad` + JIT grant TTL enforcement + PDP step\_up for privileged actions |
| Overbroad static permissions | `rule_overbroad` detects privileged calls without active JIT; PDP recommends least-privilege |

### Attack Surface: Tool Access + Data

| Threat | Coverage |
|---|---|
| SSRF to cloud metadata / internal services | `rule_ssrf` + Cilium network policy (PREVENTED) + Intent Envelope destination check |
| Shadow tool routes (bypassing orchestrator) | `rule_shadow_route` + Cilium prevent-shadow-routes policy (PREVENTED) |
| RAG pipeline exfiltration | Runtime PII detector on response content; blast radius expansion alert |
| Credential harvesting via prompt injection | Runtime injection detector (7 pattern categories) + eBPF network capture |
| Supply chain: malicious tool endpoint | eBPF detects egress to non-allowlisted endpoints |

### Attack Surface: Identity Infrastructure (Kubernetes / AWS)

| Threat | Coverage |
|---|---|
| RBAC misconfiguration / privilege escalation | `rule_rbac` (K8s audit) + Kyverno admission policy |
| IAM privilege escalation (AWS) | `rule_iam_escalation` (CloudTrail: AttachRolePolicy, CreateRole, PassRole) |
| Cross-namespace lateral movement | `rule_stolen_token` + Cilium namespace isolation (PREVENTED) |
| Confused deputy (induced privilege chain) | `rule_confused_deputy` (OTel trace correlation: agent ID mismatch) |

### Attack Surface: Behavioral / Temporal

| Threat | Coverage |
|---|---|
| Gradual privilege creep | Drift engine z-score (privilege\_ratio dimension) |
| Tool diversification beyond declared scope | Intent Envelope + drift engine (tool\_entropy dimension) |
| Destination sprawl | Blast Radius Index (unique\_destinations + new\_edge growth) |
| Multi-agent prompt hijack (chain poisoning) | OTel trace analysis + Runtime injection detection |

---

## Key Design Decisions and Outcomes

### Telemetry-First, No Inline Proxy
**Decision:** Never intercept at the API gateway layer.
**Why:** Inline proxies add latency, become single points of failure, and are bypassable by direct TCP calls between agent components. Telemetry at the code level (OTel), kernel level (eBPF), and control plane level (K8s audit, CloudTrail) is harder to bypass and provides higher-confidence signal.
**Outcome:** All 14 scenarios produce findings without any proxy in the path. The SSRF and shadow route scenarios are *prevented* by distributed Cilium network policies - no central enforcement needed.

### Behavioral Accountability vs. Event Alerting
**Decision:** Build accountability scoring (drift, blast radius, intent conformance) alongside point-in-time alerting.
**Why:** Individual events often look benign. The threat is the pattern. Accountability scoring surfaces trajectory risk before any individual event crosses a detection threshold.
**Outcome:** Gradual Privilege Creep (scenario 7) is caught by the drift engine before any individual API call would trigger a deterministic rule.

### Intent Envelopes + Behavioral Baselines (Complementary)
**Decision:** Support both declared boundaries (Intent Envelope) and learned baselines (BehavioralBaseline).
**Why:** New agent deployments need immediate accountability without waiting for baseline data. Envelopes provide day-1 coverage. Baselines provide deeper statistical coverage over time.
**Outcome:** Intent Mismatch (scenario 8) fires on day 1 via Intent Envelope violation. Gradual creep (scenario 7) fires via z-score drift after baseline stabilizes.

### JIT as Forcing Function
**Decision:** JIT grants are not optional audit records - the PDP actively requires them for privileged actions.
**Why:** Without enforcement, JIT is just logging. The PDP's `step_up` outcome creates a natural checkpoint: agents must request time-bound, scoped access for privileged operations.
**Outcome:** JIT Grant Abuse (scenario 11) is detected by `rule_overbroad` when the grant expires mid-session. The approval workflow creates a complete audit trail from request → approval → grant → use → expiry.

---

## What Was Intentionally Not Built

| Omission | Rationale |
|---|---|
| **Inline API gateway / proxy** | Telemetry-first architecture supersedes this. Proxies add latency and false security. All signals arrive via OTel, eBPF, K8s audit, or CloudTrail - not via request interception. |
| **In-process SDK enforcement (blocking)** | SDK provides telemetry and optional local checks, not central enforcement. Blocking at the SDK level risks breaking agent workflows for false positives. Enforcement is distributed at the policy layer. |
| **Cloud SCP (Service Control Policies)** | AWS SCP enforcement is out of scope for the control plane MVP. CloudTrail coverage provides detection; prevention can be layered via customer SCP configuration. |
| **Webhook export to SIEM/SOAR** | Findings are queryable via the API and visible in the dashboard. SIEM/SOAR integration is a planned extension, not core to the accountability platform. |

---

## Repository

**GitHub:** [SP-Autonomy/agent-accountability-platform](https://github.com/SP-Autonomy/agent-accountability-platform)

```bash
git clone https://github.com/SP-Autonomy/agent-accountability-platform.git
cd agent-accountability-platform
make up && make scenario-all
```
