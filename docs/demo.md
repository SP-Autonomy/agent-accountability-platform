# AIAAP Demo Walkthrough

**AI Agent Accountability Platform - Step-by-step demo**

The core 5-minute story:
1. **Declare intent** - register an agent's capability envelope (which tools, which destinations, which privilege tier)
2. **Run a scenario** - inject signals that violate the envelope
3. **See accountability** - Intent violation + Drift Score spike + Blast Radius growth appear in the dashboard together

Three independent demo paths. Each stands alone - you do not need to complete a previous one.

| Path | What it proves | Time |
|---|---|---|
| [1. Local SaaS](#1-local-saas-demo) | Full signal pipeline + accountability UI (no K8s, no AWS) | ~5 min |
| [2. Kubernetes Connector](#2-kubernetes-connector-demo) | Live K8s telemetry + adversarial scenarios | ~20 min |
| [3. AWS CloudTrail Connector](#3-aws-cloudtrail-connector-demo) | Cloud IAM detection via EventBridge/Lambda | ~10 min |

---

## 1. Local SaaS Demo

**What this proves:** The entire ingest → correlation → finding → dashboard pipeline using synthetic events. No Kubernetes or AWS account required.

### Prerequisites
- Docker + Docker Compose
- `make`

### Step 1 - Start the control plane

```bash
make up
```

Wait ~30 seconds for all services to pass health checks. Verify:

```bash
make health
# ✅ Ingest    ✅ Detections    ✅ Identity
```

Open the dashboard: **http://localhost:8501**

You should see the Overview page with 4 KPI cards at zero.

---

### Step 2 - Inject a synthetic SSRF event

This simulates an instrumented agent calling the cloud metadata IP (169.254.169.254).

```bash
make demo-ingest-ssrf
```

What just happened:
- An OTLP JSON span was POSTed to `http://localhost:8100/otlp/v1/traces`
- The ingest service stored a `RawEvent` and a `NormalizedEvent` with `dest=169.254.169.254`
- The event type is `tool_call_executed`, severity `HIGH`

**Wait ~15 seconds** (the correlator loop runs every 10s), then refresh the dashboard.

Expected results:
- **Overview** → Open Findings: `1`
- **Findings Timeline** (page 6) → one finding: "SSRF: Metadata IP Access" with status `DETECTED`
- Click the expander → see the OTel span evidence as JSON

---

### Step 3 - Inject a synthetic AWS IAM escalation event

This simulates an `AttachRolePolicy` CloudTrail event forwarded from AWS.

```bash
make demo-ingest-iam
```

**Wait ~15 seconds**, then navigate to **Cloud Coverage** (page 7) in the dashboard.

Expected results:
- Cloud Events (total): `1`
- IAM Findings: `1`
- Finding: "IAM Privilege Escalation: AttachRolePolicy on prod-eks-node-role (us-east-1)"
- Connector status: `🟢 Connected` (event received in last hour)

---

### Step 4 - Explore the UI

| Dashboard page | What to check |
|---|---|
| Overview | KPI cards, capability pack toggles (Runtime Pack / Identity Pack) |
| Agents | No agents yet (need instrumented app running) |
| Tool Usage | Empty heatmap (will populate after `make up-demo`) |
| JIT Grants | Create a grant: principal=`demo-agent`, scope=`secrets:read`, reason=`demo` |
| Scenarios | Cards for all 6 adversarial scenarios (K8s required to run them) |
| Findings | SSRF finding + IAM finding from steps 2–3 |
| Cloud Coverage | IAM finding + connector status |

---

### Step 5 - Start the demo agentic app (optional)

```bash
make up-demo
```

This starts the orchestrator + tools service + OTel Collector. The orchestrator sends real OTel spans with AIAAP attributes. After ~30 seconds you should see:
- **Agents** page: `orchestrator-01` principal appears
- **Tool Usage** page: heatmap populates
- **Overview**: Active Agents counter increments

---

## 2. Kubernetes Connector Demo

**What this proves:** Live K8s telemetry (OTel spans + eBPF network events + audit logs) flowing to the SaaS control plane, plus adversarial scenarios with PREVENTED/DETECTED verdicts.

### Prerequisites
- Docker + Docker Compose (for the SaaS control plane)
- `kind`, `kubectl`, `helm`
- 8 GB RAM available for the cluster

### Step 1 - Start the SaaS control plane

```bash
make up
make health   # all green before proceeding
```

### Step 2 - Create the kind cluster

```bash
make k8s-up
```

This creates a 2-node kind cluster (`kind-aiaap`) with:
- K8s audit logging enabled (writes to `/tmp/aiaap-audit/`)
- CNI disabled (Cilium will be installed next)

Verify:
```bash
kubectl --context kind-aiaap get nodes
# NAME                  STATUS     ROLES           AGE
# aiaap-control-plane   NotReady   control-plane   30s
# aiaap-worker          NotReady   <none>           30s
```
Nodes are `NotReady` until Cilium is installed.

### Step 3 - Install Cilium CNI

```bash
make k8s-cilium
```

After completion:
```bash
kubectl --context kind-aiaap get nodes
# Both nodes should be Ready
```

### Step 4 - Install Tetragon eBPF sensor

```bash
make k8s-tetragon
```

Tetragon installs as a DaemonSet in `kube-system`. The AIAAP `TracingPolicy` (`tcp_connect` kprobe) is applied by the eBPF connector Helm chart in the next step.

### Step 5 - Install Kyverno admission controller

```bash
make k8s-kyverno
```

### Step 6 - Deploy AIAAP K8s connectors

```bash
make k8s-deploy
```

This deploys three Helm charts to `aiaap-system` namespace:
- `aiaap-otel-collector` - receives OTLP spans, enriches with k8s metadata, forwards to ingest
- `aiaap-ebpf-sensor` - Tetragon policy + forwarder DaemonSet that tails Tetragon events
- `aiaap-k8s-audit` - tails K8s audit log on control-plane node, forwards to ingest

Verify connectors are running:
```bash
kubectl --context kind-aiaap get pods -n aiaap-system
# NAME                                   READY   STATUS    RESTARTS
# aiaap-otel-collector-xxx               1/1     Running
# aiaap-ebpf-sensor-forwarder-xxx        1/1     Running   (DaemonSet)
# aiaap-k8s-audit-xxx                    1/1     Running
```

### Step 7 - Apply enforcement policies

```bash
make k8s-enforce
```

Applies:
- 3 Kyverno ClusterPolicies (automount token, privileged pods, SA allowlist)
- 3 CiliumNetworkPolicies (block metadata IP, egress allowlist, shadow route prevention)

Verify:
```bash
kubectl --context kind-aiaap get clusterpolicy
kubectl --context kind-aiaap get ciliumnetworkpolicy -A
```

### Step 8 - Run the SSRF adversarial scenario

```bash
make scenario-ssrf
```

The scenario runner:
1. Verifies the Cilium metadata-block policy is applied
2. Deploys a K8s Job in `ai-app` namespace that curls `169.254.169.254`
3. Cilium blocks the connection at the network level
4. The eBPF forwarder captures the `tcp_connect` event (action=blocked) and sends it to ingest
5. The correlator produces a Finding with `status=PREVENTED`

Expected output:
```
[ssrf_metadata] setup: Cilium policy verified
[ssrf_metadata] execute: SSRF job deployed
[ssrf_metadata] polling for findings... (up to 120s)
[ssrf_metadata] found: SSRF: Metadata IP Access - PREVENTED ✅
[ssrf_metadata] verdict: PREVENTED (expected: PREVENTED) - PASS
```

Dashboard → **Scenarios** page: `ssrf_metadata` card shows `PREVENTED` badge in green.

### Step 9 - Run additional scenarios

```bash
make scenario-rbac      # RBAC escalation → DETECTED
make scenario-shadow    # Shadow route → PREVENTED (Cilium ingress policy)
```

Each scenario card on the Scenarios page updates with its verdict badge after the run.

---

## 3. AWS CloudTrail Connector Demo

**What this proves:** AWS IAM privilege escalation events flow from CloudTrail → EventBridge → Lambda → AIAAP ingest → IAM escalation finding in dashboard.

### Prerequisites
- AWS account with CloudTrail enabled (management events)
- AWS CLI configured (`aws sts get-caller-identity` works)
- AWS SAM CLI (`brew install aws-sam-cli` or `pip install aws-sam-cli`)
- AIAAP SaaS control plane running (`make up`)
- AIAAP ingest reachable from AWS Lambda (ngrok or deployed URL)

### Step 1 - Bootstrap a tenant API key

```bash
make tenant-bootstrap TENANT=aws-demo
```

Output:
```
✅ Tenant 'aws-demo' provisioned successfully.

  AIAAP_TENANT_ID=aws-demo
  AIAAP_API_KEY=<your-key>

⚠️  This key will NOT be shown again.
```

Copy the `AIAAP_API_KEY` value.

### Step 2 - Expose ingest locally (if not deployed)

If testing with local docker-compose, expose the ingest service with ngrok:

```bash
ngrok http 8100
# Forwarding: https://abc123.ngrok.io → localhost:8100
```

Use the ngrok URL as `AiAAPIngestUrl`.

### Step 3 - Deploy the Lambda forwarder

```bash
cd connectors/aws/cloudtrail_forwarder

sam build

sam deploy --guided \
  --parameter-overrides \
    AiAAPIngestUrl=https://abc123.ngrok.io \
    AiAAPApiKey=<your-key-from-step-1> \
    AiAAPTenantId=aws-demo
```

Accept all defaults in the guided deploy. The SAM template creates:
- Lambda function `aiaap-cloudtrail-forwarder`
- EventBridge rule `aiaap-iam-escalation-events` matching IAM actions via CloudTrail

### Step 4 - Trigger a real IAM event

```bash
# Create a test role (this generates a CloudTrail event)
aws iam create-role \
  --role-name aiaap-test-$(date +%s) \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[]}'
```

This triggers the `CreateRole` EventBridge pattern → Lambda is invoked → POST to AIAAP ingest.

### Step 5 - Verify in dashboard

Wait ~15 seconds (correlation loop), then open **http://localhost:8501** → **Cloud Coverage** (page 7).

Expected:
- Connector status: `🟢 Connected`
- Cloud Events (last hour): ≥1
- IAM Findings: `1` - "IAM Privilege Escalation: CreateRole (us-east-1)"

### Step 6 - Test with synthetic event (no AWS needed)

Skip steps 2–4 if you just want to see the CloudTrail → finding pipeline:

```bash
make demo-ingest-iam
```

This POSTs a pre-built CloudTrail JSON payload directly to local ingest.

### Cleanup

```bash
# Delete the test role
aws iam delete-role --role-name aiaap-test-<timestamp>

# Remove the Lambda + EventBridge rule
cd connectors/aws/cloudtrail_forwarder && sam delete
```

---

---

## 4. Intent Integrity Demo

**What this proves:** The Intent Integrity capability - envelope declaration, boundary violation detection, drift scoring, and blast radius tracking - all surfaced on three new dashboard pages.

**Time required:** ~5 minutes (SaaS only, no K8s or AWS needed)

### Prerequisites

- AIAAP control plane running (`make up`, all services green)
- Dashboard open at **http://localhost:8501**

---

### Step 1 - Inject the `intent_mismatch_exfil` scenario

```bash
make scenario-intent-mismatch
```

This injects three OTel spans:
1. **Span 1** declares intent: label=`document_summarizer`, allowed_tools=`["summarize_doc"]`, max_privilege=`low`
2. **Span 2** violates the envelope: tool=`fetch_url`, destination=`203.0.113.99` (external IP)
3. **Span 3** violates privilege tier: tool=`read_secrets` (high privilege)

The normalizer extracts the SDK intent envelope from Span 1 and stores it immediately.

---

### Step 2 - Verify the envelope was registered

Navigate to **http://localhost:8501 → Intent Integrity** (page 11).

Expected:
- **Active Envelopes**: 1
- Envelope card for `scenario-intent-mismatch-agent` showing:
  - Label: `document_summarizer`
  - Allowed Tools: `summarize_doc`
  - Allowed Destinations: `internal-docs.svc, *.internal`
  - Max Privilege: `low`
  - Created by: `sdk`

---

### Step 3 - Wait for the intent integrity loop

The intent loop runs every 120 seconds (with a 60s offset from startup).

```bash
# Check the detections service logs to watch it fire
docker compose -f saas/docker-compose.yml logs -f detections
# Look for: intent_analysis_complete violations=1 ...
```

After 1–3 minutes, **refresh** the Intent Integrity page.

Expected:
- **Boundary Violations (24h)**: ≥ 1
- Violation entry: `[HIGH] Intent Boundary Violation - scenario-intent-mismatch-agent`

---

### Step 4 - Run the `gradual_privilege_creep` scenario

```bash
make scenario-priv-creep
```

This injects 3 benign spans followed by 7 privileged tool calls, driving `privileged_ratio` far above baseline.

After the next behavioral loop cycle (up to 5 minutes), navigate to **Drift Timeline** (page 12).

Expected:
- Drift score timeline shows a spike for `scenario-priv-creep-agent`
- Feature breakdown: `Privileged Ratio (z_priv)` is the dominant contributor

---

### Step 5 - Explore the Blast Radius page

Navigate to **Blast Radius** (page 13).

After the intent loop runs, you will see:
- Bar chart: blast radius scores per agent
- Growth timeline: blast score over 24h for selected agents
- Component breakdown: destinations, resources, privileged edges, new edges

---

### Step 6 - Create a UI envelope (manual)

On the **Intent Integrity** page, expand **"Create Intent Envelope (UI)"**:

- Agent: select any registered principal
- Intent Label: `read_only_task`
- Allowed Tools: `read_file, summarize_doc`
- Allowed Destinations: `*.internal`
- Max Privilege: `low`
- TTL: `8` hours
- Click **Create Envelope**

The new envelope appears in the Active Envelopes section with `created_by: UI`.

---

### Step 7 - Review the full narrative

| Page | What you see |
|---|---|
| 11 Intent Integrity | Envelope registry, violation list, KPI cards |
| 12 Drift Timeline | Drift score spikes driven by privilege escalation |
| 13 Blast Radius | Access graph expansion alerts |
| 06 Findings | `intent_boundary` and `intent_drift` findings alongside SSRF and IAM findings |
| 02 Agents | Risk score reflects both behavioral anomaly and intent integrity signals |

---

## Resetting State

```bash
# Wipe all data (findings, events, principals) and restart fresh
make down
make up
# Database volume is wiped on 'make clean'

# Full reset including volumes:
make clean
make up
```
