# AIAAP Connectors Guide

Connectors are lightweight, customer-managed components that collect signals from your environment and forward them to the AIAAP SaaS control plane. They are **completely optional** - the control plane runs without any connectors, and you can inject synthetic events directly for testing.

## How connector tracking works

Connectors **self-register** - no manual registration step needed. When a connector sends its first event to `POST /api/events` (or the first OTel spans arrive at `/otlp/v1/traces`), the ingest service automatically creates a `ConnectorInstance` record. Subsequent events update `last_seen` and `events_1h`.

Pass two optional fields to register your connector:
```json
{
  "source": "ebpf",
  "tenant_id": "default",
  "payload": {...},
  "connector_type": "ebpf",
  "connector_instance_id": "ebpf-sensor-prod-us-east"
}
```

View all registered connectors via the API or dashboard:
```bash
curl http://localhost:8100/api/connectors?tenant_id=default | jq '.[].instance_id'
# → ["ebpf-sensor-prod-us-east", "otel-default", ...]
```

Dashboard: **Connectors** page (page 8) shows health status, last seen, events/hour, and coverage gaps.

---

## Connector Overview

| Connector | Location | Signal type | Deployment |
|---|---|---|---|
| Kubernetes OTel Collector | `connectors/k8s/helm/aiaap-otel-collector/` | OTel spans (agent identity, tool calls) | Helm |
| Kubernetes eBPF Sensor | `connectors/k8s/helm/aiaap-ebpf-sensor/` | Network events (Tetragon kprobe) | Helm DaemonSet |
| Kubernetes Audit Collector | `connectors/k8s/helm/aiaap-k8s-audit/` | K8s audit logs (RBAC, secrets, exec) | Helm, control-plane node |
| AWS CloudTrail | `connectors/aws/cloudtrail_forwarder/` | IAM privilege escalation events | Lambda + EventBridge or container |
| Python OTel SDK | `connectors/code/otel_sdk_python/` | In-process span emission | `pip install` |

All connectors POST to the same ingest API:
```
POST http://<AIAAP_INGEST_URL>/api/events     (eBPF, audit, CloudTrail)
POST http://<AIAAP_INGEST_URL>/otlp/v1/traces (OTel spans via Collector)
```

---

## 1. Kubernetes Connector (Helm)

Deploys three Helm charts to `aiaap-system` namespace in your cluster.

### Prerequisites
- Kubernetes 1.26+
- Helm 3
- Cilium CNI (for eBPF sensor and network enforcement)
- Tetragon (for eBPF events)
- SaaS control plane reachable from the cluster (set `ingestUrl` in Helm values)

### One-command install (kind cluster)

```bash
# Creates kind cluster + installs all dependencies + deploys all connectors
make k8s-full
```

### Manual install (existing cluster)

```bash
# 1. Apply namespaces
kubectl apply -f connectors/k8s/helm/namespaces.yaml

# 2. Deploy OTel Collector
helm upgrade --install aiaap-otel-collector connectors/k8s/helm/aiaap-otel-collector \
  -n aiaap-system --create-namespace \
  --set config.exporters.otlphttp.endpoint=http://<INGEST_HOST>:8100/otlp

# 3. Deploy eBPF sensor (requires Tetragon + Cilium)
helm upgrade --install aiaap-ebpf-sensor connectors/k8s/helm/aiaap-ebpf-sensor \
  -n aiaap-system \
  --set forwarder.ingestUrl=http://<INGEST_HOST>:8100 \
  --set forwarder.tenantId=<TENANT_ID>

# 4. Deploy audit collector
helm upgrade --install aiaap-k8s-audit connectors/k8s/helm/aiaap-k8s-audit \
  -n aiaap-system \
  --set config.ingestUrl=http://<INGEST_HOST>:8100 \
  --set config.tenantId=<TENANT_ID>

# 5. Apply enforcement policies
kubectl apply -f connectors/k8s/helm/aiaap-enforcement/kyverno/
kubectl apply -f connectors/k8s/helm/aiaap-enforcement/cilium/
```

### Verify K8s connector

```bash
# All pods should be Running
kubectl get pods -n aiaap-system

# Check OTel Collector logs - should show "Everything is ready"
kubectl logs -n aiaap-system deploy/aiaap-otel-collector

# Check ingest received events
curl -s http://localhost:8100/api/events?limit=10 | jq '.[].source'
# Should show "otel", "ebpf", "audit"
```

### What each chart collects

**aiaap-otel-collector:**
- Receives OTLP gRPC/HTTP from instrumented apps in the cluster
- The `k8sattributes` processor enriches spans with `k8s.pod.name`, `k8s.namespace.name`, `k8s.serviceaccount.name`
- Forwards to ingest as JSON OTLP over HTTP

**aiaap-ebpf-sensor:**
- `TracingPolicy` applies a `tcp_connect` kprobe via Tetragon
- A Python forwarder DaemonSet tails Tetragon's JSON event log at `/var/run/cilium/tetragon/`
- Filters to watched namespaces (configurable in `values.yaml`)
- Forwards `process_connect` events to ingest

**aiaap-k8s-audit:**
- Runs on the control-plane node (hostPath mount of `/var/log/kubernetes/audit/`)
- Tails the audit log and filters for: `secrets get/list`, `rolebindings create/patch`, `pods/exec create`, `serviceaccounts/token get`
- Forwards matching entries to ingest

---

## 2. AWS CloudTrail Connector

Captures AWS IAM privilege escalation events and forwards them to AIAAP. Detailed guide: [`connectors/aws/cloudtrail_forwarder/README.md`](../connectors/aws/cloudtrail_forwarder/README.md).

### Option A: Lambda + EventBridge (Recommended)

```bash
cd connectors/aws/cloudtrail_forwarder
sam build
sam deploy --guided \
  --parameter-overrides \
    AiAAPIngestUrl=https://<INGEST_HOST> \
    AiAAPApiKey=<API_KEY> \
    AiAAPTenantId=<TENANT_ID>
```

**EventBridge pattern (correct):**
```yaml
detail-type: ["AWS API Call via CloudTrail"]
detail:
  eventSource: ["iam.amazonaws.com"]
  eventName:
    - "CreatePolicyVersion"
    - "AttachRolePolicy"
    - "PutRolePolicy"
    - "UpdateAssumeRolePolicy"
    - "CreateRole"
    - "PassRole"
```

Note: The pattern uses `detail.eventSource` and `detail.eventName`, NOT `source: ["aws.iam"]`.

### Option B: Container (ECS/Fargate)

```bash
docker build -t aiaap-cloudtrail-forwarder connectors/aws/cloudtrail_forwarder/

docker run \
  -e AIAAP_INGEST_URL=https://<INGEST_HOST> \
  -e AIAAP_API_KEY=<API_KEY> \
  -e AIAAP_TENANT_ID=<TENANT_ID> \
  -e AWS_REGION=us-east-1 \
  -e POLL_INTERVAL_SECONDS=60 \
  aiaap-cloudtrail-forwarder
```

Required IAM policy for container mode:
```json
{"Statement": [{"Effect": "Allow", "Action": ["cloudtrail:LookupEvents"], "Resource": "*"}]}
```

### Verify CloudTrail connector

```bash
# Inject a test IAM event
make demo-ingest-iam

# Wait 15 seconds, then check
curl -s "http://localhost:8200/api/findings?scenario_id=iam_escalation" | jq '.[0].title'
# "IAM Privilege Escalation: AttachRolePolicy on prod-eks-node-role (us-east-1)"

# Check cloud events in ingest
curl -s "http://localhost:8100/api/events?source=cloud&limit=5" | jq '.[].event_type'
# "cloud.iam.attach_role_policy"
```

### Normalization mapping

| CloudTrail field | AIAAP NormalizedEvent field | Example |
|---|---|---|
| `eventName` | `tool_name` | `AttachRolePolicy` |
| `eventSource` → snake → prefix | `event_type` | `cloud.iam.attach_role_policy` |
| `userIdentity.arn` | `payload._aiaap_actor_arn` | `arn:aws:iam::123::user/attacker` |
| `requestParameters.roleName` | `dest` | `prod-eks-node-role` |
| always `"cloud"` | `source` | `cloud` |

---

## 3. Python OTel SDK Connector

For instrumenting Python agentic apps to emit AIAAP-compatible spans.

### Install

```bash
pip install -e connectors/code/otel_sdk_python/
```

### Usage

```python
from connectors.code.otel_sdk_python.tracer import init_tracer
from connectors.code.otel_sdk_python.decorators import trace_tool_call, trace_agent_step
from connectors.code.otel_sdk_python.attributes import ATTR_TOOL_NAME, ATTR_DESTINATION_HOST

# Initialize (call once at startup)
init_tracer(
    service_name="my-agent",
    otlp_endpoint="http://localhost:4317",  # or the OTel Collector in-cluster
)

# Instrument an agent step
@trace_agent_step("prompt_received")
async def handle_prompt(prompt: str):
    ...

# Instrument a tool call
@trace_tool_call(tool_name="fetch_url", risk_level="high")
async def fetch(url: str):
    ...
```

Span names emitted: `prompt_received`, `tool_call_requested`, `tool_call_executed`, `retrieval_query`, `retrieval_result`, `response_generated`.

AIAAP attributes on spans:
- `aiaap.agent.id` - set via `AGENT_ID` env var or `AiAAPMiddleware`
- `aiaap.tool.name` - set by `@trace_tool_call`
- `aiaap.tool.destination_host` - set manually or via middleware
- `aiaap.risk.flags` - JSON array string (e.g. `["metadata_ip_access"]`)
- `aiaap.jit.grant_id` - set via `attach_jit_context(grant_id, purpose)`

### FastAPI auto-instrumentation

```python
from connectors.code.otel_sdk_python.middleware import AiAAPMiddleware

app = FastAPI()
app.add_middleware(AiAAPMiddleware)
# Automatically attaches AGENT_ID, NAMESPACE, SERVICE_ACCOUNT env vars to every span
```

### Verify SDK connector

After running your instrumented app, check:
```bash
# Agents should appear
curl -s http://localhost:8300/api/principals | jq '.[].name'

# Tool usages should populate
curl -s http://localhost:8100/api/tool-usages | jq '.[0]'
```

---

## Multi-Tenant API Key Configuration

When `REQUIRE_API_KEY=true` is set in the control plane:

### 1. Bootstrap a tenant key

```bash
python saas/scripts/bootstrap_tenant.py --tenant-id acme --description "Acme Corp"
# Prints: AIAAP_API_KEY=<key>  (one-time, store securely)
```

### 2. Configure connectors

All connectors accept API key via the `X-Api-Key` HTTP header:

**K8s connector** - set in Helm values:
```yaml
# connectors/k8s/helm/aiaap-otel-collector/values.yaml
tenantId: acme
apiKey: <key>    # passed as env var to the collector exporter headers
```

**CloudTrail Lambda** - SAM parameter:
```bash
sam deploy --parameter-overrides AiAAPApiKey=<key> AiAAPTenantId=acme
```

**curl / manual:**
```bash
curl -X POST http://localhost:8100/api/events \
  -H "X-Api-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"source":"cloud","payload":{...}}'
```

The control plane derives `tenant_id` from the key record - callers cannot pass a different `X-Tenant-Id` to spoof another tenant.

---

## Connector Health Checks

```bash
# List all registered connectors + last seen + events/1h
curl -s "http://localhost:8100/api/connectors?tenant_id=default" | jq '.[] | {instance_id, connector_type, last_seen, events_1h}'

# Quick source-level check: are events from each type reaching ingest?
curl -s "http://localhost:8100/api/events?source=otel&limit=1"   | jq 'length'
curl -s "http://localhost:8100/api/events?source=ebpf&limit=1"   | jq 'length'
curl -s "http://localhost:8100/api/events?source=audit&limit=1"  | jq 'length'
curl -s "http://localhost:8100/api/events?source=cloud&limit=1"  | jq 'length'

# POV smoke test (CLI connector - zero infrastructure)
make pov-cli
```

Or use the **Connectors** dashboard page (page 8) which shows connector health, coverage gaps, and quick-start commands.

## Quick-start: POV environments

| Environment | Command | Prerequisite |
|---|---|---|
| CLI (zero infra) | `make pov-cli` | `make up` |
| Kubernetes | `make pov-k8s` | kind + helm |
| AWS CloudTrail | `make pov-cloud` | AWS CLI + SAM |

Sample environments under `examples/`:
- `examples/customer_env_cli/` - send events via curl, verify connector registers
- `examples/customer_env_k8s/` - kind cluster + OTel collector + sample agent
- `examples/customer_env_cloud/` - SAM deploy CloudTrail forwarder + generate events
