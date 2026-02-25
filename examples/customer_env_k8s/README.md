# Customer POV: Kubernetes Connector

Stand up a local Kubernetes environment with the AIAAP OTel connector and a sample
instrumented agent in under 10 minutes.

## Prerequisites

- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) (Kubernetes in Docker)
- [Helm 3](https://helm.sh/docs/intro/install/)
- Docker
- AIAAP control plane running: `make up` (in repo root)

## Quick start

```bash
cd examples/customer_env_k8s
./deploy.sh
```

This will:
1. Create a `kind` cluster named `aiaap-pov`
2. Deploy the AIAAP OTel Collector Helm chart into `aiaap-system`
3. Build and deploy the sample agent to the `ai-app` namespace
4. Print status and dashboard URL

## What the sample agent does

`sample_agent/app.py` is a minimal FastAPI service with OTel instrumentation:
- Emits `tool_call_executed` spans with `aiaap.tool.name` attribute
- Sends spans to the in-cluster OTel Collector
- The OTel Collector forwards them to the AIAAP ingest service (via host gateway)

## Verify

After `./deploy.sh`, check:
```bash
# Connector should auto-register
curl -s "http://localhost:8100/api/connectors?tenant_id=default" | jq '.[].connector_type'
# → "k8s_otel"

# Agent should appear
curl -s "http://localhost:8300/api/principals" | jq '.[].name'
# → "pov-k8s-agent"
```

Open the AIAAP dashboard → **Connectors** page → see `otel-default` (or `aiaap-pov-otel`) as healthy.

## Clean up

```bash
kind delete cluster --name aiaap-pov
```
