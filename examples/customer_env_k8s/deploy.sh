#!/usr/bin/env bash
# Deploy AIAAP K8s connector POV environment
# Creates a kind cluster and deploys the OTel collector + sample agent
set -e

CLUSTER_NAME="aiaap-pov"
INGEST_URL="${INGEST_URL:-http://host.docker.internal:8100}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== AIAAP K8s Connector POV ==="
echo "Cluster: $CLUSTER_NAME"
echo "Ingest:  $INGEST_URL"
echo ""

# 1. Create kind cluster
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "1. Cluster '$CLUSTER_NAME' already exists - reusing"
else
  echo "1. Creating kind cluster '$CLUSTER_NAME'..."
  kind create cluster --name "$CLUSTER_NAME"
fi

# 2. Create namespaces
echo "2. Creating namespaces..."
kubectl create namespace aiaap-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace ai-app       --dry-run=client -o yaml | kubectl apply -f -

# 3. Deploy OTel Collector
echo "3. Deploying AIAAP OTel Collector..."
helm upgrade --install aiaap-otel-collector \
  "$REPO_ROOT/connectors/k8s/helm/aiaap-otel-collector" \
  --namespace aiaap-system \
  --set ingestEndpoint="${INGEST_URL}/otlp" \
  --set tenantId="default" \
  --wait --timeout=120s

echo "   OTel Collector deployed."

# 4. Build and deploy sample agent
echo "4. Building sample agent..."
AGENT_DIR="$REPO_ROOT/examples/customer_env_k8s/sample_agent"
docker build -t aiaap-pov-agent:latest "$AGENT_DIR" --quiet

echo "   Loading image into kind cluster..."
kind load docker-image aiaap-pov-agent:latest --name "$CLUSTER_NAME"

echo "   Deploying sample agent to ai-app namespace..."
kubectl -n ai-app apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pov-agent
  namespace: ai-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pov-agent
  template:
    metadata:
      labels:
        app: pov-agent
    spec:
      containers:
        - name: pov-agent
          image: aiaap-pov-agent:latest
          imagePullPolicy: Never
          env:
            - name: AGENT_ID
              value: "pov-k8s-agent"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://aiaap-otel-collector.aiaap-system.svc.cluster.local:4317"
          ports:
            - containerPort: 8080
EOF

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Verify:"
echo "  curl -s 'http://localhost:8100/api/connectors?tenant_id=default' | jq '.[].connector_type'"
echo "  curl -s 'http://localhost:8300/api/principals' | jq '.[].name'"
echo ""
echo "Dashboard: http://localhost:8501 → Connectors page"
echo "Clean up:  kind delete cluster --name $CLUSTER_NAME"
