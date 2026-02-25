#!/usr/bin/env bash
# Send sample events from CLI - registers a "cli" connector instance
set -e

INGEST_URL="${INGEST_URL:-http://localhost:8100}"
CONNECTOR_INSTANCE="${CONNECTOR_INSTANCE_ID:-pov-cli-01}"
TENANT="${TENANT_ID:-default}"

echo "=== AIAAP CLI Connector POV ==="
echo "Ingest URL: $INGEST_URL"
echo "Connector:  $CONNECTOR_INSTANCE"
echo ""

post_event() {
  local source="$1"
  local connector_type="$2"
  local payload="$3"
  curl -sf -X POST "$INGEST_URL/api/events" \
    -H "Content-Type: application/json" \
    -d "{
      \"source\": \"$source\",
      \"tenant_id\": \"$TENANT\",
      \"connector_type\": \"$connector_type\",
      \"connector_instance_id\": \"$CONNECTOR_INSTANCE\",
      \"payload\": $payload
    }" > /dev/null
  echo "  ✓ $source / $connector_type event sent"
}

# 1. OTel-style agent span
post_event "otel" "cli" '{"event_type":"tool_call_executed","agent_id":"pov-agent-01","tool_name":"search_docs"}'

# 2. OTel-style fetch_url span
post_event "otel" "cli" '{"event_type":"tool_call_executed","agent_id":"pov-agent-01","tool_name":"fetch_url","destination_host":"api.example.com"}'

# 3. eBPF-style network event
post_event "ebpf" "cli" '{"type":"process_connect","destination_ip":"203.0.113.10","destination_port":443,"namespace":"ai-app","pod_name":"agent-pod-abc"}'

# 4. Audit-style event
post_event "audit" "cli" '{"verb":"get","objectRef":{"resource":"secrets","namespace":"ai-app"},"user":{"username":"system:serviceaccount:ai-app:agent-sa"}}'

# 5. Cloud-style event
post_event "cloud" "cli" '{"eventName":"ListRoles","eventSource":"iam.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/pov-user"}}'

echo ""
echo "All 5 events sent successfully."
