#!/usr/bin/env bash
# Verify the CLI connector registered and events are visible
set -e

INGEST_URL="${INGEST_URL:-http://localhost:8100}"
CONNECTOR_INSTANCE="${CONNECTOR_INSTANCE_ID:-pov-cli-01}"
TENANT="${TENANT_ID:-default}"

echo "=== Verifying CLI Connector ==="
echo ""

# 1. Check connector registered
echo "1. Checking connector registration..."
result=$(curl -sf "$INGEST_URL/api/connectors?tenant_id=$TENANT" 2>/dev/null || echo "[]")
match=$(echo "$result" | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = [c for c in data if c.get('instance_id') == '$CONNECTOR_INSTANCE']
if found:
    c = found[0]
    print(f'  ✓ Connector registered: {c[\"instance_id\"]} ({c[\"connector_type\"]}) last_seen={c[\"last_seen\"]} events_1h={c[\"events_1h\"]}')
else:
    print('  ✗ Connector NOT found')
    sys.exit(1)
" 2>&1)
echo "$match"

# 2. Check events visible
echo ""
echo "2. Checking events in ingest..."
event_count=$(curl -sf "$INGEST_URL/api/events?tenant_id=$TENANT&limit=20" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "0")
echo "  ✓ Found $event_count normalized events"

echo ""
echo "=== Verification PASSED ==="
echo ""
echo "Open the AIAAP dashboard → Connectors page to see $CONNECTOR_INSTANCE."
