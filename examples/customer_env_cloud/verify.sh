#!/usr/bin/env bash
# Verify AIAAP received CloudTrail events and the connector registered
set -e

: "${AIAAP_INGEST_URL:=http://localhost:8100}"
: "${AIAAP_TENANT_ID:=default}"

echo "=== Verifying CloudTrail Connector ==="
echo ""

# 1. Check connector instances
echo "1. Registered connectors:"
curl -sf "$AIAAP_INGEST_URL/api/connectors?tenant_id=$AIAAP_TENANT_ID" 2>/dev/null | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
ct_connectors = [c for c in data if c.get('connector_type') == 'cloudtrail']
if ct_connectors:
    for c in ct_connectors:
        print(f'  ✓ cloudtrail connector: {c[\"instance_id\"]} last_seen={c[\"last_seen\"]} events_1h={c[\"events_1h\"]}')
else:
    print('  ℹ No cloudtrail connector registered yet (may take 1-2 min after events)')
" 2>/dev/null || echo "  ✗ Could not reach ingest at $AIAAP_INGEST_URL"

# 2. Check cloud events
echo ""
echo "2. Cloud events in ingest:"
count=$(curl -sf "$AIAAP_INGEST_URL/api/events?source=cloud&limit=5" 2>/dev/null | \
  python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
echo "  ✓ $count cloud events received"

echo ""
echo "Dashboard: http://localhost:8501 → Connectors page"
