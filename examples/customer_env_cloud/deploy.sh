#!/usr/bin/env bash
# Deploy AWS CloudTrail connector Lambda via SAM
set -e

: "${AIAAP_INGEST_URL:?Set AIAAP_INGEST_URL (e.g. http://your-ingest:8100)}"
: "${DEPLOY_BUCKET:?Set DEPLOY_BUCKET (S3 bucket for SAM artifacts)}"
: "${AWS_REGION:=us-east-1}"
: "${AIAAP_TENANT_ID:=default}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORWARDER_DIR="$REPO_ROOT/connectors/aws/cloudtrail_forwarder"

echo "=== AIAAP CloudTrail Connector POV ==="
echo "Ingest:  $AIAAP_INGEST_URL"
echo "Region:  $AWS_REGION"
echo "Bucket:  $DEPLOY_BUCKET"
echo ""

cd "$FORWARDER_DIR"

echo "1. Building SAM..."
sam build

echo "2. Deploying to AWS..."
sam deploy \
  --stack-name aiaap-cloudtrail-forwarder \
  --s3-bucket "$DEPLOY_BUCKET" \
  --region "$AWS_REGION" \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset \
  --parameter-overrides \
    "AiAAPIngestUrl=$AIAAP_INGEST_URL" \
    "AiAAPTenantId=$AIAAP_TENANT_ID"

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Next: run ./generate_events.sh to create CloudTrail events"
echo "Then: run ./verify.sh to confirm AIAAP received them"
