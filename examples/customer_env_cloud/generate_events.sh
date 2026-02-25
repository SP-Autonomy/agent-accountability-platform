#!/usr/bin/env bash
# Generate CloudTrail events by making IAM API calls
# These will be captured by the Lambda forwarder and sent to AIAAP
set -e

: "${AWS_REGION:=us-east-1}"

echo "=== Generating CloudTrail Events ==="
echo "Region: $AWS_REGION"
echo ""

echo "1. aws iam list-roles (generates ListRoles CloudTrail event)..."
aws iam list-roles --max-items 1 --region "$AWS_REGION" > /dev/null
echo "   ✓ ListRoles event generated"

echo "2. aws iam list-policies (generates ListPolicies CloudTrail event)..."
aws iam list-policies --scope Local --max-items 1 --region "$AWS_REGION" > /dev/null
echo "   ✓ ListPolicies event generated"

echo ""
echo "CloudTrail events generated. The Lambda forwarder will deliver them to AIAAP"
echo "within the next EventBridge polling interval (typically 1-2 minutes)."
echo ""
echo "Run ./verify.sh after ~2 minutes to confirm AIAAP received the events."
