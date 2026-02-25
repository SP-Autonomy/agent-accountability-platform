# AIAAP AWS CloudTrail Connector

Forwards AWS IAM privilege escalation events from CloudTrail to the AIAAP SaaS ingest service.
Detected actions trigger the `iam_escalation` detection rule and appear in the Cloud Coverage dashboard page.

## Detected Actions

| Action | Severity | Why it matters |
|---|---|---|
| `AttachRolePolicy` | HIGH | Grants a role broad permissions |
| `PutRolePolicy` | HIGH | Embeds inline policy on a role |
| `CreatePolicyVersion` | HIGH | Replaces a policy with elevated perms |
| `UpdateAssumeRolePolicy` | HIGH | Changes who can assume a role |
| `CreateRole` | HIGH | New role may have over-broad trust |
| `PassRole` | HIGH | Allows service to assume another role |
| `PutGroupPolicy` | HIGH | Inline policy added to IAM group |
| `AddUserToGroup` | HIGH | User gains all group permissions |

## Event Flow

```
AWS IAM API call
      │
      ▼
CloudTrail (management event)
      │
      ▼
EventBridge (rule: detail.eventSource = iam.amazonaws.com, detail.eventName in [...])
      │
      ▼
Lambda / Container Forwarder
      │  normalize: actor ARN → principal, role/policy → dest
      ▼
AIAAP Ingest API  POST /api/events  {source: "cloud"}
      │
      ▼
Correlation Engine (10s loop) → Finding: iam_escalation DETECTED
      │
      ▼
Dashboard → Cloud Coverage page
```

## Option A: Lambda + EventBridge (Recommended)

### Prerequisites
- AWS SAM CLI: `brew install aws-sam-cli`
- Active CloudTrail in the account (management events enabled)
- AIAAP tenant API key (from `make tenant-bootstrap TENANT=<id>`)

### Deploy

```bash
cd connectors/aws/cloudtrail_forwarder

# Build the Lambda package
sam build

# Deploy (interactive first time)
sam deploy --guided \
  --parameter-overrides \
    AiAAPIngestUrl=https://ingest.aiaap.example.com \
    AiAAPApiKey=<your-api-key> \
    AiAAPTenantId=<your-tenant-id>

# Or non-interactive after first deploy
sam deploy
```

### Required IAM Permissions (for SAM deployer)
```json
{
  "Action": [
    "cloudformation:*",
    "lambda:*",
    "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
    "iam:PassRole", "iam:GetRole",
    "events:PutRule", "events:PutTargets",
    "s3:*"
  ]
}
```

### Test

```bash
# Simulate an IAM escalation event via CloudTrail (generates a real CloudTrail record)
aws iam create-role \
  --role-name aiaap-test-escalation-$(date +%s) \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[]}'

# Or inject a synthetic event directly to AIAAP (no AWS needed):
make demo-ingest-iam
```

## Option B: Container Forwarder (ECS/Fargate)

For customers who cannot use Lambda or prefer a long-running container.

### Build & Run

```bash
cd connectors/aws/cloudtrail_forwarder

docker build -t aiaap-cloudtrail-forwarder .

docker run -e AIAAP_INGEST_URL=https://ingest.aiaap.example.com \
           -e AIAAP_API_KEY=<key> \
           -e AIAAP_TENANT_ID=<tenant> \
           -e AWS_REGION=us-east-1 \
           -e POLL_INTERVAL_SECONDS=60 \
           -e AWS_ACCESS_KEY_ID=<key> \
           -e AWS_SECRET_ACCESS_KEY=<secret> \
           aiaap-cloudtrail-forwarder
```

### Required IAM Policy for Container
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["cloudtrail:LookupEvents"],
    "Resource": "*"
  }]
}
```

### ECS Task Definition (excerpt)
```json
{
  "containerDefinitions": [{
    "name": "aiaap-cloudtrail-forwarder",
    "image": "<ecr-repo>/aiaap-cloudtrail-forwarder:latest",
    "environment": [
      {"name": "AIAAP_INGEST_URL", "value": "https://ingest.aiaap.example.com"},
      {"name": "AIAAP_TENANT_ID", "value": "acme"},
      {"name": "AWS_REGION", "value": "us-east-1"},
      {"name": "POLL_INTERVAL_SECONDS", "value": "60"}
    ],
    "secrets": [
      {"name": "AIAAP_API_KEY", "valueFrom": "arn:aws:secretsmanager:...:aiaap-api-key"}
    ]
  }]
}
```

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `AIAAP_INGEST_URL` | Yes | - | AIAAP ingest base URL |
| `AIAAP_API_KEY` | Yes (if `REQUIRE_API_KEY=true`) | `""` | Tenant API key |
| `AIAAP_TENANT_ID` | Yes | `default` | Tenant ID (derived from key in prod) |
| `AWS_REGION` | Container only | `us-east-1` | AWS region to poll |
| `POLL_INTERVAL_SECONDS` | Container only | `60` | Poll frequency |
| `CLOUDTRAIL_EVENT_NAMES` | Container only | see defaults | Comma-separated event filter |
