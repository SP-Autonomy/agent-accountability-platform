# Customer POV: AWS CloudTrail Connector

Connect AWS CloudTrail to AIAAP and see IAM privilege escalation events in 3 steps.

## Prerequisites

- AWS CLI configured (`aws configure`)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- AIAAP control plane reachable (set `AIAAP_INGEST_URL`)
- An S3 bucket for SAM deployment artifacts: `DEPLOY_BUCKET`

## Quick start

```bash
cd examples/customer_env_cloud

# 1. Configure
cp .env.example .env
# Edit .env: set AIAAP_INGEST_URL, DEPLOY_BUCKET, AWS_REGION

source .env

# 2. Deploy Lambda forwarder
./deploy.sh

# 3. Generate CloudTrail events
./generate_events.sh

# 4. Verify AIAAP received them
./verify.sh
```

## What it does

1. `deploy.sh` - builds and deploys the CloudTrail Lambda forwarder via SAM
2. `generate_events.sh` - runs `aws iam list-roles` (generates a ListRoles CloudTrail event)
3. AIAAP receives the event at `POST /api/events` with `connector_type: "cloudtrail"`
4. `verify.sh` - checks `GET /api/connectors` shows the CloudTrail instance

## Manual deploy (no SAM)

If you prefer a container-based forwarder (ECS/Fargate):
```bash
docker run \
  -e AIAAP_INGEST_URL=http://<your-ingest>:8100 \
  -e AIAAP_TENANT_ID=default \
  -e AWS_REGION=us-east-1 \
  -e POLL_INTERVAL_SECONDS=60 \
  $(docker build -q connectors/aws/cloudtrail_forwarder/)
```

## Clean up

```bash
aws cloudformation delete-stack --stack-name aiaap-cloudtrail-forwarder
```
