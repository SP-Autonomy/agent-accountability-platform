"""
AIAAP AWS CloudTrail Forwarder - Lambda Handler
================================================
Triggered by an EventBridge rule that matches CloudTrail API calls on IAM.
Normalizes the CloudTrail event and POSTs it to the AIAAP ingest service.

Environment variables (set in SAM template or Lambda console):
  AIAAP_INGEST_URL   - Base URL of AIAAP ingest service (e.g. https://ingest.aiaap.example.com)
  AIAAP_API_KEY      - API key for authentication (X-Api-Key header)
  AIAAP_TENANT_ID    - Tenant identifier for this AWS account

EventBridge event structure received:
  {
    "version": "0",
    "id": "...",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "detail": { <CloudTrail event> }
  }
"""

import json
import logging
import os

import urllib.request

from normalizer import normalize_cloudtrail_event

logger = logging.getLogger()
logger.setLevel(logging.INFO)

AIAAP_INGEST_URL = os.environ["AIAAP_INGEST_URL"].rstrip("/")
AIAAP_API_KEY = os.environ.get("AIAAP_API_KEY", "")
AIAAP_TENANT_ID = os.environ.get("AIAAP_TENANT_ID", "default")

INGEST_ENDPOINT = f"{AIAAP_INGEST_URL}/api/events"


def lambda_handler(event: dict, context) -> dict:
    """
    Main Lambda entrypoint. Receives EventBridge event wrapping a CloudTrail record.
    """
    detail = event.get("detail")
    if not detail:
        logger.warning("event_missing_detail", event_keys=list(event.keys()))
        return {"statusCode": 400, "body": "missing detail"}

    event_name = detail.get("eventName", "unknown")
    logger.info("processing_cloudtrail_event", event_name=event_name,
                account=detail.get("recipientAccountId"),
                region=detail.get("awsRegion"))

    payload = normalize_cloudtrail_event(detail, AIAAP_TENANT_ID)

    try:
        _post_to_ingest(payload)
        logger.info("event_forwarded", event_name=event_name)
        return {"statusCode": 200, "body": "forwarded"}
    except Exception as exc:
        logger.error("forward_failed", error=str(exc), event_name=event_name)
        raise


def _post_to_ingest(payload: dict) -> None:
    """POST normalized event to AIAAP ingest API using stdlib urllib (no requests dep)."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        INGEST_ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": AIAAP_API_KEY,
            "X-Tenant-Id": AIAAP_TENANT_ID,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"Ingest returned HTTP {resp.status}")
