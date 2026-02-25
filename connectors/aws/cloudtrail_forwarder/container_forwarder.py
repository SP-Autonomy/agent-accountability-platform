"""
AIAAP AWS CloudTrail Forwarder - Container Mode
================================================
Alternative to Lambda for customers who prefer ECS/Fargate or standalone containers.
Polls CloudTrail lookup_events API on a configurable interval and forwards new
events to the AIAAP ingest service.

Environment variables:
  AIAAP_INGEST_URL      - Base URL of AIAAP ingest service
  AIAAP_API_KEY         - API key for authentication
  AIAAP_TENANT_ID       - Tenant identifier for this AWS account
  AWS_REGION            - AWS region to poll (default: us-east-1)
  POLL_INTERVAL_SECONDS - How often to poll CloudTrail (default: 60)
  CLOUDTRAIL_EVENT_NAMES - Comma-separated list of event names to filter (optional)

AWS permissions required on the container's IAM role:
  cloudtrail:LookupEvents
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
import requests

from normalizer import normalize_cloudtrail_event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("aiaap-cloudtrail-forwarder")

AIAAP_INGEST_URL = os.environ["AIAAP_INGEST_URL"].rstrip("/")
AIAAP_API_KEY = os.environ.get("AIAAP_API_KEY", "")
AIAAP_TENANT_ID = os.environ.get("AIAAP_TENANT_ID", "default")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))
INGEST_ENDPOINT = f"{AIAAP_INGEST_URL}/api/events"

# Default IAM escalation event filter. Override via CLOUDTRAIL_EVENT_NAMES env var.
DEFAULT_EVENT_NAMES = [
    "CreatePolicyVersion",
    "AttachRolePolicy",
    "PutRolePolicy",
    "UpdateAssumeRolePolicy",
    "CreateRole",
    "PassRole",
    "CreateClusterRoleBinding",  # K8s RBAC if using EKS audit
    "PutGroupPolicy",
    "AddUserToGroup",
]

_event_names_env = os.environ.get("CLOUDTRAIL_EVENT_NAMES", "")
EVENT_NAMES = (
    [e.strip() for e in _event_names_env.split(",") if e.strip()]
    if _event_names_env
    else DEFAULT_EVENT_NAMES
)


def poll_once(client, start_time: datetime) -> datetime:
    """
    Poll CloudTrail for events since start_time.
    Returns the timestamp of the latest event seen (for next poll window).
    """
    latest = start_time
    paginator = client.get_paginator("lookup_events")

    for event_name in EVENT_NAMES:
        try:
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start_time,
                EndTime=datetime.now(tz=timezone.utc),
            )
            for page in pages:
                for ct_event_record in page.get("Events", []):
                    # CloudTrail lookup_events returns events with a CloudTrailEvent JSON string
                    raw_str = ct_event_record.get("CloudTrailEvent", "{}")
                    ct_event = json.loads(raw_str)

                    event_time = ct_event_record.get("EventTime")
                    if event_time and event_time > latest:
                        latest = event_time

                    forward_event(ct_event)
        except Exception as exc:
            logger.error("poll_error", event_name=event_name, error=str(exc))

    return latest


def forward_event(ct_event: dict) -> None:
    """Normalize and POST a CloudTrail event to AIAAP ingest."""
    payload = normalize_cloudtrail_event(ct_event, AIAAP_TENANT_ID)
    event_name = ct_event.get("eventName", "unknown")
    try:
        resp = requests.post(
            INGEST_ENDPOINT,
            json=payload,
            headers={
                "X-Api-Key": AIAAP_API_KEY,
                "X-Tenant-Id": AIAAP_TENANT_ID,
            },
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("forwarded", event_name=event_name, status=resp.status_code)
    except Exception as exc:
        logger.error("forward_failed", event_name=event_name, error=str(exc))


def run():
    """Main poll loop. Runs indefinitely."""
    logger.info(
        "starting_cloudtrail_forwarder",
        region=AWS_REGION,
        poll_interval=POLL_INTERVAL,
        ingest_url=AIAAP_INGEST_URL,
        tenant_id=AIAAP_TENANT_ID,
        event_names=EVENT_NAMES,
    )

    client = boto3.client("cloudtrail", region_name=AWS_REGION)
    # Start from POLL_INTERVAL seconds ago to catch any events during startup
    last_poll_time = datetime.now(tz=timezone.utc) - timedelta(seconds=POLL_INTERVAL)

    while True:
        logger.info("polling", since=last_poll_time.isoformat())
        try:
            last_poll_time = poll_once(client, last_poll_time)
        except Exception as exc:
            logger.error("poll_cycle_error", error=str(exc))
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
