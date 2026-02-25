"""
AIAAP Reference Tools Service
-------------------------------
Provides tool endpoints used by the orchestrator. Every tool function
is wrapped with @trace_tool_call so the SDK emits tool_call_executed spans
with the correct AIAAP semantic attributes.

Endpoints:
  GET  /customer/{customer_id}   - customer record retrieval
  GET  /search?q=...             - document search
  POST /fetch                    - URL fetch (high-risk: can be used for SSRF)
  GET  /health
"""

import os
import logging

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from pydantic import BaseModel

from connectors.code.otel_sdk_python.tracer import init_tracer
from connectors.code.otel_sdk_python.middleware import AiAAPMiddleware
from connectors.code.otel_sdk_python.decorators import trace_tool_call
from connectors.code.otel_sdk_python.attributes import (
    ATTR_DESTINATION_HOST,
    ATTR_RISK_FLAGS,
    SPAN_TOOL_CALL_EXECUTED,
)

import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_ID      = os.getenv("AGENT_ID",     "tools-service")
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://aiaap-otel-collector:4317")

init_tracer(service_name="aiaap-tools", otlp_endpoint=OTLP_ENDPOINT)
HTTPXClientInstrumentor().instrument()

app = FastAPI(title="AIAAP Tools Service", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(AiAAPMiddleware, agent_id=AGENT_ID)
FastAPIInstrumentor.instrument_app(app)

tracer = trace.get_tracer("aiaap-tools")

# ── Fake data store ───────────────────────────────────────────────────────────
CUSTOMERS = {
    "001": {"id": "001", "name": "Acme Corp", "tier": "enterprise", "region": "us-east-1"},
    "002": {"id": "002", "name": "Beta LLC",  "tier": "startup",    "region": "eu-west-1"},
}
DOCS = [
    {"id": "d1", "title": "Security Best Practices", "snippet": "Always rotate credentials..."},
    {"id": "d2", "title": "Agent Identity Guide",     "snippet": "SPIFFE/SPIRE provides workload identity..."},
]


# ── Tool implementations ──────────────────────────────────────────────────────

class FetchRequest(BaseModel):
    url: str


@app.get("/health")
def health():
    return {"status": "healthy", "service": "aiaap-tools"}


@app.get("/customer/{customer_id}")
def get_customer(customer_id: str):
    """Customer record retrieval tool. Emits tool_call_executed span."""
    with tracer.start_as_current_span(SPAN_TOOL_CALL_EXECUTED) as span:
        span.set_attribute("aiaap.tool.name", "get_customer")
        span.set_attribute("aiaap.tool.risk_level", "low")
        span.set_attribute("aiaap.tool.customer_id", customer_id)

        customer = CUSTOMERS.get(customer_id)
        if not customer:
            span.set_attribute("aiaap.tool.result", "not_found")
            raise HTTPException(status_code=404, detail=f"Customer {customer_id} not found")

        span.set_attribute("aiaap.tool.result", "found")
        return customer


@app.get("/search")
def search_docs(q: str = ""):
    """Document search tool. Emits tool_call_executed span."""
    with tracer.start_as_current_span(SPAN_TOOL_CALL_EXECUTED) as span:
        span.set_attribute("aiaap.tool.name", "search_docs")
        span.set_attribute("aiaap.tool.risk_level", "low")
        span.set_attribute("aiaap.tool.query", q[:200])

        results = [d for d in DOCS if q.lower() in d["title"].lower() or q.lower() in d["snippet"].lower()]
        span.set_attribute("aiaap.tool.result_count", len(results))
        return {"results": results, "query": q}


@app.post("/fetch")
async def fetch_url(req: FetchRequest):
    """
    URL fetch tool - HIGH RISK.
    This is the tool that can be abused for SSRF (e.g. fetching metadata IPs).
    The SDK span will capture aiaap.tool.destination_host for detection.
    """
    from urllib.parse import urlparse

    with tracer.start_as_current_span(SPAN_TOOL_CALL_EXECUTED) as span:
        span.set_attribute("aiaap.tool.name", "fetch_url")
        span.set_attribute("aiaap.tool.risk_level", "high")

        try:
            parsed = urlparse(req.url)
            host = parsed.hostname or ""
            span.set_attribute(ATTR_DESTINATION_HOST, host)

            # Flag metadata IP access explicitly so the correlator can detect it
            METADATA_IPS = {"169.254.169.254", "metadata.google.internal", "metadata.internal"}
            if host in METADATA_IPS or (host.startswith("169.254.")):
                span.set_attribute(ATTR_RISK_FLAGS, json.dumps(["metadata_ip_access", "ssrf_risk"]))
                logger.warning("SSRF risk: tool attempting metadata IP fetch: %s", req.url)

            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                resp = await client.get(req.url)
                span.set_attribute("aiaap.tool.http_status", resp.status_code)
                return {"status": resp.status_code, "body": resp.text[:1000], "url": req.url}

        except httpx.ConnectError as exc:
            span.set_attribute("aiaap.tool.result", "connection_blocked")
            # Connection blocked (e.g. by Cilium) - this is the expected SSRF prevention
            return {"status": "blocked", "error": str(exc), "url": req.url}
        except Exception as exc:
            span.set_attribute("aiaap.tool.result", "error")
            raise HTTPException(status_code=500, detail=str(exc))
