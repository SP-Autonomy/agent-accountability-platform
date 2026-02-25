"""
AIAAP Reference Agentic Orchestrator
-------------------------------------
A minimal FastAPI agent that receives chat prompts, dispatches tool calls,
and returns responses. Every workflow step is wrapped with AIAAP SDK spans
so the OTel Collector can forward them to the ingest service.

Spans emitted per request:
  prompt_received       → root span for the whole request
  tool_call_requested   → child span when a tool is about to be called
  tool_call_executed    → child span inside the tools service (its own span)
  response_generated    → child span for the final response assembly
"""

import os
import json
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
from connectors.code.otel_sdk_python.attributes import (
    ATTR_AGENT_ID, ATTR_AGENT_ROLE, ATTR_TOOL_NAME,
    ATTR_DESTINATION_HOST, ATTR_RISK_FLAGS, ATTR_JIT_GRANT_ID,
    SPAN_PROMPT_RECEIVED, SPAN_TOOL_CALL_REQUESTED, SPAN_RESPONSE_GENERATED,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
AGENT_ID       = os.getenv("AGENT_ID",       "orchestrator-01")
AGENT_ROLE     = os.getenv("AGENT_ROLE",      "orchestrator")
TOOLS_BASE_URL = os.getenv("TOOLS_BASE_URL",  "http://tools:9000")
LLM_BASE_URL   = os.getenv("LLM_BASE_URL",    "http://ollama:11434")
LLM_MODEL      = os.getenv("LLM_MODEL",       "llama3.2:1b")
OTLP_ENDPOINT  = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://aiaap-otel-collector:4317")
IDENTITY_URL   = os.getenv("IDENTITY_URL",    "http://aiaap-identity:8300")
PDP_ENABLED    = os.getenv("PDP_ENABLED",     "true").lower() == "true"
PDP_TIMEOUT_SEC = float(os.getenv("PDP_TIMEOUT_SEC", "1.5"))

# ── SDK init (must happen before FastAPIInstrumentor) ─────────────────────────
init_tracer(service_name="aiaap-orchestrator", otlp_endpoint=OTLP_ENDPOINT)
HTTPXClientInstrumentor().instrument()  # auto-instrument outbound httpx calls

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AIAAP Orchestrator", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(AiAAPMiddleware, agent_id=AGENT_ID)
FastAPIInstrumentor.instrument_app(app)

tracer = trace.get_tracer("aiaap-orchestrator")

# ── Models ────────────────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str
    user_id: str = "anon"
    jit_grant_id: str | None = None   # optional JIT context from caller

class ChatResponse(BaseModel):
    response: str
    tool_used: str | None = None
    trace_id: str | None = None


# ── Tool dispatch ─────────────────────────────────────────────────────────────
TOOL_KEYWORDS = {
    "customer": "get_customer",
    "search":   "search_docs",
    "fetch":    "fetch_url",
    "url":      "fetch_url",
    "http":     "fetch_url",
}

def _detect_tool(message: str) -> str | None:
    lower = message.lower()
    for keyword, tool in TOOL_KEYWORDS.items():
        if keyword in lower:
            return tool
    return None


async def _pdp_check(
    tool_name: str,
    destination: str | None,
    jit_grant_id: str | None,
    agent_id: str,
    trace_id: str | None,
) -> tuple[bool, str, int | None]:
    """
    Call the Policy Decision Point. Returns (allowed, reason, decision_id).
    Fail-open: if PDP is disabled or unreachable, allow the call.
    """
    if not PDP_ENABLED:
        return True, "pdp_disabled", None
    try:
        payload: dict = {
            "agent_id":    agent_id,
            "tool_name":   tool_name,
            "tenant_id":   "default",
            "signal_source": "operational",
        }
        if destination:
            payload["destination"] = destination
        if jit_grant_id:
            try:
                payload["jit_grant_id"] = int(jit_grant_id)
            except (ValueError, TypeError):
                pass
        if trace_id:
            payload["trace_id"] = trace_id

        async with httpx.AsyncClient(timeout=PDP_TIMEOUT_SEC) as client:
            resp = await client.post(f"{IDENTITY_URL}/api/pdp/evaluate", json=payload)

        if resp.status_code == 200:
            data = resp.json()
            outcome = data.get("outcome", "allow")
            reason  = data.get("reason", "")
            dec_id  = data.get("decision_id")
            allowed = outcome == "allow"
            return allowed, reason, dec_id
        # Non-200 from PDP → fail-open
        return True, f"pdp_http_{resp.status_code}_fail_open", None
    except Exception as exc:
        logger.warning("PDP unavailable (fail-open): %s", exc)
        return True, "pdp_unavailable_fail_open", None


async def _call_tool(tool_name: str, message: str, jit_grant_id: str | None = None) -> str:
    """
    Dispatch a tool call and emit a tool_call_requested span.
    The tools service emits its own tool_call_executed span via the SDK.
    """
    import re

    span = trace.get_current_span()

    # Extract destination URL for fetch_url tool (needed for PDP check)
    destination: str | None = None
    if tool_name == "fetch_url":
        urls = re.findall(r'https?://[^\s]+', message)
        target_url = urls[0] if urls else "http://example.com"
        destination = target_url.split("/")[2]  # hostname only

    # Extract current trace ID for PDP correlation
    ctx = span.get_span_context()
    current_trace_id = format(ctx.trace_id, "032x") if ctx and ctx.trace_id else None

    with tracer.start_as_current_span(SPAN_TOOL_CALL_REQUESTED) as req_span:
        req_span.set_attribute(ATTR_TOOL_NAME, tool_name)
        req_span.set_attribute(ATTR_AGENT_ID, AGENT_ID)
        if jit_grant_id:
            req_span.set_attribute(ATTR_JIT_GRANT_ID, jit_grant_id)

        # ── PDP pre-flight ────────────────────────────────────────────────────
        pdp_allowed, pdp_reason, pdp_decision_id = await _pdp_check(
            tool_name=tool_name,
            destination=destination,
            jit_grant_id=jit_grant_id,
            agent_id=AGENT_ID,
            trace_id=current_trace_id,
        )
        req_span.set_attribute("aiaap.pdp.outcome", "allow" if pdp_allowed else "block")
        req_span.set_attribute("aiaap.pdp.reason", pdp_reason)
        if pdp_decision_id:
            req_span.set_attribute("aiaap.pdp.decision_id", str(pdp_decision_id))

        if not pdp_allowed:
            req_span.set_attribute(ATTR_RISK_FLAGS, json.dumps(["pdp_blocked"]))
            logger.warning("PDP blocked tool '%s': %s (decision=%s)", tool_name, pdp_reason, pdp_decision_id)
            return f"[BLOCKED by policy] {tool_name}: {pdp_reason}"

        # ── Tool dispatch ──────────────────────────────────────────────────────
        async with httpx.AsyncClient(timeout=10.0) as client:
            if tool_name == "get_customer":
                resp = await client.get(f"{TOOLS_BASE_URL}/customer/001")
            elif tool_name == "search_docs":
                resp = await client.get(f"{TOOLS_BASE_URL}/search", params={"q": message[:100]})
            elif tool_name == "fetch_url":
                req_span.set_attribute(ATTR_DESTINATION_HOST, destination or "unknown")
                resp = await client.post(
                    f"{TOOLS_BASE_URL}/fetch",
                    json={"url": target_url}
                )
            else:
                return f"Unknown tool: {tool_name}"

        if resp.status_code == 200:
            return resp.text[:500]
        else:
            req_span.set_attribute(ATTR_RISK_FLAGS, json.dumps(["tool_error"]))
            return f"Tool error: {resp.status_code}"


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "healthy", "agent_id": AGENT_ID}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """
    Main chat endpoint. Spans:
    1. prompt_received (root)
    2. tool_call_requested (if tool detected)
    3. response_generated
    """
    with tracer.start_as_current_span(SPAN_PROMPT_RECEIVED) as root_span:
        root_span.set_attribute(ATTR_AGENT_ID, AGENT_ID)
        root_span.set_attribute(ATTR_AGENT_ROLE, AGENT_ROLE)
        root_span.set_attribute("aiaap.request.user_id", req.user_id)
        if req.jit_grant_id:
            root_span.set_attribute(ATTR_JIT_GRANT_ID, req.jit_grant_id)

        # Get the trace ID for response
        ctx = root_span.get_span_context()
        trace_id_hex = format(ctx.trace_id, "032x") if ctx.trace_id else None

        tool_used = None
        tool_result = ""

        # Detect if a tool call is needed
        tool_name = _detect_tool(req.message)
        if tool_name:
            try:
                tool_result = await _call_tool(tool_name, req.message, req.jit_grant_id)
                tool_used = tool_name
            except Exception as exc:
                logger.warning("Tool call failed: %s", exc)
                tool_result = f"Tool unavailable: {exc}"

        # Generate response (simple passthrough for demo; in production calls Ollama)
        with tracer.start_as_current_span(SPAN_RESPONSE_GENERATED) as resp_span:
            if tool_result:
                response_text = f"[Agent] Tool '{tool_used}' result: {tool_result}"
            else:
                response_text = f"[Agent] Received: {req.message[:200]}"
            resp_span.set_attribute("aiaap.response.length", len(response_text))

    return ChatResponse(
        response=response_text,
        tool_used=tool_used,
        trace_id=trace_id_hex,
    )
