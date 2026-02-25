"""
AIAAP POV Sample Agent - Kubernetes
A minimal FastAPI service instrumented with the AIAAP OTel SDK.
Emits tool_call_executed spans so the OTel Collector can forward them to ingest.
"""

import os
import time
import threading

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

# ── Import AIAAP SDK ───────────────────────────────────────────────────────────
# In production: pip install -e connectors/code/otel_sdk_python/
# In this container: mounted at /app/connectors
import sys
sys.path.insert(0, "/app")

try:
    from connectors.code.otel_sdk_python.tracer import init_tracer
    from connectors.code.otel_sdk_python.attributes import (
        ATTR_AGENT_ID, ATTR_TOOL_NAME, SPAN_TOOL_CALL_EXECUTED,
    )
    SDK_AVAILABLE = True
except ImportError:
    # Fallback: use bare OpenTelemetry if SDK not installed
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    ATTR_AGENT_ID = "aiaap.agent.id"
    ATTR_TOOL_NAME = "aiaap.tool.name"
    SPAN_TOOL_CALL_EXECUTED = "tool_call_executed"
    SDK_AVAILABLE = False

# ── Configuration ─────────────────────────────────────────────────────────────
AGENT_ID      = os.getenv("AGENT_ID", "pov-k8s-agent")
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

if SDK_AVAILABLE:
    init_tracer(service_name=AGENT_ID, otlp_endpoint=OTLP_ENDPOINT)

tracer = trace.get_tracer(AGENT_ID)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AIAAP POV Sample Agent")
FastAPIInstrumentor.instrument_app(app)


@app.get("/health")
def health():
    return {"status": "healthy", "agent_id": AGENT_ID, "sdk": SDK_AVAILABLE}


@app.get("/run")
def run_tools():
    """Simulate tool calls - each emits a span the OTel Collector picks up."""
    results = []
    for tool in ["search_docs", "get_customer", "summarize"]:
        with tracer.start_as_current_span(SPAN_TOOL_CALL_EXECUTED) as span:
            span.set_attribute(ATTR_AGENT_ID, AGENT_ID)
            span.set_attribute(ATTR_TOOL_NAME, tool)
            time.sleep(0.05)  # simulate work
            results.append({"tool": tool, "status": "ok"})
    return {"agent_id": AGENT_ID, "tools_called": results}


# ── Background loop: emit spans every 30s ─────────────────────────────────────
def _emit_loop():
    while True:
        try:
            with tracer.start_as_current_span(SPAN_TOOL_CALL_EXECUTED) as span:
                span.set_attribute(ATTR_AGENT_ID, AGENT_ID)
                span.set_attribute(ATTR_TOOL_NAME, "heartbeat")
        except Exception:
            pass
        time.sleep(30)


threading.Thread(target=_emit_loop, daemon=True).start()
