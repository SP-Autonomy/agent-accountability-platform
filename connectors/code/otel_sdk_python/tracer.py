"""
AIAAP tracer initialisation.
Call init_tracer() once at startup, then use get_tracer() everywhere.
"""

import os
import logging
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

logger = logging.getLogger(__name__)

_tracer: trace.Tracer | None = None


def init_tracer(
    service_name: str | None = None,
    otlp_endpoint: str | None = None,
    console_fallback: bool = True,
) -> trace.Tracer:
    """
    Initialise the global TracerProvider and return the service tracer.

    Args:
        service_name:    Overrides OTEL_SERVICE_NAME env var.
        otlp_endpoint:   Overrides OTEL_EXPORTER_OTLP_ENDPOINT env var.
        console_fallback: If True and OTLP fails to connect, also log spans to console.
    """
    global _tracer

    name = service_name or os.getenv("OTEL_SERVICE_NAME", "aiaap-workload")
    endpoint = otlp_endpoint or os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
    )

    provider = TracerProvider()

    # OTLP exporter - sends to OTel Collector (or directly to ingest in dev)
    try:
        otlp_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info("AIAAP SDK: OTLP exporter configured → %s", endpoint)
    except Exception as exc:
        logger.warning("AIAAP SDK: OTLP exporter init failed (%s)", exc)

    # Console fallback for development / debugging
    if console_fallback:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(name)
    return _tracer


def get_tracer() -> trace.Tracer:
    """Return the initialised tracer. Auto-inits with defaults if not yet called."""
    global _tracer
    if _tracer is None:
        _tracer = init_tracer()
    return _tracer
