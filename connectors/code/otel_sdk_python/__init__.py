"""
AIAAP SDK - OpenTelemetry instrumentation for agentic workloads.

Usage:
    from connectors.code.otel_sdk_python import init_tracer
    from connectors.code.otel_sdk_python.decorators import trace_tool_call, trace_agent_step
    from connectors.code.otel_sdk_python.attributes import ATTR_AGENT_ID, ATTR_TOOL_NAME

    init_tracer(service_name="my-agent", otlp_endpoint="http://collector:4317")
"""

from connectors.code.otel_sdk_python.tracer import init_tracer, get_tracer

__all__ = ["init_tracer", "get_tracer"]
