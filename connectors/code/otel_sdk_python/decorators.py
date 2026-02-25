"""
AIAAP span decorators for agentic workflow steps and tool calls.

Usage:
    from connectors.code.otel_sdk_python.decorators import trace_tool_call, trace_agent_step
    from connectors.code.otel_sdk_python.attributes import ATTR_AGENT_ID

    @trace_agent_step("prompt_received")
    def handle_chat(request, agent_id: str):
        with get_tracer().start_as_current_span("prompt_received") as span:
            span.set_attribute(ATTR_AGENT_ID, agent_id)
        ...

    @trace_tool_call(tool_name="fetch_url", risk_level="high")
    def fetch_url(url: str) -> str:
        ...
"""

import functools
import json
import logging
from urllib.parse import urlparse

from opentelemetry import trace
from opentelemetry.trace import StatusCode

from connectors.code.otel_sdk_python.attributes import (
    ATTR_TOOL_NAME,
    ATTR_DESTINATION_HOST,
    ATTR_DESTINATION_IP,
    ATTR_RISK_FLAGS,
    SPAN_TOOL_CALL_EXECUTED,
)
from connectors.code.otel_sdk_python.tracer import get_tracer

logger = logging.getLogger(__name__)

# IPs / hostnames that indicate elevated risk (metadata service)
_HIGH_RISK_DESTINATIONS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
}


def trace_tool_call(tool_name: str, risk_level: str = "low"):
    """
    Decorator that wraps a tool function with a tool_call_executed OTel span.

    Automatically:
    - Sets aiaap.tool.name attribute
    - Extracts destination_host from a 'url' keyword argument if present
    - Flags high-risk destinations in aiaap.risk.flags
    - Records exceptions on the span and re-raises
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(SPAN_TOOL_CALL_EXECUTED) as span:
                span.set_attribute(ATTR_TOOL_NAME, tool_name)
                span.set_attribute("aiaap.tool.risk_level", risk_level)

                # Extract destination from url kwarg
                url = kwargs.get("url") or (args[0] if args and isinstance(args[0], str) and args[0].startswith("http") else None)
                if url:
                    try:
                        parsed = urlparse(url)
                        host = parsed.hostname or ""
                        span.set_attribute(ATTR_DESTINATION_HOST, host)
                        if host in _HIGH_RISK_DESTINATIONS or host.startswith("169.254."):
                            span.set_attribute(ATTR_RISK_FLAGS, json.dumps(["metadata_ip_access"]))
                    except Exception:
                        pass

                try:
                    result = func(*args, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper
    return decorator


def trace_agent_step(step_name: str):
    """
    Decorator that wraps a high-level agent workflow step with a named OTel span.
    The span name is the step_name (e.g. 'prompt_received', 'tool_call_requested').
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(step_name) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper
    return decorator
