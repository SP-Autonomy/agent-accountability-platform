"""
JIT grant context propagation helpers.
Attaches an active JIT grant ID to the current OTel span so the
correlation engine can verify that privileged tool calls have authorization.
"""

import logging
from opentelemetry import trace, context, baggage

from connectors.code.otel_sdk_python.attributes import ATTR_JIT_GRANT_ID, ATTR_REQUEST_PURPOSE

logger = logging.getLogger(__name__)


def attach_jit_context(grant_id: str, purpose: str = "") -> None:
    """
    Attach JIT grant attributes to the current active span.
    Call this after acquiring a JIT grant before executing a privileged tool.

    Args:
        grant_id: The JIT grant UUID returned by the identity service.
        purpose:  Human-readable reason for the grant (shown in dashboard).
    """
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_attribute(ATTR_JIT_GRANT_ID, grant_id)
        if purpose:
            span.set_attribute(ATTR_REQUEST_PURPOSE, purpose)
    else:
        logger.debug("attach_jit_context: no active recording span")


def get_current_grant_id() -> str | None:
    """Return the JIT grant ID from the current span, if present."""
    span = trace.get_current_span()
    if span and span.is_recording():
        ctx = span.get_span_context()
        # Attributes are not readable back from the SDK in general;
        # this is for user-level context propagation via baggage.
        return baggage.get_baggage(ATTR_JIT_GRANT_ID)
    return None
