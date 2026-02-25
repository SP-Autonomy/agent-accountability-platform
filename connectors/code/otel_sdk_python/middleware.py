"""
AIAAP FastAPI middleware for automatic span enrichment.
Adds AIAAP-specific attributes to every request span:
  - aiaap.agent.id (from X-Agent-Id header or AGENT_ID env var)
  - aiaap.k8s.namespace (from NAMESPACE env var / downward API)
  - aiaap.k8s.service_account (from SERVICE_ACCOUNT env var / downward API)
  - aiaap.tenant.id (from X-Tenant-Id header or TENANT_ID env var)
"""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from opentelemetry import trace

from connectors.code.otel_sdk_python.attributes import (
    ATTR_AGENT_ID, ATTR_NAMESPACE, ATTR_SERVICE_ACCOUNT, ATTR_TENANT_ID
)


class AiAAPMiddleware(BaseHTTPMiddleware):
    """
    Enrich the current OTel span with AIAAP identity attributes on every request.
    Register with: app.add_middleware(AiAAPMiddleware)
    """

    def __init__(self, app, agent_id: str | None = None):
        super().__init__(app)
        self._agent_id = agent_id or os.getenv("AGENT_ID", "unknown-agent")
        self._namespace = os.getenv("NAMESPACE", "default")
        self._service_account = os.getenv("SERVICE_ACCOUNT", "default")
        self._tenant_id = os.getenv("TENANT_ID", "default")

    async def dispatch(self, request: Request, call_next):
        span = trace.get_current_span()
        if span and span.is_recording():
            # Allow per-request overrides via headers (useful for multi-agent scenarios)
            agent_id = request.headers.get("X-Agent-Id", self._agent_id)
            tenant_id = request.headers.get("X-Tenant-Id", self._tenant_id)

            span.set_attribute(ATTR_AGENT_ID, agent_id)
            span.set_attribute(ATTR_NAMESPACE, self._namespace)
            span.set_attribute(ATTR_SERVICE_ACCOUNT, self._service_account)
            span.set_attribute(ATTR_TENANT_ID, tenant_id)

        response = await call_next(request)
        return response
