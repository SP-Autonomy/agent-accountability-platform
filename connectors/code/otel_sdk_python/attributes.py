"""
AIAAP semantic attribute name constants.
Use these on every span to ensure consistent correlation across signals.
"""

# Agent identity
ATTR_AGENT_ID          = "aiaap.agent.id"
ATTR_AGENT_ROLE        = "aiaap.agent.role"
ATTR_NAMESPACE         = "aiaap.k8s.namespace"
ATTR_SERVICE_ACCOUNT   = "aiaap.k8s.service_account"
ATTR_TENANT_ID         = "aiaap.tenant.id"

# Tool invocation
ATTR_TOOL_NAME             = "aiaap.tool.name"
ATTR_DESTINATION_HOST      = "aiaap.tool.destination_host"
ATTR_DESTINATION_IP        = "aiaap.tool.destination_ip"
ATTR_DATA_CLASSIFICATION   = "aiaap.data.classification"

# JIT context
ATTR_JIT_GRANT_ID      = "aiaap.jit.grant_id"
ATTR_REQUEST_PURPOSE   = "aiaap.request.purpose"

# Risk signals
ATTR_RISK_FLAGS        = "aiaap.risk.flags"   # JSON array string, e.g. '["privileged_action"]'
ATTR_SUSPECTED_INJECTION = "aiaap.risk.suspected_injection"  # bool as string "true"/"false"

# Standard workflow step span names (use as span names, not attributes)
SPAN_PROMPT_RECEIVED      = "prompt_received"
SPAN_TOOL_CALL_REQUESTED  = "tool_call_requested"
SPAN_TOOL_CALL_EXECUTED   = "tool_call_executed"
SPAN_RETRIEVAL_QUERY      = "retrieval_query"
SPAN_RETRIEVAL_RESULT     = "retrieval_result"
SPAN_RESPONSE_GENERATED   = "response_generated"
