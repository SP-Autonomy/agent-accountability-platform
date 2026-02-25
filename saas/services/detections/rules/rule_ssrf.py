"""
Rule: ssrf_metadata
--------------------
Detects two classes of suspicious outbound calls from agent tool spans:

1. Cloud Metadata Service (IMDS) access - highest severity:
   - OTel span: aiaap.tool.destination_host = 169.254.169.254 / metadata.google.internal
   - eBPF event: ebpf_process_connect to dest_ip starting with 169.254.

2. External data exfiltration - aiaap.risk.flags contains "external_dest" or
   "rag_injection_suspected" on a tool call to a non-RFC1918 destination.
   This covers RAG poisoning, intent mismatch exfil, and lateral movement probes.

Status logic:
  - PREVENTED: eBPF event shows action=blocked (Cilium blocked the connection)
  - DETECTED:  OTel span detected the attempt but no eBPF block confirmed
"""

import json
from typing import Optional

from saas.services.shared.models import (
    NormalizedEvent, Finding, Severity, FindingStatus, EventSource,
)

_METADATA_PREFIXES = (
    "169.254.169.254",
    "169.254.",
    "metadata.google.internal",
    "metadata.internal",
)

# Risk flags that indicate external/exfil intent on any destination
_EXFIL_FLAGS = {"external_dest", "rag_injection_suspected", "metadata_ip_access"}

SCENARIO_ID = "ssrf_metadata"


def _is_metadata(dest: str | None) -> bool:
    if not dest:
        return False
    return any(dest.startswith(p) for p in _METADATA_PREFIXES)


def _has_exfil_flag(ev: NormalizedEvent) -> bool:
    """Return True if the OTel event carries a flag indicating external exfiltration."""
    attrs = ev.payload.get("attributes", {})
    raw = attrs.get("aiaap.risk.flags", "")
    if not raw:
        return False
    try:
        flags = set(json.loads(raw))
    except (json.JSONDecodeError, TypeError):
        flags = {raw}
    return bool(flags & _EXFIL_FLAGS)


def check(events: list[NormalizedEvent], db) -> Optional[Finding]:
    otel_metadata_hit: Optional[NormalizedEvent] = None
    otel_exfil_hit:    Optional[NormalizedEvent] = None
    ebpf_hit:          Optional[NormalizedEvent] = None

    for ev in events:
        if ev.source == EventSource.otel:
            if _is_metadata(ev.dest):
                otel_metadata_hit = ev
            elif _has_exfil_flag(ev):
                otel_exfil_hit = ev
        if ev.source == EventSource.ebpf and _is_metadata(ev.payload.get("dest_ip", "")):
            ebpf_hit = ev

    if not otel_metadata_hit and not otel_exfil_hit and not ebpf_hit:
        return None

    # Determine status
    if ebpf_hit and ebpf_hit.payload.get("action") == "blocked":
        status = FindingStatus.prevented
    else:
        status = FindingStatus.detected

    # Build evidence list and title
    if otel_metadata_hit or ebpf_hit:
        evidence_ids = [ev.id for ev in [otel_metadata_hit, ebpf_hit] if ev]
        title = "SSRF Attempt: Cloud Metadata Endpoint Access"
        severity = Severity.high
    else:
        evidence_ids = [otel_exfil_hit.id]
        dest = otel_exfil_hit.dest or "unknown"
        title = f"External Data Exfiltration: Agent called '{dest}'"
        severity = Severity.high

    tenant_id = events[0].tenant_id

    return Finding(
        tenant_id=tenant_id,
        title=title,
        severity=severity,
        status=status,
        evidence_refs=evidence_ids,
        scenario_id=SCENARIO_ID,
    )
