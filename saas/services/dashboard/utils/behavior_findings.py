"""
Behavior Findings - dashboard-side behavioral anomaly detector.

Consumes AgentBaseline objects from baseline_engine and emits explicit
BehavioralFinding dicts (plain JSON-serializable) that pages render directly.

Each finding includes:
  finding_type, severity, agent, evidence (baseline vs observed),
  confidence, recommended_action, tool/destination, timestamp.

Usage:
    from utils.baseline_engine import compute_baselines
    from utils.behavior_findings import compute_behavioral_findings

    baselines = compute_baselines(snap["tool_usages"], snap["pid_map"])
    findings  = compute_behavioral_findings(baselines)
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from utils.baseline_engine import (
    AgentBaseline,
    is_high_risk_destination,
    is_privileged_tool,
)


# ── Constants ──────────────────────────────────────────────────────────────────

MIN_BASELINE_CALLS   = 5     # need at least N calls in baseline for drift analysis
JS_DRIFT_THRESHOLD   = 0.12  # Jensen-Shannon divergence above this → drift finding
PRIV_RATIO_THRESHOLD = 0.15  # absolute increase in privileged ratio
BURST_MULTIPLIER     = 2.0   # burst_max ratio to trigger burst finding
BURST_MIN_ABS        = 5     # also require at least 5 calls in burst window
SEQ_WINDOW_SECONDS   = 300   # max seconds between calls to count as a sequence

# Suspicious two-call sequences: (pattern1, pattern2, description, severity)
SUSPICIOUS_SEQUENCES: list[tuple[str, str, str, str]] = [
    ("fetch_url",          "read_env",         "Web fetch → env-var read (SSRF→credential exfil)",         "high"),
    ("fetch_url",          "read_secret",      "Web fetch → secret read (SSRF→secret access)",              "high"),
    ("http_get",           "read_secret",      "HTTP call → secret read",                                   "high"),
    ("fetch_url",          "credential",       "Web fetch → credential access",                             "high"),
    ("fetch_url",          "write",            "Web fetch → write operation (possible data staging)",       "medium"),
    ("create_rolebinding", "exec",             "Role-binding create → exec (privilege escalation chain)",  "critical"),
    ("attach_policy",      "exec",             "Policy attach → exec (privilege escalation chain)",        "critical"),
    ("list_secret",        "get_secret",       "Secret list → get (secret enumeration + access)",           "medium"),
    ("list_secret",        "read_secret",      "Secret list → read (lateral secret access)",                "medium"),
    ("scan",               "fetch_url",        "Network scan → external fetch (recon→exfil)",               "medium"),
    ("read_file",          "fetch_url",        "File read → external fetch (possible data exfil)",          "medium"),
    ("search",             "exfil",            "Search → exfil keyword (data exfiltration indicator)",      "high"),
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── JS Divergence ──────────────────────────────────────────────────────────────

def _js_divergence(p: dict[str, int], q: dict[str, int]) -> float:
    """Jensen-Shannon divergence between two count distributions. Range [0, 1]."""
    all_keys = set(p) | set(q)
    if not all_keys:
        return 0.0
    p_tot = sum(p.values()) or 1
    q_tot = sum(q.values()) or 1
    pn = {k: p.get(k, 0) / p_tot for k in all_keys}
    qn = {k: q.get(k, 0) / q_tot for k in all_keys}
    mn = {k: (pn[k] + qn[k]) / 2 for k in all_keys}

    def _kl(a: dict[str, float], b: dict[str, float]) -> float:
        return sum(a[k] * math.log(a[k] / b[k]) for k in all_keys if a[k] > 0 and b[k] > 0)

    try:
        return max(0.0, min(1.0, (_kl(pn, mn) + _kl(qn, mn)) / 2))
    except Exception:
        return 0.0


# ── Finding constructor ────────────────────────────────────────────────────────

def _finding(
    finding_type: str,
    severity: str,
    agent: str,
    evidence: dict[str, Any],
    confidence: float,
    recommended_action: str,
    tool: str | None = None,
    destination: str | None = None,
) -> dict[str, Any]:
    return {
        "finding_type":       finding_type,
        "severity":           severity,
        "agent":              agent,
        "tool":               tool,
        "destination":        destination,
        "evidence":           evidence,
        "confidence":         round(max(0.0, min(1.0, confidence)), 3),
        "recommended_action": recommended_action,
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "source":             "behavioral_baseline",
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def compute_behavioral_findings(
    baselines: dict[str, AgentBaseline],
) -> list[dict[str, Any]]:
    """
    Generate behavioral findings for all agents.

    Returns a deduplicated list sorted by severity (critical → low).
    Each finding is a plain dict (JSON-serializable for st.cache_data).
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str | None]] = set()  # dedup: (agent, type, tool_or_dest)

    def _add(f: dict) -> None:
        key = (f["agent"], f["finding_type"], f.get("tool") or f.get("destination"))
        if key not in seen:
            seen.add(key)
            findings.append(f)

    for agent_name, bl in baselines.items():
        if agent_name.startswith("unknown"):
            continue

        b = bl.baseline
        c = bl.current
        has_baseline = b.total_calls >= MIN_BASELINE_CALLS

        # ── 1. New tool used ──────────────────────────────────────────────────
        for tool in bl.new_tools:
            if tool in ("unknown", ""):
                continue
            priv = is_privileged_tool(tool)
            _add(_finding(
                finding_type="new_tool",
                severity="high" if priv else "medium",
                agent=agent_name,
                tool=tool,
                evidence={
                    "new_tool":        tool,
                    "is_privileged":   priv,
                    "baseline_tools":  sorted(b.tool_counts)[:15],
                    "calls_in_window": c.tool_counts.get(tool, 0),
                },
                confidence=0.90 if priv else 0.75,
                recommended_action=(
                    f"Privileged tool '{tool}' not seen in baseline - "
                    "verify it has a JIT grant and is in the intent envelope."
                    if priv else
                    f"Tool '{tool}' appeared for the first time. Confirm it is "
                    "expected for this agent's declared intent."
                ),
            ))

        # ── 2. Destination analysis ───────────────────────────────────────────
        for dest in c.unique_destinations:
            if not dest or dest == "-":
                continue
            is_new       = dest not in b.unique_destinations
            high_risk    = is_high_risk_destination(dest)
            calls_in_win = c.dest_counts.get(dest, 0)

            if high_risk and is_new:
                _add(_finding(
                    finding_type="new_high_risk_destination",
                    severity="critical",
                    agent=agent_name,
                    destination=dest,
                    evidence={
                        "destination":        dest,
                        "is_new":             True,
                        "calls_in_window":    calls_in_win,
                        "baseline_dests":     sorted(list(b.unique_destinations))[:15],
                        "risk_category":      "metadata / internal / RFC1918",
                    },
                    confidence=0.95,
                    recommended_action=(
                        f"CRITICAL: '{dest}' matches a high-risk destination pattern "
                        "(metadata service, internal IP, or secrets endpoint) and was "
                        "NOT seen in the baseline. Apply Cilium egress policy immediately."
                    ),
                ))
            elif high_risk and not is_new:
                _add(_finding(
                    finding_type="known_high_risk_destination",
                    severity="high",
                    agent=agent_name,
                    destination=dest,
                    evidence={
                        "destination":     dest,
                        "is_new":          False,
                        "calls_in_window": calls_in_win,
                        "note":            "High-risk destination re-accessed (seen in baseline)",
                    },
                    confidence=0.80,
                    recommended_action=(
                        f"High-risk destination '{dest}' accessed again (also present in baseline). "
                        "Confirm this is legitimate and enforce egress policy."
                    ),
                ))
            elif is_new and not high_risk:
                _add(_finding(
                    finding_type="new_destination",
                    severity="low",
                    agent=agent_name,
                    destination=dest,
                    evidence={
                        "destination":     dest,
                        "calls_in_window": calls_in_win,
                        "baseline_dests":  sorted(list(b.unique_destinations))[:10],
                    },
                    confidence=0.65,
                    recommended_action=(
                        f"New destination '{dest}' not seen in the 7-day baseline. "
                        "Confirm it is in the agent's declared intent envelope."
                    ),
                ))

        # ── 3. Tool distribution drift (JS divergence) ────────────────────────
        if has_baseline and c.total_calls >= 3:
            jsd = _js_divergence(b.tool_counts, c.tool_counts)
            if jsd >= JS_DRIFT_THRESHOLD:
                all_tools = set(b.tool_counts) | set(c.tool_counts)
                b_tot     = sum(b.tool_counts.values()) or 1
                c_tot     = sum(c.tool_counts.values()) or 1
                shifts    = {
                    t: abs(c.tool_counts.get(t, 0) / c_tot - b.tool_counts.get(t, 0) / b_tot)
                    for t in all_tools
                }
                top_drifting = sorted(shifts, key=lambda x: -shifts[x])[:5]
                _add(_finding(
                    finding_type="tool_distribution_drift",
                    severity="high" if jsd >= 0.30 else "medium",
                    agent=agent_name,
                    evidence={
                        "js_divergence":       round(jsd, 4),
                        "threshold":           JS_DRIFT_THRESHOLD,
                        "baseline_top_tools":  sorted(b.tool_counts, key=lambda x: -b.tool_counts[x])[:5],
                        "current_top_tools":   sorted(c.tool_counts, key=lambda x: -c.tool_counts[x])[:5],
                        "top_drifting_tools":  top_drifting,
                    },
                    confidence=min(0.5 + jsd, 0.95),
                    recommended_action=(
                        f"Tool usage pattern shifted significantly (JSD={jsd:.3f}, threshold={JS_DRIFT_THRESHOLD}). "
                        f"Largest contributors: {', '.join(top_drifting[:3])}. "
                        "Review recent activity and update the intent envelope if the change is legitimate."
                    ),
                ))

        # ── 4. Privileged ratio spike ─────────────────────────────────────────
        if has_baseline and c.total_calls >= 3:
            delta = bl.privileged_ratio_delta
            if delta > PRIV_RATIO_THRESHOLD:
                priv_tools = [t for t in c.tool_counts if is_privileged_tool(t)]
                _add(_finding(
                    finding_type="privileged_ratio_spike",
                    severity="high",
                    agent=agent_name,
                    evidence={
                        "baseline_privileged_ratio": round(b.privileged_ratio, 3),
                        "current_privileged_ratio":  round(c.privileged_ratio, 3),
                        "delta":                     round(delta, 3),
                        "baseline_privileged_calls": b.privileged_calls,
                        "current_privileged_calls":  c.privileged_calls,
                        "privileged_tools_used":     priv_tools,
                    },
                    confidence=0.85,
                    recommended_action=(
                        f"Privileged tool usage jumped from {b.privileged_ratio:.0%} → "
                        f"{c.privileged_ratio:.0%} (Δ={delta:+.0%}). "
                        f"Tools involved: {', '.join(priv_tools[:5]) or 'unknown'}. "
                        "Ensure each privileged action has a corresponding JIT grant."
                    ),
                ))

        # ── 5. Burst anomaly ──────────────────────────────────────────────────
        if has_baseline and c.burst_max >= BURST_MIN_ABS:
            base_burst  = max(b.burst_max, 1)
            burst_ratio = c.burst_max / base_burst
            if burst_ratio >= BURST_MULTIPLIER:
                _add(_finding(
                    finding_type="burst_anomaly",
                    severity="medium",
                    agent=agent_name,
                    evidence={
                        "baseline_burst_max_per_5min": b.burst_max,
                        "current_burst_max_per_5min":  c.burst_max,
                        "burst_ratio":                 round(burst_ratio, 2),
                        "total_calls_in_window":       c.total_calls,
                    },
                    confidence=0.70,
                    recommended_action=(
                        f"Call rate spiked to {c.burst_max} calls/5 min "
                        f"(baseline max: {b.burst_max}, ratio: {burst_ratio:.1f}×). "
                        "Check for automation loops, data scraping, or exfiltration attempts."
                    ),
                ))

        # ── 6. Suspicious call sequences ─────────────────────────────────────
        calls = c.ordered_calls
        seq_seen: set[tuple[str, str]] = set()
        for i, call1 in enumerate(calls):
            for j in range(i + 1, min(i + 8, len(calls))):
                call2  = calls[j]
                ts1, ts2 = call1.get("ts") or "", call2.get("ts") or ""
                # Time proximity check
                if ts1 and ts2:
                    try:
                        dt1 = datetime.fromisoformat(ts1.replace("Z", "+00:00"))
                        dt2 = datetime.fromisoformat(ts2.replace("Z", "+00:00"))
                        if dt1.tzinfo is None:
                            dt1 = dt1.replace(tzinfo=timezone.utc)
                        if dt2.tzinfo is None:
                            dt2 = dt2.replace(tzinfo=timezone.utc)
                        if abs((dt2 - dt1).total_seconds()) > SEQ_WINDOW_SECONDS:
                            break
                    except Exception:
                        pass
                t1 = (call1.get("tool") or "").lower()
                t2 = (call2.get("tool") or "").lower()
                for p1, p2, desc, sev in SUSPICIOUS_SEQUENCES:
                    if p1 in t1 and p2 in t2:
                        seq_key = (p1, p2)
                        if seq_key not in seq_seen:
                            seq_seen.add(seq_key)
                            _add(_finding(
                                finding_type="suspicious_sequence",
                                severity=sev,
                                agent=agent_name,
                                tool=f"{call1['tool']} → {call2['tool']}",
                                evidence={
                                    "tool_1":      call1.get("tool"),
                                    "tool_2":      call2.get("tool"),
                                    "dest_1":      call1.get("dest"),
                                    "dest_2":      call2.get("dest"),
                                    "ts_1":        ts1[:19],
                                    "ts_2":        ts2[:19],
                                    "pattern":     f"{p1} → {p2}",
                                    "description": desc,
                                },
                                confidence=0.65,
                                recommended_action=(
                                    f"Suspicious two-call sequence detected: {desc}. "
                                    "Review the trace for this call chain to confirm intent."
                                ),
                            ))

    # Sort by severity then agent
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 5), f["agent"]))
    return findings
