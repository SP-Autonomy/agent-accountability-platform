"""
Baseline Engine - dashboard-side per-agent behavioral baseline computation.

Operates on tool_usage records from get_snapshot(). No DB access required;
purely derived from the snapshot data already loaded in memory.

Usage:
    from utils.baseline_engine import compute_baselines, is_high_risk_destination

    baselines = compute_baselines(snap["tool_usages"], snap["pid_map"])
    # baselines: dict[agent_name, AgentBaseline]
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


# ── Risk classification helpers ────────────────────────────────────────────────

HIGH_RISK_DEST_PREFIXES: tuple[str, ...] = (
    "169.254.",                  # Link-local / AWS IMDS
    "metadata.google.internal",
    "metadata.internal",
    "127.",                      # Loopback
    "::1",
    "localhost",
    "10.",                       # RFC1918 class A
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.",                   # RFC1918 class B
    "192.168.",                  # RFC1918 class C
)

HIGH_RISK_DEST_SUBSTRINGS: tuple[str, ...] = (
    "vault", "kms", "secrets-manager", "secretsmanager",
    "iam.amazonaws", "ssm.amazonaws", ".internal",
)

PRIVILEGED_TOOL_SUBSTRINGS: tuple[str, ...] = (
    "secret", "cred", "token", "policy", "role", "exec",
    "admin", "root", "privilege", "sudo", "escalat",
    "attach_pod", "create_rolebinding", "put_policy",
    "delete_", "drop_", "purge",
)


def is_high_risk_destination(dest: str) -> bool:
    """Return True if dest matches any high-risk destination pattern."""
    if not dest:
        return False
    d = dest.lower()
    return (
        any(d.startswith(p) for p in HIGH_RISK_DEST_PREFIXES)
        or any(s in d for s in HIGH_RISK_DEST_SUBSTRINGS)
    )


def is_privileged_tool(tool_name: str) -> bool:
    """Return True if tool_name suggests privileged / sensitive operation."""
    if not tool_name:
        return False
    t = tool_name.lower()
    return any(s in t for s in PRIVILEGED_TOOL_SUBSTRINGS)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class WindowMetrics:
    """Aggregated metrics for a single time window."""
    total_calls:        int            = 0
    tool_counts:        dict[str, int] = field(default_factory=dict)
    dest_counts:        dict[str, int] = field(default_factory=dict)
    unique_destinations: set[str]      = field(default_factory=set)
    privileged_calls:   int            = 0
    privileged_ratio:   float          = 0.0
    call_rate_per_hour: float          = 0.0
    burst_max:          int            = 0    # max calls in any 5-min bin
    known_edges:        set[tuple[str, str]] = field(default_factory=set)  # (tool, dest)
    window_hours:       float          = 0.0
    # Ordered call list for sequence analysis (tool, dest, ts dicts)
    ordered_calls:      list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AgentBaseline:
    """Baseline and current-window metrics for a single agent."""
    agent_name:     str
    baseline:       WindowMetrics
    current:        WindowMetrics
    baseline_hours: float
    current_hours:  float

    @property
    def new_tools(self) -> set[str]:
        """Tools in current window absent from baseline."""
        return set(self.current.tool_counts) - set(self.baseline.tool_counts)

    @property
    def new_destinations(self) -> set[str]:
        """Destinations in current window absent from baseline."""
        return self.current.unique_destinations - self.baseline.unique_destinations

    @property
    def new_edges(self) -> set[tuple[str, str]]:
        """(tool, dest) pairs in current window absent from baseline."""
        return self.current.known_edges - self.baseline.known_edges

    @property
    def privileged_ratio_delta(self) -> float:
        return self.current.privileged_ratio - self.baseline.privileged_ratio

    @property
    def call_rate_ratio(self) -> float:
        """current call_rate / baseline call_rate (1.0 = same)."""
        if self.baseline.call_rate_per_hour < 0.001:
            return 0.0
        return self.current.call_rate_per_hour / self.baseline.call_rate_per_hour


# ── Internal helpers ───────────────────────────────────────────────────────────

def _compute_window_metrics(usages: list[dict], window_hours: float) -> WindowMetrics:
    m = WindowMetrics(window_hours=window_hours)
    m.total_calls = len(usages)
    bins: dict[str, int] = defaultdict(int)

    for u in sorted(usages, key=lambda x: x.get("timestamp") or ""):
        tool = (u.get("tool_name") or "unknown").strip()
        dest = (u.get("destination") or "").strip()
        ts   = u.get("timestamp") or ""

        m.tool_counts[tool] = m.tool_counts.get(tool, 0) + 1

        if dest:
            m.dest_counts[dest] = m.dest_counts.get(dest, 0) + 1
            m.unique_destinations.add(dest)

        if is_privileged_tool(tool):
            m.privileged_calls += 1

        m.known_edges.add((tool, dest))
        m.ordered_calls.append({"tool": tool, "dest": dest, "ts": ts})

        # 5-minute burst bins
        if len(ts) >= 16:
            try:
                hh     = int(ts[11:13])
                mm     = int(ts[14:16])
                bin_m  = (mm // 5) * 5
                bin_key = f"{ts[:11]}{hh:02d}:{bin_m:02d}"
                bins[bin_key] += 1
            except (ValueError, IndexError):
                pass

    m.call_rate_per_hour = m.total_calls / max(window_hours, 0.001)
    m.privileged_ratio   = m.privileged_calls / max(m.total_calls, 1)
    m.burst_max          = max(bins.values()) if bins else 0
    return m


# ── Public API ─────────────────────────────────────────────────────────────────

def compute_baselines(
    tool_usages: list[dict],
    pid_map: dict[int, str],
    baseline_window_hours: int   = 168,   # 7 days
    current_window_hours:  float = 1.0,   # last 1 hour = "current"
) -> dict[str, AgentBaseline]:
    """
    Compute per-agent behavioral baselines from snapshot tool_usage records.

    Parameters
    ----------
    tool_usages           : mode-filtered tool_usage list from get_snapshot()
    pid_map               : {principal_id (int) → agent_name (str)}
    baseline_window_hours : look-back for baseline (default 7 days)
    current_window_hours  : recent observation window (default 1 hour)

    Returns
    -------
    dict mapping agent_name → AgentBaseline
    """
    now               = datetime.now(timezone.utc)
    current_cutoff    = now - timedelta(hours=current_window_hours)
    baseline_cutoff   = now - timedelta(hours=baseline_window_hours)
    current_cutoff_s  = current_cutoff.isoformat()
    baseline_cutoff_s = baseline_cutoff.isoformat()

    by_agent: dict[str, list[dict]] = defaultdict(list)
    for u in tool_usages:
        pid  = u.get("principal_id") or 0
        name = pid_map.get(pid, f"unknown-{pid}")
        by_agent[name].append(u)

    result: dict[str, AgentBaseline] = {}
    for agent_name, usages in by_agent.items():
        baseline_usages = [
            u for u in usages
            if baseline_cutoff_s <= (u.get("timestamp") or "") < current_cutoff_s
        ]
        current_usages = [
            u for u in usages
            if (u.get("timestamp") or "") >= current_cutoff_s
        ]
        result[agent_name] = AgentBaseline(
            agent_name=agent_name,
            baseline=_compute_window_metrics(baseline_usages, float(baseline_window_hours)),
            current=_compute_window_metrics(current_usages, current_window_hours),
            baseline_hours=float(baseline_window_hours),
            current_hours=current_window_hours,
        )
    return result
