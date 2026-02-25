"""
Risk Graph Engine - blast radius computation via agent access graph.

Builds an agent → tool → destination graph from observed tool_usage records.
Produces a blast-radius score per agent, top reachable high-risk nodes,
and a human-readable "why" explanation.

Usage:
    from utils.risk_graph import compute_risk_graph

    graph = compute_risk_graph(snap["tool_usages"], snap["pid_map"])
    # graph: dict[agent_name, {blast_radius_score, why, top_high_risk, ...}]
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from utils.baseline_engine import is_high_risk_destination, is_privileged_tool


# ── Score model ────────────────────────────────────────────────────────────────
# Component 1: Destination breadth  - scales 0 → 40 pts over 0 → 20 unique dests
# Component 2: High-risk dests      - +8 pts per unique high-risk dest, cap 40 pts
# Component 3: Privileged edges     - +6 pts per unique privileged (tool, dest) pair, cap 30 pts
# New-edge multiplier               - up to ×1.30 boost if many unseen edges
# Final score capped at 100.

DEST_BREADTH_SCALE   = 40.0   # max pts for destination diversity
DEST_BREADTH_MAX     = 20     # destinations that saturate the breadth component
HIGH_RISK_PTS_EACH   = 8.0    # pts per unique high-risk destination
HIGH_RISK_PTS_CAP    = 40.0   # cap on high-risk destination component
PRIV_EDGE_PTS_EACH   = 6.0    # pts per unique privileged (tool, dest) edge
PRIV_EDGE_PTS_CAP    = 30.0   # cap on privileged edge component
NEW_EDGE_BOOST_MAX   = 0.30   # max multiplier boost for new edges (1.0 + 0.30)
MAX_SCORE            = 100.0


def compute_risk_graph(
    tool_usages: list[dict],
    pid_map: dict[int, str],
    baseline_usages: list[dict] | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Build access graph from tool_usages and compute blast radius per agent.

    Parameters
    ----------
    tool_usages     : tool_usage records (mode-filtered, from get_snapshot)
    pid_map         : {principal_id (int) → agent_name (str)}
    baseline_usages : older records for baseline edge comparison (optional).
                      Pass snap["tool_usages_raw"] filtered to older window if available.

    Returns
    -------
    dict mapping agent_name → plain dict with blast radius details.
    """
    # Collect baseline edges per agent (for new-edge detection)
    baseline_edges: dict[str, set[tuple[str, str]]] = defaultdict(set)
    if baseline_usages:
        for u in baseline_usages:
            pid  = u.get("principal_id") or 0
            name = pid_map.get(pid, f"unknown-{pid}")
            tool = (u.get("tool_name") or "unknown").strip()
            dest = (u.get("destination") or "").strip()
            baseline_edges[name].add((tool, dest))

    # Aggregate per-agent (tool, dest) call counts
    td_counts: dict[str, dict[tuple[str, str], int]] = defaultdict(lambda: defaultdict(int))
    for u in tool_usages:
        pid  = u.get("principal_id") or 0
        name = pid_map.get(pid, f"unknown-{pid}")
        if name.startswith("unknown"):
            continue
        tool = (u.get("tool_name") or "unknown").strip()
        dest = (u.get("destination") or "").strip()
        td_counts[name][(tool, dest)] += 1

    result: dict[str, dict[str, Any]] = {}

    for agent_name, edges_map in td_counts.items():
        tools_seen:   set[str] = set()
        dests_seen:   set[str] = set()
        priv_edges:   int      = 0
        new_edges:    int      = 0
        baseline_e           = baseline_edges.get(agent_name, set())

        for (tool, dest), _count in edges_map.items():
            tools_seen.add(tool)
            if dest:
                dests_seen.add(dest)
            if is_privileged_tool(tool):
                priv_edges += 1
            if (tool, dest) not in baseline_e:
                new_edges += 1

        high_risk_dests = [d for d in dests_seen if d and is_high_risk_destination(d)]
        n_dest          = len([d for d in dests_seen if d])

        # ── Score components ──────────────────────────────────────────────────
        dest_pts     = min(n_dest / DEST_BREADTH_MAX * DEST_BREADTH_SCALE, DEST_BREADTH_SCALE)
        hrd_pts      = min(len(high_risk_dests) * HIGH_RISK_PTS_EACH, HIGH_RISK_PTS_CAP)
        priv_pts     = min(priv_edges * PRIV_EDGE_PTS_EACH, PRIV_EDGE_PTS_CAP)
        new_edge_mult = 1.0 + min(new_edges * 0.04, NEW_EDGE_BOOST_MAX)

        raw_score = (dest_pts + hrd_pts + priv_pts) * new_edge_mult
        score     = min(raw_score, MAX_SCORE)

        # ── Why explanation ───────────────────────────────────────────────────
        why_parts: list[str] = []
        if hrd_pts > 0:
            why_parts.append(
                f"{len(high_risk_dests)} high-risk destination(s) "
                f"[{', '.join(high_risk_dests[:3])}{'...' if len(high_risk_dests) > 3 else ''}] "
                f"(+{hrd_pts:.0f} pts)"
            )
        if priv_pts > 0:
            why_parts.append(f"{priv_edges} privileged tool edge(s) (+{priv_pts:.0f} pts)")
        if dest_pts > 0:
            why_parts.append(f"{n_dest} unique destination(s) (+{dest_pts:.0f} pts)")
        if new_edges > 0:
            why_parts.append(f"{new_edges} unseen edge(s) (×{new_edge_mult:.2f} multiplier)")
        why = "; ".join(why_parts) if why_parts else "No significant blast radius factors observed."

        result[agent_name] = {
            "agent_name":              agent_name,
            "blast_radius_score":      round(score, 1),
            "unique_destinations":     n_dest,
            "unique_tools":            len(tools_seen),
            "privileged_edges":        priv_edges,
            "new_edges":               new_edges,
            "high_risk_destinations":  high_risk_dests,
            "top_reachable_high_risk": high_risk_dests[:5],
            "why":                     why,
            "score_components": {
                "destination_breadth_pts": round(dest_pts, 1),
                "high_risk_dest_pts":      round(hrd_pts, 1),
                "privileged_edges_pts":    round(priv_pts, 1),
                "new_edge_multiplier":     round(new_edge_mult, 3),
                "raw_score":               round(raw_score, 1),
                "final_score":             round(score, 1),
            },
        }

    return result
