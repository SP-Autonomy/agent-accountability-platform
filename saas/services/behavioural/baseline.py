"""
Behavioral Baseline Computation
---------------------------------
Computes rolling statistical baselines for each agent principal.
Baselines are derived from hourly buckets of ToolUsage data over the
last 7 days and stored in the BehavioralBaseline table.

Metrics computed per principal:
  mean_calls_per_hour     - avg tool calls per hour across 7-day window
  std_calls_per_hour      - standard deviation of that hourly count
  mean_distinct_dest      - avg unique destinations per hour
  std_distinct_dest       - std of unique destinations per hour
  mean_entropy            - avg Shannon entropy of destination distribution
  std_entropy             - std of destination entropy
  mean_privileged_ratio   - avg ratio of privileged to total calls
  std_privileged_ratio    - std of that ratio
  mean_new_tool_freq      - avg ratio of first-time tools per hour
  std_new_tool_freq       - std of that ratio
  known_tools             - all tool names ever called (graph edge set)
  known_destinations      - all destinations ever accessed
  known_namespaces        - all k8s namespaces seen
  baseline_degree         - total unique edges in the identity graph
  observations            - number of hourly buckets used
"""

import math
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import structlog

from saas.services.shared.database import SessionLocal
from saas.services.shared.models import ToolUsage, NormalizedEvent, BehavioralBaseline, AgentPrincipal

logger = structlog.get_logger()

BASELINE_WINDOW_DAYS = 7
MIN_OBSERVATIONS = 3       # minimum hourly buckets before scoring is meaningful

# Tools / destinations considered privileged
_PRIVILEGED_TOOLS = {
    "read_secrets", "write_secrets", "exec_command", "deploy_infrastructure",
    "modify_iam_policy", "create_role", "attach_policy", "update_cluster",
    "delete_resource", "kubectl_exec",
}
_SENSITIVE_DEST_PREFIXES = (
    "169.254.", "metadata.google", "vault.", "secrets.", "kms.",
    "iam.amazonaws", "sts.amazonaws",
)


def _is_privileged_tool(tool_name: str) -> bool:
    return tool_name.lower() in _PRIVILEGED_TOOLS


def _is_sensitive_dest(dest: str | None) -> bool:
    if not dest:
        return False
    return any(dest.lower().startswith(p) for p in _SENSITIVE_DEST_PREFIXES)


def _shannon_entropy(counts: list[int]) -> float:
    """Shannon entropy H of a count distribution. Returns 0 for empty input."""
    total = sum(counts)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def _mean_std(values: list[float]) -> tuple[float, float]:
    """Return (mean, std) for a list of floats. Returns (0, 1) for empty / single-value."""
    n = len(values)
    if n == 0:
        return 0.0, 1.0
    mean = sum(values) / n
    if n == 1:
        return mean, 1.0
    variance = sum((v - mean) ** 2 for v in values) / n
    return mean, max(math.sqrt(variance), 0.01)   # floor std at 0.01 to avoid div-by-zero


def compute_baseline(principal_id: int, tenant_id: str, db) -> BehavioralBaseline | None:
    """
    Compute or update the behavioral baseline for a single principal.
    Groups ToolUsage records into hourly buckets over the last BASELINE_WINDOW_DAYS days.
    Returns a (possibly new) BehavioralBaseline ORM object (not yet committed).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=BASELINE_WINDOW_DAYS)

    usages = (
        db.query(ToolUsage)
          .filter(
              ToolUsage.principal_id == principal_id,
              ToolUsage.tenant_id    == tenant_id,
              ToolUsage.timestamp    >= cutoff,
          )
          .order_by(ToolUsage.timestamp.asc())
          .all()
    )

    if not usages:
        return None

    # ── Build hourly buckets ──────────────────────────────────────────────────
    # bucket key: (year, month, day, hour)
    buckets: dict[tuple, list[ToolUsage]] = defaultdict(list)
    for u in usages:
        ts = u.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        key = (ts.year, ts.month, ts.day, ts.hour)
        buckets[key].append(u)

    if len(buckets) < 1:
        return None

    # Per-bucket metrics
    calls_per_hour:    list[float] = []
    distinct_dest_h:   list[float] = []
    entropy_h:         list[float] = []
    priv_ratio_h:      list[float] = []
    new_tool_freq_h:   list[float] = []

    all_tools_seen:    set[str] = set()
    all_dests_seen:    set[str] = set()

    for bucket_usages in sorted(buckets.values(), key=lambda b: b[0].timestamp):
        n = len(bucket_usages)
        calls_per_hour.append(float(n))

        dests = [u.destination for u in bucket_usages if u.destination]
        dest_counts = defaultdict(int)
        for d in dests:
            dest_counts[d] += 1
        distinct_dest_h.append(float(len(dest_counts)))
        entropy_h.append(_shannon_entropy(list(dest_counts.values())))

        priv_count = sum(1 for u in bucket_usages if _is_privileged_tool(u.tool_name or ""))
        priv_ratio_h.append(priv_count / n if n else 0.0)

        new_tools = [u.tool_name for u in bucket_usages
                     if u.tool_name and u.tool_name not in all_tools_seen]
        new_tool_freq_h.append(len(new_tools) / n if n else 0.0)

        all_tools_seen.update(u.tool_name for u in bucket_usages if u.tool_name)
        all_dests_seen.update(u.destination for u in bucket_usages if u.destination)

    # Also pull namespaces from NormalizedEvent for this principal
    events = (
        db.query(NormalizedEvent.dest)
          .filter(
              NormalizedEvent.principal_id == principal_id,
              NormalizedEvent.tenant_id    == tenant_id,
              NormalizedEvent.timestamp    >= cutoff,
          )
          .all()
    )
    known_namespaces = list({row.dest for row in events if row.dest})

    # ── Aggregate stats ───────────────────────────────────────────────────────
    mean_cph, std_cph   = _mean_std(calls_per_hour)
    mean_dd,  std_dd    = _mean_std(distinct_dest_h)
    mean_ent, std_ent   = _mean_std(entropy_h)
    mean_pr,  std_pr    = _mean_std(priv_ratio_h)
    mean_ntf, std_ntf   = _mean_std(new_tool_freq_h)

    degree = len(all_tools_seen) + len(all_dests_seen) + len(known_namespaces)

    # ── Upsert BehavioralBaseline ─────────────────────────────────────────────
    existing = (
        db.query(BehavioralBaseline)
          .filter_by(principal_id=principal_id, tenant_id=tenant_id)
          .first()
    )
    if existing:
        bl = existing
    else:
        bl = BehavioralBaseline(principal_id=principal_id, tenant_id=tenant_id)
        db.add(bl)

    bl.computed_at          = datetime.now(timezone.utc)
    bl.mean_calls_per_hour  = mean_cph
    bl.std_calls_per_hour   = std_cph
    bl.mean_distinct_dest   = mean_dd
    bl.std_distinct_dest    = std_dd
    bl.mean_entropy         = mean_ent
    bl.std_entropy          = std_ent
    bl.mean_privileged_ratio = mean_pr
    bl.std_privileged_ratio  = std_pr
    bl.mean_new_tool_freq   = mean_ntf
    bl.std_new_tool_freq    = std_ntf
    bl.known_tools          = sorted(all_tools_seen)
    bl.known_destinations   = sorted(all_dests_seen)
    bl.known_namespaces     = known_namespaces
    bl.baseline_degree      = degree
    bl.observations         = len(buckets)

    return bl


def compute_current_metrics(principal_id: int, tenant_id: str, db) -> dict:
    """
    Compute metrics for the last hour (the 'current' window to compare against baseline).
    Returns a dict with the same keys as the baseline mean fields.
    """
    cutoff_1h = datetime.now(timezone.utc) - timedelta(hours=1)

    usages = (
        db.query(ToolUsage)
          .filter(
              ToolUsage.principal_id == principal_id,
              ToolUsage.tenant_id    == tenant_id,
              ToolUsage.timestamp    >= cutoff_1h,
          )
          .all()
    )

    n = len(usages)
    if n == 0:
        return {
            "calls_per_hour": 0.0,
            "distinct_dest": 0.0,
            "entropy": 0.0,
            "privileged_ratio": 0.0,
            "new_tool_freq": 0.0,
            "current_tools": [],
            "current_destinations": [],
            "sample_size": 0,
        }

    dests = [u.destination for u in usages if u.destination]
    dest_counts: dict[str, int] = defaultdict(int)
    for d in dests:
        dest_counts[d] += 1

    priv = sum(1 for u in usages if _is_privileged_tool(u.tool_name or ""))

    # "new tool" = tool seen in this hour that has no ToolUsage before the last hour
    all_tools_before = set(
        r.tool_name for r in db.query(ToolUsage.tool_name)
                                .filter(
                                    ToolUsage.principal_id == principal_id,
                                    ToolUsage.tenant_id    == tenant_id,
                                    ToolUsage.timestamp    < cutoff_1h,
                                )
                                .all()
        if r.tool_name
    )
    current_tools = [u.tool_name for u in usages if u.tool_name]
    new_tools = [t for t in current_tools if t not in all_tools_before]

    return {
        "calls_per_hour":    float(n),
        "distinct_dest":     float(len(dest_counts)),
        "entropy":           _shannon_entropy(list(dest_counts.values())),
        "privileged_ratio":  priv / n,
        "new_tool_freq":     len(new_tools) / n if n else 0.0,
        "current_tools":     list(set(current_tools)),
        "current_destinations": list(dest_counts.keys()),
        "new_tools":         list(set(new_tools)),
        "sample_size":       n,
    }


def update_all_baselines(tenant_id: str = "default") -> int:
    """
    Background task: recompute baselines for all principals of a tenant.
    Called from the behavioral analysis loop every BASELINE_UPDATE_INTERVAL seconds.
    Returns the number of baselines updated.
    """
    db = SessionLocal()
    updated = 0
    try:
        principals = (
            db.query(AgentPrincipal)
              .filter(AgentPrincipal.tenant_id == tenant_id)
              .all()
        )
        for p in principals:
            try:
                bl = compute_baseline(p.id, tenant_id, db)
                if bl is not None:
                    db.commit()
                    updated += 1
            except Exception as exc:
                logger.warning("baseline_update_failed", principal_id=p.id, error=str(exc))
                db.rollback()
    finally:
        db.close()
    return updated
