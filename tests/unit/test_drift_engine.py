"""
Unit tests for drift scoring math.
No docker required - mocks the DB and baseline records.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


# ── _zscore ────────────────────────────────────────────────────────────────────

def test_zscore_zero_when_at_mean():
    from saas.services.behavioural.drift_engine import _zscore
    assert _zscore(10.0, 10.0, 2.0) == pytest.approx(0.0)


def test_zscore_positive_above_mean():
    from saas.services.behavioural.drift_engine import _zscore
    assert _zscore(13.0, 10.0, 1.0) == pytest.approx(3.0)


def test_zscore_negative_below_mean():
    from saas.services.behavioural.drift_engine import _zscore
    assert _zscore(7.0, 10.0, 1.0) == pytest.approx(-3.0)


def test_zscore_zero_std_returns_zero():
    """Zero std-dev means no baseline variance - z-score should be 0."""
    from saas.services.behavioural.drift_engine import _zscore
    assert _zscore(99.0, 10.0, 0.0) == pytest.approx(0.0)


# ── _zscore_to_points ──────────────────────────────────────────────────────────

def test_zscore_to_points_zero():
    from saas.services.behavioural.drift_engine import _zscore_to_points
    assert _zscore_to_points(0.0, 20) == pytest.approx(0.0)


def test_zscore_to_points_capped_at_max():
    """Very high z-score should be capped at the max cap value."""
    from saas.services.behavioural.drift_engine import _zscore_to_points
    # z=100, cap=20 → min(100 * 20/3, 20) = 20
    pts = _zscore_to_points(100.0, 20)
    assert pts == pytest.approx(20.0)


def test_zscore_to_points_partial():
    from saas.services.behavioural.drift_engine import _zscore_to_points
    # z=1.5, cap=20 → min(1.5 * 20/3, 20) = min(10, 20) = 10
    pts = _zscore_to_points(1.5, 20)
    assert pts == pytest.approx(10.0)


def test_zscore_to_points_negative_z_treated_as_absolute():
    """Negative z-scores (below baseline) still contribute to drift."""
    from saas.services.behavioural.drift_engine import _zscore_to_points
    pts_pos = _zscore_to_points(2.0,  20)
    pts_neg = _zscore_to_points(-2.0, 20)
    assert pts_pos == pts_neg


# ── compute_drift_score (mocked DB) ───────────────────────────────────────────

def _make_baseline_mock(
    calls_per_hour: float = 10.0,
    distinct_dest:  float = 3.0,
    entropy:        float = 1.5,
    privileged_ratio: float = 0.1,
    new_tool_freq:  float = 0.0,
    std_calls:      float = 2.0,
    std_dest:       float = 1.0,
    std_entropy:    float = 0.5,
    std_priv:       float = 0.05,
    std_new_tool:   float = 0.1,
):
    baseline = MagicMock()
    baseline.avg_calls_per_hour   = calls_per_hour
    baseline.avg_distinct_dest    = distinct_dest
    baseline.avg_entropy          = entropy
    baseline.avg_privileged_ratio = privileged_ratio
    baseline.avg_new_tool_freq    = new_tool_freq
    baseline.std_calls_per_hour   = std_calls
    baseline.std_distinct_dest    = std_dest
    baseline.std_entropy          = std_entropy
    baseline.std_privileged_ratio = std_priv
    baseline.std_new_tool_freq    = std_new_tool
    return baseline


def test_drift_score_zero_when_at_baseline():
    """If current metrics exactly match baseline, drift score should be ~0."""
    from saas.services.behavioural.drift_engine import compute_drift_score

    baseline = _make_baseline_mock()

    db = MagicMock()
    # Baseline query returns the mock
    db.query.return_value.filter_by.return_value.first.return_value = baseline

    # Patch compute_current_metrics to return values matching baseline
    current_metrics = {
        "calls_per_hour":    10.0,
        "distinct_dest":     3.0,
        "entropy":           1.5,
        "privileged_ratio":  0.1,
        "new_tool_freq":     0.0,
        "current_tools":     ["tool_a"],
        "current_destinations": ["dest_a"],
        "new_tools":         [],
        "sample_size":       10,
    }

    with patch(
        "saas.services.behavioural.drift_engine.compute_current_metrics",
        return_value=current_metrics,
    ):
        snapshot = compute_drift_score(1, "default", db, window_minutes=60)

    assert snapshot is not None
    # Drift score should be near 0
    assert snapshot.drift_score == pytest.approx(0.0, abs=0.5)


def test_drift_score_high_when_privileged_ratio_spikes():
    """Spiking privileged_ratio should drive drift score up significantly."""
    from saas.services.behavioural.drift_engine import compute_drift_score

    # Baseline: 10% privileged, very low std
    baseline = _make_baseline_mock(privileged_ratio=0.1, std_priv=0.02)

    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = baseline

    # Current: 80% privileged (massive spike)
    current_metrics = {
        "calls_per_hour":    10.0,
        "distinct_dest":     3.0,
        "entropy":           1.5,
        "privileged_ratio":  0.8,   # ← spike
        "new_tool_freq":     0.0,
        "current_tools":     ["tool_a"],
        "current_destinations": ["dest_a"],
        "new_tools":         [],
        "sample_size":       10,
    }

    with patch(
        "saas.services.behavioural.drift_engine.compute_current_metrics",
        return_value=current_metrics,
    ):
        snapshot = compute_drift_score(1, "default", db, window_minutes=60)

    assert snapshot is not None
    # Should be well above alert threshold (60)
    assert snapshot.drift_score > 20.0  # At minimum z_priv contributes significantly


def test_drift_score_no_baseline_returns_none():
    """No baseline → cannot compute drift → returns None."""
    from saas.services.behavioural.drift_engine import compute_drift_score

    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = None  # no baseline

    result = compute_drift_score(1, "default", db, window_minutes=60)
    assert result is None


def test_drift_score_capped_at_100():
    """Drift score must never exceed 100."""
    from saas.services.behavioural.drift_engine import compute_drift_score

    # Absurdly low std → every deviation is enormous z-score
    baseline = _make_baseline_mock(
        std_calls=0.01, std_dest=0.01, std_entropy=0.01,
        std_priv=0.01, std_new_tool=0.01,
    )

    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = baseline

    # Current metrics wildly different
    current_metrics = {
        "calls_per_hour":    1000.0,
        "distinct_dest":     500.0,
        "entropy":           10.0,
        "privileged_ratio":  1.0,
        "new_tool_freq":     1.0,
        "current_tools":     ["tool_a"],
        "current_destinations": ["dest_a"],
        "new_tools":         ["new_tool_x", "new_tool_y"],
        "sample_size":       100,
    }

    with patch(
        "saas.services.behavioural.drift_engine.compute_current_metrics",
        return_value=current_metrics,
    ):
        snapshot = compute_drift_score(1, "default", db, window_minutes=60)

    assert snapshot is not None
    assert snapshot.drift_score <= 100.0


def test_drift_metrics_stored_in_snapshot():
    """The snapshot should include z-score components in its metrics dict."""
    from saas.services.behavioural.drift_engine import compute_drift_score

    baseline = _make_baseline_mock()
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = baseline

    current_metrics = {
        "calls_per_hour":    12.0,
        "distinct_dest":     4.0,
        "entropy":           1.7,
        "privileged_ratio":  0.2,
        "new_tool_freq":     0.1,
        "current_tools":     ["tool_a"],
        "current_destinations": ["dest_a"],
        "new_tools":         [],
        "sample_size":       10,
    }

    with patch(
        "saas.services.behavioural.drift_engine.compute_current_metrics",
        return_value=current_metrics,
    ):
        snapshot = compute_drift_score(1, "default", db, window_minutes=60)

    assert snapshot is not None
    assert "z_calls"    in snapshot.metrics
    assert "z_priv"     in snapshot.metrics
    assert "z_dest"     in snapshot.metrics
    assert "z_entropy"  in snapshot.metrics
    assert "z_new_tool" in snapshot.metrics
