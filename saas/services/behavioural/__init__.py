"""
AIAAP Behavioural Analytics
-----------------------------
Detects anomalies in agent behaviour using:
  1. Statistical baseline comparison (z-score per metric)
  2. Identity graph drift (new edges, degree spike)
  3. Optional Isolation Forest scoring

Modules:
  baseline.py       - compute and store rolling baselines per principal
  graph_drift.py    - build identity graphs and detect structural drift
  anomaly_scoring.py - z-score computation, flagging, and Finding creation
"""
