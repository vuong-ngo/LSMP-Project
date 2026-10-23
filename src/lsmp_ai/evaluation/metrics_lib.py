"""
metrics_lib.py — Unified metric library for intrusion anomaly detection.
100% compatible with SME research paper metrics and evaluation pipeline.

Theoretical foundations:
- Axelsson (2000), "The Base-Rate Fallacy and Its Implications for the Difficulty
  of Intrusion Detection", ACM TISSEC 3(3). DOI: 10.1145/357830.357849
- Gu et al. (2006), "An Information-Theoretic Measure of Intrusion Detection Capability" (C_ID).
- Saito & Rehmsmeier (2015), PLOS ONE 10(3), DOI: 10.1371/journal.pone.0118432
"""
from __future__ import annotations

from lsmp_ai.evaluation.metrics import (
    basic_metrics,
    ranking_metrics,
    bayesian_detection_rate,
    bdr_table,
    alarms_per_hour,
    cid,
    bootstrap_ci,
    pick_threshold,
    recall_at_k,
    full_report,
    rule_only_score,
    to_binary_labels,
    compute_classification_metrics,
    compute_confusion_matrix_df,
)

__all__ = [
    "basic_metrics",
    "ranking_metrics",
    "bayesian_detection_rate",
    "bdr_table",
    "alarms_per_hour",
    "cid",
    "bootstrap_ci",
    "pick_threshold",
    "recall_at_k",
    "full_report",
    "rule_only_score",
    "to_binary_labels",
    "compute_classification_metrics",
    "compute_confusion_matrix_df",
]
