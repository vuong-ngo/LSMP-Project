# ============================================================================
# file: evaluation/__init__.py
# Description: Model evaluation package providing classification metrics,
#              ablation studies, benchmark latency runner, and significance tests.
# ============================================================================

from lsmp_ai.evaluation.comparison import ModelComparator, run_iforest_ocsvm_comparison
from lsmp_ai.evaluation.metrics import (
    compute_classification_metrics,
    compute_confusion_matrix_df,
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
)
from lsmp_ai.evaluation.benchmark_runner import benchmark_inference, BenchmarkResult
from lsmp_ai.evaluation.ablation import (
    run_ablation_study,
    run_feature_group_ablation,
    run_hyperparameter_sensitivity,
    run_gate_rate_sweep,
)
from lsmp_ai.evaluation.significance_test import paired_t_test, wilcoxon_signed_rank, compare_models
from lsmp_ai.evaluation import metrics_lib

__all__ = [
    "ModelComparator",
    "run_iforest_ocsvm_comparison",
    "compute_classification_metrics",
    "compute_confusion_matrix_df",
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
    "benchmark_inference",
    "BenchmarkResult",
    "run_ablation_study",
    "run_feature_group_ablation",
    "run_hyperparameter_sensitivity",
    "run_gate_rate_sweep",
    "paired_t_test",
    "wilcoxon_signed_rank",
    "compare_models",
    "metrics_lib",
]
