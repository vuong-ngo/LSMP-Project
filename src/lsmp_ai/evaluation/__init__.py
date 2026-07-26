# ============================================================================
# file: evaluation/__init__.py
# Description: Model evaluation package providing classification metrics,
#              ablation studies, benchmark latency runner, and significance tests.
# ============================================================================

from lsmp_ai.evaluation.comparison import ModelComparator, run_iforest_ocsvm_comparison
from lsmp_ai.evaluation.metrics import compute_classification_metrics, compute_confusion_matrix_df
from lsmp_ai.evaluation.benchmark_runner import benchmark_inference, BenchmarkResult
from lsmp_ai.evaluation.ablation import run_ablation_study
from lsmp_ai.evaluation.significance_test import paired_t_test, wilcoxon_signed_rank, compare_models

__all__ = [
    "ModelComparator",
    "run_iforest_ocsvm_comparison",
    "compute_classification_metrics",
    "compute_confusion_matrix_df",
    "benchmark_inference",
    "BenchmarkResult",
    "run_ablation_study",
    "paired_t_test",
    "wilcoxon_signed_rank",
    "compare_models",
]
