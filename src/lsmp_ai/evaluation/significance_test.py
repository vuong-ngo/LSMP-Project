# ============================================================================
# file: evaluation/significance_test.py
# Description: Statistical significance testing for model comparison (t-test, Wilcoxon).
# ============================================================================

# ===== IMPORT MODULES =====
from itertools import combinations
import numpy as np
from scipy.stats import wilcoxon, ttest_rel

from lsmp_ai.common.logger import setup_logger

logger = setup_logger(__name__)


# ===== PAIRED T-TEST FUNCTION =====
def paired_t_test(scores_a: np.ndarray, scores_b: np.ndarray) -> dict:
    t_stat, p_value = ttest_rel(scores_a, scores_b)
    return {
        "test": "Paired t-test",
        "t_statistic": float(t_stat),
        "p_value": float(p_value),
        "significant": bool(p_value < 0.05),
    }


# ===== WILCOXON SIGNED-RANK FUNCTION =====
def wilcoxon_signed_rank(scores_a: np.ndarray, scores_b: np.ndarray) -> dict:
    stat, p_value = wilcoxon(scores_a, scores_b, alternative="two-sided")
    return {
        "test": "Wilcoxon Signed-Rank",
        "statistic": float(stat),
        "p_value": float(p_value),
        "significant": bool(p_value < 0.05),
    }


# ===== MODEL COMPARISON FUNCTION =====
def compare_models(
    scores_dict: dict[str, np.ndarray],
    test_func=wilcoxon_signed_rank,
) -> dict:
    results = {}

    for (name_a, scores_a), (name_b, scores_b) in combinations(scores_dict.items(), 2):
        key = f"{name_a} vs {name_b}"
        result = test_func(scores_a, scores_b)
        results[key] = result
        sig = "SIGNIFICANT" if result["significant"] else "not significant"
        logger.info(f"{key}: p={result['p_value']:.4f} ({sig})")

    return results
