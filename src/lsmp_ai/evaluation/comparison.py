# ============================================================================
# file: evaluation/comparison.py
# Description: Model comparator for benchmarking Isolation Forest, OCSVM, and Cascade models.
# ============================================================================

# ===== IMPORT MODULES =====
import time
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.evaluation.metrics import compute_classification_metrics
from lsmp_ai.evaluation.benchmark_runner import benchmark_inference, BenchmarkResult
from lsmp_ai.evaluation.significance_test import compare_models
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel

logger = setup_logger(__name__)


# ===== MODEL COMPARATOR CLASS =====
class ModelComparator:
    """Orchestrates comprehensive comparison between Isolation Forest, One-Class SVM,
    and Cascade (iForest -> OCSVM) models.
    """

    def __init__(
        self,
        iforest_params: Optional[Dict[str, Any]] = None,
        ocsvm_params: Optional[Dict[str, Any]] = None,
        cascade_threshold: int = 80,
        benchmark_runs: int = 50,
        random_state: int = 42,
    ):
        self.iforest_params = iforest_params or {
            "n_estimators": 100,
            "max_samples": "auto",
            "contamination": 0.05,
            "random_state": random_state,
        }
        self.ocsvm_params = ocsvm_params or {
            "kernel": "rbf",
            "nu": 0.05,
            "gamma": "scale",
        }
        self.cascade_threshold = cascade_threshold
        self.benchmark_runs = benchmark_runs
        self.random_state = random_state

    def compare(
        self,
        X_train: np.ndarray | pd.DataFrame,
        X_test: np.ndarray | pd.DataFrame,
        y_test: np.ndarray | pd.Series,
        y_train: Optional[np.ndarray | pd.Series] = None,
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        logger.info("Initializing model comparison (iForest vs OCSVM vs Cascade)...")

        model_iforest = IForestModel(**self.iforest_params)
        model_ocsvm = OCSVMModel(**self.ocsvm_params)
        model_cascade = CascadeModel(
            iforest=IForestModel(**self.iforest_params),
            ocsvm=OCSVMModel(**self.ocsvm_params),
            threshold_percentile=self.cascade_threshold,
        )

        models = {
            "Isolation Forest": model_iforest,
            "One-Class SVM": model_ocsvm,
            "Cascade (iForest->OCSVM)": model_cascade,
        }

        eval_records = {}
        scores_dict = {}
        full_details = {
            "models": {},
            "significance_tests": {},
        }

        for model_name, model in models.items():
            logger.info(f"Training and evaluating model: {model_name}")

            start_train = time.perf_counter()
            model.fit(X_train, y_train)
            train_time_sec = time.perf_counter() - start_train

            y_pred = model.predict(X_test)
            y_score = model.score(X_test)
            scores_dict[model_name] = y_score

            class_metrics = compute_classification_metrics(y_test, y_pred, y_score)

            bench_res: BenchmarkResult = benchmark_inference(
                model=model,
                X=X_test,
                n_runs=self.benchmark_runs,
                model_name=model_name,
            )

            record = {
                **class_metrics,
                "train_time_sec": float(train_time_sec),
                "latency_mean_ms": bench_res.latency_mean_ms,
                "latency_p99_ms": bench_res.latency_p99_ms,
                "throughput_rows_sec": bench_res.throughput_rows_per_sec,
            }
            eval_records[model_name] = record

            full_details["models"][model_name] = {
                "metrics": class_metrics,
                "benchmark": {
                    "latency_mean_ms": bench_res.latency_mean_ms,
                    "latency_std_ms": bench_res.latency_std_ms,
                    "latency_p99_ms": bench_res.latency_p99_ms,
                    "throughput_rows_per_sec": bench_res.throughput_rows_per_sec,
                },
                "training_time_sec": train_time_sec,
            }

        try:
            sig_results = compare_models(scores_dict)
            full_details["significance_tests"] = sig_results
        except Exception as e:
            logger.warning(f"Failed to calculate statistical significance: {e}")

        df_comparison = pd.DataFrame(eval_records).T
        df_comparison.index.name = "Model"

        logger.info(f"\nModel Comparison Results Summary:\n{df_comparison.to_string()}")
        return df_comparison, full_details


# ===== HELPER FUNCTION =====
def run_iforest_ocsvm_comparison(
    X_train: np.ndarray | pd.DataFrame,
    X_test: np.ndarray | pd.DataFrame,
    y_test: np.ndarray | pd.Series,
    y_train: Optional[np.ndarray | pd.Series] = None,
    iforest_params: Optional[Dict[str, Any]] = None,
    ocsvm_params: Optional[Dict[str, Any]] = None,
    cascade_threshold: int = 80,
    benchmark_runs: int = 50,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    comparator = ModelComparator(
        iforest_params=iforest_params,
        ocsvm_params=ocsvm_params,
        cascade_threshold=cascade_threshold,
        benchmark_runs=benchmark_runs,
    )
    return comparator.compare(X_train, X_test, y_test, y_train=y_train)
