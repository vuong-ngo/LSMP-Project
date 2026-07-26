# ============================================================================
# file: pipeline/evaluate_pipeline.py
# Description: Pipeline workflow for model ablation evaluation and benchmarking.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import pandas as pd
from sklearn.model_selection import train_test_split

from lsmp_ai.common.config_loader import DataConfig, ModelConfig
from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.evaluation.ablation import run_ablation_study
from lsmp_ai.evaluation.metrics import compute_classification_metrics
from lsmp_ai.io.data_loader import DataLoader
from lsmp_ai.io.result_writer import ResultWriter

logger = setup_logger(__name__)


# ===== EVALUATE PIPELINE CLASS =====
class EvaluatePipeline:
    def __init__(
        self,
        data_config: DataConfig,
        model_config: ModelConfig,
        data_loader: DataLoader | None = None,
        result_writer: ResultWriter | None = None,
    ):
        self.data_config = data_config
        self.model_config = model_config
        self.data_loader = data_loader or DataLoader()
        self.result_writer = result_writer or (
            ResultWriter(self.data_loader._db) if hasattr(self.data_loader, "_db") and self.data_loader._db else None
        )

    def run(
        self,
        dataset_path: str | None = None,
        output_path: str = "reports/results/bang_3_1_so_sanh_baseline.csv",
    ) -> pd.DataFrame:
        if dataset_path:
            df = self.data_loader.load_from_csv(dataset_path)
        else:
            df = self.data_loader.load_from_db()

        X = df[FEATURE_COLUMNS].values
        y = self.data_loader.prepare_labels(df["label"])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=(1 - self.data_config.train_ratio),
            random_state=42,
        )

        iforest_params = {
            "n_estimators": self.model_config.iforest.n_estimators[0],
            "max_samples": self.model_config.iforest.max_samples[0],
            "contamination": self.model_config.iforest.contamination[0],
        }
        ocsvm_params = {
            "kernel": self.model_config.ocsvm.kernel[0],
            "nu": self.model_config.ocsvm.nu[0],
            "gamma": self.model_config.ocsvm.gamma[0],
        }

        results = run_ablation_study(
            X_train, X_test, y_test,
            y_train=y_train,
            iforest_params=iforest_params,
            ocsvm_params=ocsvm_params,
            cascade_threshold=self.model_config.cascade.threshold_percentile,
        )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        results.to_csv(output_path)
        logger.info(f"Results saved to {output_path}")

        # Persist metrics to evaluation_metrics database table
        if self.result_writer and "Cascade iForest→OCSVM" in results.index:
            try:
                cascade_metrics = results.loc["Cascade iForest→OCSVM"].to_dict()
                self.result_writer.write_metrics(
                    metrics_dict=cascade_metrics,
                    model_config="cascade_iforest_ocsvm",
                    model_version="cascade-v1.0",
                    dataset_split="test",
                    hyperparameters={"iforest": iforest_params, "ocsvm": ocsvm_params}
                )
                logger.info("Evaluation metrics successfully written to evaluation_metrics table.")
            except Exception as e:
                logger.warning(f"Could not persist evaluation metrics to database: {e}")

        return results
