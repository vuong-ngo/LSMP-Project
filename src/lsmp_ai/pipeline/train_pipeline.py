# ============================================================================
# file: pipeline/train_pipeline.py
# Description: Pipeline workflow for training, preprocessing, and model registry serialization.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config, DataConfig, ModelConfig
from lsmp_ai.common.exceptions import ModelTrainingError
from lsmp_ai.common.constants import LABEL_NORMAL, LABEL_ANOMALY, FEATURE_COLUMNS
from lsmp_ai.io.db_client import DBClient
from lsmp_ai.io.data_loader import DataLoader
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry


# ===== TRAIN PIPELINE CLASS =====
class TrainPipeline:
    def __init__(
        self,
        data_config: DataConfig | None = None,
        model_config: ModelConfig | None = None,
        data_loader: DataLoader | None = None,
        model_registry: ModelRegistry | None = None,
    ):
        self.data_config = data_config or (getattr(config, "data_config", None) if config else DataConfig())
        self.model_config = model_config or (getattr(config, "model_config", None) if config else ModelConfig())
        self.data_loader = data_loader or DataLoader()
        self.model_registry = model_registry or ModelRegistry(
            registry_dir=getattr(self.model_config, "model_store_path", None)
        )

    def run(
        self, 
        dataset_path: str | None = None, 
        do_grid_search: bool = False, 
        model_version: str = "cascade-v1.0"
    ) -> str:
        """Executes full training pipeline, fitting feature pipeline and CascadeModel."""
        logger.info("Initializing TrainPipeline run...")
        if dataset_path:
            df_raw = self.data_loader.load_from_csv(dataset_path)
        else:
            try:
                df_raw = self.data_loader.load_from_db()
            except Exception as e:
                logger.warning(f"Could not load data from DB: {e}. Checking fallback CSV.")
                df_raw = pd.DataFrame()

        if df_raw.empty:
            fallback_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                "data", "processed", "dataset.csv"
            )
            if not os.path.exists(fallback_path):
                logger.info("Processed dataset not found. Triggering automated CICIDS2017 dataset preparation...")
                try:
                    from scripts.prepare_data import prepare_dataset
                    prepare_dataset()
                except Exception as prep_err:
                    logger.warning(f"Could not prepare CICIDS2017 dataset: {prep_err}")

            if os.path.exists(fallback_path):
                df_raw = self.data_loader.load_from_csv(fallback_path)
            else:
                raise ModelTrainingError("Training dataset is empty. Cannot train model.")

        if 'label' not in df_raw.columns:
            logger.warning("No 'label' column found in raw features. Assuming all samples are benign baseline.")
            df_raw['label'] = LABEL_NORMAL

        # Policy A2: Separate unknown samples into data/unlabeled/ (never train on unknowns)
        df_labeled, df_unknown = DataLoader.audit_and_separate_unknowns(df_raw, label_col='label')
        if not df_unknown.empty:
            logger.info(f"Policy A2: Separated {len(df_unknown)} unknown samples to data/unlabeled/unlabeled_samples.csv; excluded from training.")
        df_raw = df_labeled

        # Standardize benign / attack / anomaly aliases to canonical labels
        from lsmp_ai.common.constants import LABEL_NORMAL_ALIASES, LABEL_ANOMALY_ALIASES
        s_lbl = df_raw['label'].astype(str).str.strip().str.lower()
        df_raw.loc[s_lbl.isin(LABEL_NORMAL_ALIASES), 'label'] = LABEL_NORMAL
        df_raw.loc[s_lbl.isin(LABEL_ANOMALY_ALIASES), 'label'] = LABEL_ANOMALY

        feature_cols = config.features if (config and hasattr(config, "features") and config.features) else list(FEATURE_COLUMNS)
        missing_feats = [col for col in feature_cols if col not in df_raw.columns]
        if missing_feats:
            logger.warning(f"Missing feature columns in training data: {missing_feats}. Creating zeros.")
            for col in missing_feats:
                df_raw[col] = 0.0

        total_samples = len(df_raw)
        normal_count = int((df_raw['label'] == LABEL_NORMAL).sum())
        anomaly_count = int((df_raw['label'] == LABEL_ANOMALY).sum())

        val_df = pd.DataFrame()
        val_ratio = getattr(self.data_config, "val_ratio", 0.0)
        train_ratio = getattr(self.data_config, "train_ratio", 0.6)

        df_normal = df_raw[df_raw['label'] == LABEL_NORMAL]
        df_anomaly = df_raw[df_raw['label'] == LABEL_ANOMALY]

        if val_ratio > 0.0:
            test_ratio = getattr(self.data_config, "test_ratio", 0.2)
            try:
                from scripts.prepare_data import temporal_split
            except ImportError:
                def temporal_split(df: pd.DataFrame, frac=(0.6, 0.2, 0.2)):
                    sort_col = "window_end" if "window_end" in df.columns else ("timestamp" if "timestamp" in df.columns else None)
                    df_s = df.sort_values(sort_col).reset_index(drop=True) if sort_col else df.reset_index(drop=True)
                    n_s = len(df_s)
                    i1_s = int(n_s * frac[0])
                    i2_s = int(n_s * (frac[0] + frac[1]))
                    return df_s.iloc[:i1_s], df_s.iloc[i1_s:i2_s], df_s.iloc[i2_s:]

            tr, va, te = temporal_split(df_raw, frac=(train_ratio, val_ratio, test_ratio))
            train_df = tr[tr['label'] == LABEL_NORMAL].reset_index(drop=True)
            val_df = va.reset_index(drop=True)
            test_df = te.reset_index(drop=True)
            logger.info(
                f"SME-kit 3-way Temporal Split: Train={len(train_df)} (Pure Normal), "
                f"Val={len(val_df)} (Normal: {(val_df['label']==LABEL_NORMAL).sum()}, Anom: {(val_df['label']==LABEL_ANOMALY).sum()}), "
                f"Test={len(test_df)} (Normal: {(test_df['label']==LABEL_NORMAL).sum()}, Anom: {(test_df['label']==LABEL_ANOMALY).sum()})"
            )
        elif not df_normal.empty and not df_anomaly.empty:
            test_ratio = 1.0 - train_ratio
            df_normal_train, df_normal_test = train_test_split(
                df_normal, test_size=test_ratio, random_state=42
            )
            train_df = df_normal_train.reset_index(drop=True)
            test_df = pd.concat(
                [df_normal_test, df_anomaly], ignore_index=True
            ).sample(frac=1.0, random_state=42).reset_index(drop=True)
            logger.info(
                f"One-Class Split: Train={len(train_df)} (100% Normal), "
                f"Test={len(test_df)} (Normal: {len(df_normal_test)}, Anomaly: {len(df_anomaly)})"
            )
        else:
            test_ratio = 1.0 - train_ratio
            strat = df_raw['label'] if ('label' in df_raw.columns and len(df_raw['label'].unique()) > 1) else None
            train_df, test_df = train_test_split(
                df_raw, test_size=test_ratio, random_state=42, stratify=strat
            )

        if train_df.empty:
            raise ModelTrainingError(
                "No benign samples are available in the training partition. "
                "Refusing to fit novelty detectors on attack data."
            )

        if (train_df['label'] != LABEL_NORMAL).any():
            raise ModelTrainingError(
                "Training partition contains non-benign samples. "
                "Refusing to fit novelty detectors outside train_benign."
            )

        feat_pipeline = FeaturePipeline()
        X_train_scaled = feat_pipeline.fit_transform(train_df)
        X_val_scaled = feat_pipeline.transform(val_df) if not val_df.empty else None
        y_val = val_df['label'].values if not val_df.empty else None

        cascade_params = config.cascade_params if (config and hasattr(config, "cascade_params")) else {}
        cascade_params["model_version"] = model_version
        
        gate_rate = cascade_params.get("gate_rate", 0.20)
        w_stage1 = cascade_params.get("w_stage1", 0.40)
        cascade_model = CascadeModel(gate_rate=gate_rate, w_stage1=w_stage1, cascade_params=cascade_params)
        thresh_cfg = config.threshold_params if (config and hasattr(config, "threshold_params")) else {}
        criterion = thresh_cfg.get("criterion", "fpr_budget")
        max_fpr = float(thresh_cfg.get("max_fpr", 0.02))
        cascade_model.fit(
            X_train_scaled,
            train_df['label'].values,
            X_val=X_val_scaled,
            y_val=y_val,
            criterion=criterion,
            max_fpr=max_fpr,
        )

        metrics = {}
        confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        if len(test_df['label'].unique()) > 1:
            X_test_scaled = feat_pipeline.transform(test_df)
            preds = cascade_model.predict(X_test_scaled)
            scores = cascade_model.score(X_test_scaled)
            
            from lsmp_ai.evaluation.metrics import compute_classification_metrics
            metrics = compute_classification_metrics(test_df['label'].values, preds, scores)
            confusion = {
                "tp": metrics.get("tp", 0),
                "fp": metrics.get("fp", 0),
                "tn": metrics.get("tn", 0),
                "fn": metrics.get("fn", 0)
            }
            try:
                timing_bench = cascade_model.benchmark_timing(X_test_scaled)
                metrics["compute_saving_vs_ocsvm_only"] = timing_bench.get("compute_saving_vs_ocsvm_only", 0.0)
                metrics["gate_rate_actual"] = timing_bench.get("gate_rate_actual", 0.0)
            except Exception as bench_err:
                logger.warning(f"Could not compute timing benchmark: {bench_err}")
        else:
            logger.warning(
                f"Test dataset contains only a single class ({list(test_df['label'].unique())}). "
                "Supervised classification evaluation (Precision/Recall/F1/ROC) is skipped for registration."
            )
            metrics = {
                "evaluation_status": "SKIPPED_SINGLE_CLASS",
                "test_samples": len(test_df),
                "classes": list(test_df['label'].unique()),
            }

        version = self.model_registry.register_model(cascade_model, metrics=metrics)
        pipeline_path = os.path.join(self.model_registry.registry_dir, version, "feature_pipeline.joblib")
        feat_pipeline.save(pipeline_path)
        logger.info(f"Saved feature pipeline binary to {pipeline_path}")

        # Update manifest.json with feature_pipeline.joblib hash & harden permissions (S2 defense)
        from lsmp_ai.common.security import compute_file_sha256, secure_file_permissions
        secure_file_permissions(pipeline_path, 0o640)
        manifest_path = os.path.join(self.model_registry.registry_dir, version, "manifest.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r") as f:
                    m_data = json.load(f)
                if "artifact_hashes" not in m_data:
                    m_data["artifact_hashes"] = {}
                m_data["artifact_hashes"]["feature_pipeline.joblib"] = compute_file_sha256(pipeline_path)
                with open(manifest_path, "w") as f:
                    json.dump(m_data, f, indent=4)
                secure_file_permissions(manifest_path, 0o640)
            except Exception as e:
                logger.warning(f"Could not update feature_pipeline hash in manifest: {e}")

        # Persist metrics to evaluation_metrics database table if DB available
        if metrics:
            try:
                db_client = DBClient()
                db_client.write_evaluation_metrics(
                    run_id=f"train_{version}",
                    model_config_name="cascade_iforest_ocsvm",
                    dataset_split="cicids2017",
                    precision=metrics.get("precision", 0.0),
                    recall=metrics.get("recall", 0.0),
                    f1=metrics.get("f1_score", 0.0),
                    fpr=metrics.get("false_positive_rate", 0.0),
                    roc_auc=metrics.get("roc_auc", 0.5),
                    hyperparameters=getattr(cascade_model, "cascade_params", cascade_params),
                    model_version=version
                )
            except Exception as eval_err:
                logger.warning(f"Could not persist evaluation metrics to DB: {eval_err}")

        self.last_run_summary = {
            "version": version,
            "total_samples": total_samples,
            "train_samples": len(train_df),
            "val_samples": len(val_df),
            "test_samples": len(test_df),
            "normal_count": normal_count,
            "anomaly_count": anomaly_count,
            "metrics": metrics,
            "confusion_matrix": confusion,
            "cascade_params": getattr(cascade_model, "cascade_params", cascade_params),
            "model_path": os.path.join(self.model_registry.registry_dir, version),
        }
        return version


# ===== STANDALONE RUNNER FUNCTION =====
def run_train_pipeline(
    db_url: str = None, 
    model_version: str = "cascade-v1.0",
    test_size: float = 0.3,
    random_state: int = 42
) -> str:
    """Standalone helper function to run the train pipeline."""
    db_client = DBClient(db_url) if db_url else None
    data_loader = DataLoader(db_client)
    data_config = DataConfig(train_ratio=(1.0 - test_size), val_ratio=0.0, test_ratio=test_size) if config else None
    pipeline = TrainPipeline(data_config=data_config, data_loader=data_loader)
    return pipeline.run(model_version=model_version)
