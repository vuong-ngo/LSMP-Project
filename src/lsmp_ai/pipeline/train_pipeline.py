# ============================================================================
# file: pipeline/train_pipeline.py
# Description: Pipeline workflow for training, preprocessing, and model registry serialization.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

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
        self.data_config = data_config or (config.data if config else DataConfig())
        self.model_config = model_config or (config.model if config else ModelConfig())
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
            if os.path.exists(fallback_path):
                df_raw = self.data_loader.load_from_csv(fallback_path)
            else:
                raise ModelTrainingError("Training dataset is empty. Cannot train model.")

        if 'label' not in df_raw.columns:
            df_raw['label'] = LABEL_NORMAL

        feature_cols = config.features if (config and hasattr(config, "features") and config.features) else list(FEATURE_COLUMNS)
        missing_feats = [col for col in feature_cols if col not in df_raw.columns]
        if missing_feats:
            logger.warning(f"Missing feature columns in training data: {missing_feats}. Creating zeros.")
            for col in missing_feats:
                df_raw[col] = 0.0

        min_class_count = df_raw['label'].value_counts().min() if 'label' in df_raw.columns else 0
        use_stratify = df_raw['label'] if (len(df_raw['label'].unique()) > 1 and min_class_count >= 2) else None
        
        test_ratio = 1.0 - getattr(self.data_config, "train_ratio", 0.7)
        train_df, test_df = train_test_split(
            df_raw,
            test_size=test_ratio,
            random_state=42,
            stratify=use_stratify
        )

        feat_pipeline = FeaturePipeline()
        X_train_scaled = feat_pipeline.fit_transform(train_df)

        cascade_params = config.cascade_params if (config and hasattr(config, "cascade_params")) else {}
        cascade_params["model_version"] = model_version
        
        cascade_model = CascadeModel(cascade_params=cascade_params)
        cascade_model.fit(X_train_scaled, train_df['label'].values)

        metrics = {}
        if len(test_df['label'].unique()) > 1:
            X_test_scaled = feat_pipeline.transform(test_df)
            preds = cascade_model.predict(X_test_scaled)
            scores = cascade_model.score(X_test_scaled)
            
            y_true = (test_df['label'] == LABEL_ANOMALY).astype(int)
            y_pred = (preds == LABEL_ANOMALY).astype(int)
            
            precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
            try:
                auc = roc_auc_score(y_true, scores)
            except Exception:
                auc = 0.5
            metrics = {"precision": float(precision), "recall": float(recall), "f1_score": float(f1), "roc_auc": float(auc)}

        version = self.model_registry.register_model(cascade_model, metrics=metrics)
        pipeline_path = os.path.join(self.model_registry.registry_dir, version, "feature_pipeline.joblib")
        feat_pipeline.save(pipeline_path)
        logger.info(f"Saved feature pipeline binary to {pipeline_path}")
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
    data_config = DataConfig(train_ratio=(1.0 - test_size)) if config else None
    pipeline = TrainPipeline(data_config=data_config, data_loader=data_loader)
    return pipeline.run(model_version=model_version)
