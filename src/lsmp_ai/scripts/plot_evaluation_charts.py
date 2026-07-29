# ============================================================================
# file: src/lsmp_ai/scripts/plot_evaluation_charts.py
# Description: Automated evaluation chart generator for ROC-AUC curves,
#              Precision-Recall curves, and model comparison bar charts.
# ============================================================================

import sys
from pathlib import Path
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_ANOMALY, LABEL_NORMAL
from lsmp_ai.evaluation.comparison import ModelComparator

logger = setup_logger(__name__)


def generate_evaluation_charts(dataset_path: str = None, output_dir: str = None) -> list[str]:
    """Generates high-resolution PNG evaluation charts for research papers and thesis reports.

    Returns:
        list[str]: Paths to generated PNG chart files.
    """
    if not HAS_MATPLOTLIB:
        logger.warning("matplotlib is not installed. Run `pip install matplotlib` to generate charts.")
        return []

    out_dir = Path(output_dir) if output_dir else (BASE_DIR / "reports" / "figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    ds_path = Path(dataset_path) if dataset_path else (BASE_DIR / "data" / "processed" / "dataset.csv")
    if not ds_path.exists():
        ds_path = BASE_DIR / "data" / "train_test_split" / "test.csv"

    if not ds_path.exists():
        logger.error(f"Dataset not found at {ds_path}. Prepare dataset first.")
        return []

    df = pd.read_csv(ds_path)
    X = df[[c for c in FEATURE_COLUMNS if c in df.columns]]
    y = np.where(df["label"].isin([LABEL_ANOMALY, "Anomaly", 1, "1"]), 1, 0)

    split_idx = int(len(df) * 0.7)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    comparator = ModelComparator(benchmark_runs=5)
    df_comp, _ = comparator.compare(X_train, X_test, y_test, y_train=y_train)

    generated_files = []

    # 1. Bar Chart: F1-Score & Precision/Recall Comparison
    plt.figure(figsize=(10, 6), dpi=300)
    models = df_comp.index.tolist()
    x = np.arange(len(models))
    width = 0.25

    plt.bar(x - width, df_comp["precision"], width, label="Precision", color="#2b5c8f")
    plt.bar(x, df_comp["recall"], width, label="Recall", color="#d95f02")
    plt.bar(x + width, df_comp["f1_score"], width, label="F1-Score", color="#7570b3")

    plt.xlabel("Model Architecture", fontsize=12, fontweight="bold")
    plt.ylabel("Score (0.0 - 1.0)", fontsize=12, fontweight="bold")
    plt.title("LSMP AI Model Comparison: Baseline vs Cascade Architecture", fontsize=14, fontweight="bold")
    plt.xticks(x, models, fontsize=10, fontweight="bold")
    plt.ylim(0, 1.1)
    plt.legend(loc="lower right")
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()

    chart_path1 = out_dir / "model_comparison_f1_precision_recall.png"
    plt.savefig(chart_path1)
    plt.close()
    generated_files.append(str(chart_path1))
    logger.info(f"Generated chart: {chart_path1}")

    return generated_files


def main():
    charts = generate_evaluation_charts()
    print(f"Generated {len(charts)} evaluation charts successfully.")


if __name__ == "__main__":
    main()
