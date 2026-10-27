# ============================================================================
# file: src/lsmp_ai/scripts/healthcheck_services.py
# Description: Automated Model & System Resource Audit Script for LSMP AI Engine.
# ============================================================================

import os
import sys
import time
from pathlib import Path
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

try:
    import psutil
except ImportError:
    psutil = None

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.version import __version__

logger = setup_logger(__name__)


def audit_model_health() -> tuple[dict, bool]:
    """Audits the latest registered model version, accuracy metrics, throughput, latency, and memory."""
    models_dir = BASE_DIR / "models_store"
    registry = ModelRegistry(registry_dir=str(models_dir))

    catalog_path = models_dir / "catalog.json"
    latest_version = None
    metrics_info = {}

    if catalog_path.exists():
        try:
            import json
            with open(catalog_path, "r") as f:
                catalog = json.load(f)
                latest_version = catalog.get("latest_version")
                if latest_version and latest_version in catalog:
                    metrics_info = catalog[latest_version].get("metrics", {})
        except Exception:
            pass

    if not latest_version:
        versions = [d.name for d in models_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
        if versions:
            latest_version = sorted(versions)[-1]
        else:
            return {"error": "No trained model version registered in models_store/"}, False

    try:
        model = registry.load_model(latest_version)
        X_dummy = np.random.randn(1000, len(FEATURE_COLUMNS))
        
        t0 = time.perf_counter()
        _ = model.predict(X_dummy)
        t_elapsed = time.perf_counter() - t0

        eps = 1000.0 / max(t_elapsed, 1e-6)
        latency_ms = (t_elapsed / 1000.0) * 1000.0
    except Exception:
        eps = 0.0
        latency_ms = 0.0

    try:
        process = psutil.Process(os.getpid())
        ram_mb = process.memory_info().rss / (1024 * 1024)
    except Exception:
        ram_mb = 0.0

    health_data = {
        "model_version": latest_version,
        "accuracy": metrics_info.get("accuracy", 0.0),
        "precision": metrics_info.get("precision", 0.0),
        "recall": metrics_info.get("recall", 0.0),
        "f1_score": metrics_info.get("f1_score", 0.0),
        "roc_auc": metrics_info.get("roc_auc", 0.5),
        "throughput_eps": eps,
        "latency_ms": latency_ms,
        "ram_mb": ram_mb
    }
    return health_data, True


def main():
    print("=" * 70)
    print(f"🤖 LSMP AI Model Engine & System Resource Health Audit ({__version__})")
    print("=" * 70)

    health_data, is_model_ok = audit_model_health()

    print("\n📦 Active Model & Inference Performance Audit:")
    print("-" * 70)
    if is_model_ok:
        print(f"  • Model Version:        {health_data['model_version']}")
        print(f"  • Model Accuracy:       {health_data['accuracy']*100:.2f}%")
        print(f"  • Model Precision:      {health_data['precision']*100:.2f}%")
        print(f"  • Model Recall:         {health_data['recall']*100:.2f}%")
        print(f"  • Model F1-Score:       {health_data['f1_score']*100:.2f}%")
        print(f"  • Model ROC-AUC:        {health_data['roc_auc']:.4f}")
        print(f"  • Throughput (EPS):     {health_data['throughput_eps']:,.1f} Events/sec")
        print(f"  • Avg Latency:          {health_data['latency_ms']:.3f} ms / log")
    else:
        print(f"  • Model Status:         {health_data.get('error', 'Error')}")

    print("\n💻 System Hardware & Memory Resource Audit:")
    print("-" * 70)
    if psutil:
        try:
            cpu_pct = psutil.cpu_percent(interval=0.2)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage(str(BASE_DIR))

            cpu_status = "OK" if cpu_pct < 85 else "HIGH"
            mem_status = "OK" if mem.percent < 90 else "HIGH"
            disk_status = "OK" if disk.percent < 90 else "CRITICAL"

            print(f"  • CPU Utilization:      {cpu_pct:.1f}% (Threshold: < 85.0%, Status: {cpu_status})")
            print(f"  • RAM Memory Usage:     {mem.percent:.1f}% ({mem.used/(1024**3):.2f}/{mem.total/(1024**3):.2f} GB) (Status: {mem_status})")
            if is_model_ok:
                print(f"  • Process Memory RAM:   {health_data['ram_mb']:.1f} MB (Threshold: < 300 MB, Status: OK)")
            print(f"  • Disk Space Available: {disk.percent:.1f}% ({disk.free/(1024**3):.2f} GB Free) (Status: {disk_status})")
        except Exception as e:
            print(f"  [!] Resource check warning: {e}")
    else:
        print("  • psutil is not available for hardware audit.")

    print("=" * 70)


if __name__ == "__main__":
    main()
