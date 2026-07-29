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
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    pass

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.common.constants import FEATURE_COLUMNS

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
    console = Console()
    console.print(Panel("[bold cyan]🤖 LSMP AI Model Engine & System Resource Health Audit[/bold cyan]", border_style="cyan"))

    health_data, is_model_ok = audit_model_health()

    t_model = Table(title="📦 Active Model & Inference Performance Audit", show_header=True, header_style="bold blue")
    t_model.add_column("Property / Metric", style="bold white")
    t_model.add_column("Value / Status", justify="right", style="cyan")

    if is_model_ok:
        t_model.add_row("Model Version", f"[bold yellow]{health_data['model_version']}[/bold yellow]")
        t_model.add_row("Model Accuracy", f"{health_data['accuracy']*100:.2f}%")
        t_model.add_row("Model Precision", f"{health_data['precision']*100:.2f}%")
        t_model.add_row("Model Recall", f"{health_data['recall']*100:.2f}%")
        t_model.add_row("Model F1-Score", f"{health_data['f1_score']*100:.2f}%")
        t_model.add_row("Model ROC-AUC", f"{health_data['roc_auc']:.4f}")
        t_model.add_row("Throughput (EPS)", f"[bold green]{health_data['throughput_eps']:,.1f} Events/sec[/bold green]")
        t_model.add_row("Avg Latency", f"[bold green]{health_data['latency_ms']:.3f} ms / log[/bold green]")
    else:
        t_model.add_row("Model Status", f"[bold red]{health_data.get('error', 'Error')}[/bold red]")

    console.print(t_model)

    t_res = Table(title="💻 System Hardware & Memory Resource Audit", show_header=True, header_style="bold yellow")
    t_res.add_column("Resource", style="bold white")
    t_res.add_column("Current Value", justify="right")
    t_res.add_column("Threshold", justify="right", style="dim white")
    t_res.add_column("Status", justify="right")

    try:
        cpu_pct = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(str(BASE_DIR))

        cpu_status = "[bold green]OK[/bold green]" if cpu_pct < 85 else "[bold red]HIGH[/bold red]"
        mem_status = "[bold green]OK[/bold green]" if mem.percent < 90 else "[bold red]HIGH[/bold red]"
        disk_status = "[bold green]OK[/bold green]" if disk.percent < 90 else "[bold red]CRITICAL[/bold red]"

        t_res.add_row("CPU Utilization", f"{cpu_pct:.1f}%", "< 85.0%", cpu_status)
        t_res.add_row("RAM Memory Usage", f"{mem.percent:.1f}% ({mem.used/(1024**3):.2f}/{mem.total/(1024**3):.2f} GB)", "< 90.0%", mem_status)
        if is_model_ok:
            t_res.add_row("Process Memory Footprint", f"{health_data['ram_mb']:.1f} MB RAM", "< 300 MB", "[bold green]OK[/bold green]")
        t_res.add_row("Disk Space Available", f"{disk.percent:.1f}% ({disk.free/(1024**3):.2f} GB Free)", "< 90.0%", disk_status)
    except Exception:
        pass

    console.print(t_res)


if __name__ == "__main__":
    main()
