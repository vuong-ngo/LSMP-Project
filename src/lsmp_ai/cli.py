# ============================================================================
# file: src/lsmp_ai/cli.py
# Description: Production Raw Typer CLI interface for LSMP AI Engine.
#              Provides structured CLI commands for training, serving, health audit,
#              autotraining daemon, research evaluation CSV export, and DB sync.
# ============================================================================

import os
import sys
import json
import typer
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.scripts.train import run_training
from lsmp_ai.scripts.status import show_program_status
from lsmp_ai.scripts.serve import start_serving_daemon, stop_serving_daemon, main as serve_main
from lsmp_ai.scripts.autotrain import start_autotrain_daemon, stop_autotrain_daemon, main as autotrain_main
from lsmp_ai.scripts.evaluate import run_evaluation
from lsmp_ai.scripts.export_db import export_models_to_db

try:
    from scripts.prepare_data import prepare_dataset
except ImportError:
    prepare_dataset = None

logger = setup_logger(__name__)

app = typer.Typer(
    name="lsmp-ai",
    help=(
        "==============================================================================\n"
        "LSMP AI Engine CLI — Security Anomaly Detection Engine for SMEs\n"
        "Integrates Wazuh SIEM rule-based severity with 2-Stage Cascade AI Architecture\n"
        "(Isolation Forest + One-Class SVM) for Real-Time Threat Scoring & Monitoring.\n"
        "=============================================================================="
    ),
    add_completion=False,
    no_args_is_help=True,
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ============================================================================
# 1. COMMAND: TRAIN MODEL
# ============================================================================
@app.command("train")
def train_cmd(
    dataset_path: Optional[str] = typer.Option(
        None,
        "--dataset",
        "-f",
        help="[DATA] Path to input training dataset CSV file (defaults to data/processed/dataset.csv)",
    ),
    model_version: str = typer.Option(
        "cascade-v1.0",
        "--model-version",
        "-v",
        help="Model version identifier to register (e.g., cascade-v1.0, cascade-v2.0)",
    ),
    test_size: float = typer.Option(
        0.3,
        "--test-size",
        "-s",
        help="Test dataset split ratio (default: 0.3 = 30% test, 70% train)",
    ),
    do_grid_search: bool = typer.Option(
        False,
        "--grid-search",
        "-g",
        help="Execute hyperparameter Grid Search tuning before model fitting",
    ),
):
    """Train 2-Stage Cascade AI Model (iForest + OCSVM) on pure benign baseline data"""
    try:
        run_training(
            dataset_path=dataset_path,
            model_version=model_version,
            test_size=test_size,
            do_grid_search=do_grid_search,
        )
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        print(f"❌ [ERROR] Model training failed: {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 2. COMMAND: PROGRAM OPERATIONAL STATUS & HEALTHCHECK
# ============================================================================
@app.command("status")
def status_cmd():
    """Inspect active program operational status, active model parameters, thresholds & DB connectivity"""
    try:
        show_program_status()
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        print(f"❌ [ERROR] Status check failed: {e}")
        raise typer.Exit(code=1)


@app.command("healthcheck", hidden=True)
def healthcheck_alias():
    """Alias for status command."""
    status_cmd()


# ============================================================================
# 3. COMMAND: REAL-TIME SERVING DAEMON (START / STOP / STATUS)
# ============================================================================
@app.command("serve")
def serve_cmd(
    action: str = typer.Argument(
        "status",
        help="Service control action: 'start' (launch background daemon), 'stop' (shutdown daemon), 'status' (check daemon state)",
    ),
    interval: int = typer.Option(
        10,
        "--interval",
        "-i",
        help="Daemon log polling interval in seconds (default: 10)",
    ),
    lookback_minutes: int = typer.Option(
        60,
        "--lookback",
        "-l",
        help="Log retrieval lookback window in minutes (default: 60)",
    ),
):
    """Start, stop or inspect real-time AI serving daemon (Verifies DB presence before running)"""
    action = action.lower().strip()
    if action == "start":
        start_serving_daemon(interval=interval, lookback_minutes=lookback_minutes)
    elif action == "stop":
        stop_serving_daemon()
    elif action in ["status", "check"]:
        pid_file = BASE_DIR / "logs" / "service.pid"
        if pid_file.exists():
            try:
                pid = pid_file.read_text().strip()
                import psutil
                if psutil.pid_exists(int(pid)):
                    print(f"✅ LSMP Real-time Serving Daemon is RUNNING (PID: {pid})")
                else:
                    print("🛑 LSMP Real-time Serving Daemon is STOPPED (Stale PID file)")
            except Exception:
                print("🛑 LSMP Real-time Serving Daemon is STOPPED")
        else:
            print("🛑 LSMP Real-time Serving Daemon is STOPPED")
    else:
        print(f"❌ Unknown serve action '{action}'. Use 'start', 'stop', or 'status'.")
        raise typer.Exit(code=1)


# ============================================================================
# 4. COMMAND: AUTO-RETRAINING DAEMON (START / STOP / STATUS)
# ============================================================================
@app.command("autotrain")
def autotrain_cmd(
    action: str = typer.Argument(
        "status",
        help="Daemon action: 'start' (launch background autotrain daemon), 'stop' (stop daemon), 'status' (check state)",
    ),
    interval_hours: float = typer.Option(
        24.0,
        "--interval-hours",
        "-H",
        help="Auto-retrain interval in hours (default: 24.0 hours)",
    ),
    interval_seconds: Optional[int] = typer.Option(
        None,
        "--interval-seconds",
        "-S",
        help="Auto-retrain interval in seconds (overrides interval-hours if specified)",
    ),
):
    """Start, stop or inspect periodic model auto-retraining background daemon service"""
    action = action.lower().strip()
    if action == "start":
        start_autotrain_daemon(interval_hours=interval_hours, interval_seconds=interval_seconds)
    elif action == "stop":
        stop_autotrain_daemon()
    elif action in ["status", "check"]:
        pid_file = BASE_DIR / "logs" / "autotrain.pid"
        if pid_file.exists():
            try:
                pid = pid_file.read_text().strip()
                import psutil
                if psutil.pid_exists(int(pid)):
                    print(f"✅ LSMP Auto-Retraining Daemon is RUNNING (PID: {pid})")
                else:
                    print("🛑 LSMP Auto-Retraining Daemon is STOPPED (Stale PID file)")
            except Exception:
                print("🛑 LSMP Auto-Retraining Daemon is STOPPED")
        else:
            print("🛑 LSMP Auto-Retraining Daemon is STOPPED")
    else:
        print(f"❌ Unknown autotrain action '{action}'. Use 'start', 'stop', or 'status'.")
        raise typer.Exit(code=1)


# ============================================================================
# 5. COMMAND: EVALUATE & RESEARCH COMPARISON (EXPORT CSV & DB)
# ============================================================================
@app.command("evaluate")
def evaluate_cmd(
    dataset_path: Optional[str] = typer.Option(
        None,
        "--dataset",
        "-f",
        help="[DATA] Path to input evaluation dataset CSV file (defaults to data/processed/dataset.csv)",
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="[DATA] Path for saving comparative evaluation CSV report (defaults to reports/results/ablation_study_comparison.csv)",
    ),
    runs: int = typer.Option(
        5,
        "--runs",
        "-r",
        help="Number of benchmark iterations for accurate throughput/latency measurement (default: 5)",
    ),
):
    """Execute model ablation study comparison (iForest vs OCSVM vs Cascade) and export CSV & DB report"""
    try:
        run_evaluation(dataset_path=dataset_path, output_csv_path=output_path, benchmark_runs=runs)
    except Exception as e:
        logger.error(f"Evaluation benchmark failed: {e}")
        print(f"❌ [ERROR] Model evaluation failed: {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 6. COMMAND: EXPORT MODEL CATALOG & METRICS TO DB
# ============================================================================
@app.command("export-db")
def export_db_cmd(
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        "-d",
        help="Database connection URL string (defaults to DATABASE_URL in .env)",
    ),
):
    """Export and sync all registered model versions, hyperparameters & metrics to Database"""
    try:
        success = export_models_to_db(db_url=db_url)
        if not success:
            raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Database export failed: {e}")
        print(f"❌ [ERROR] Database export failed: {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 7. COMMAND: INSPECT MODEL CATALOG
# ============================================================================
@app.command("models")
def models_cmd():
    """Inspect all registered AI model catalog versions in models_store/catalog.json"""
    models_dir = BASE_DIR / "models_store"
    catalog_path = models_dir / "catalog.json"

    if not catalog_path.exists():
        print(f"⚠️ No registered model catalog found at {catalog_path}.")
        return

    try:
        with open(catalog_path, "r") as f:
            catalog = json.load(f)

        latest_version = catalog.get("latest_version", "")
        print("=" * 80)
        print("📋 REGISTERED AI MODEL CATALOG INSPECTOR")
        print("=" * 80)
        print(f"{'Version':<22} | {'Registered At':<20} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9}")
        print("-" * 88)

        for version, info in catalog.items():
            if version == "latest_version":
                continue

            metrics = info.get("metrics", {})
            reg_at = info.get("registered_at", "N/A")[:19]
            is_active = " (ACTIVE)" if version == latest_version else ""

            print(
                f"{version + is_active:<22} | "
                f"{reg_at:<20} | "
                f"{metrics.get('accuracy', 0.0)*100:>8.2f}% | "
                f"{metrics.get('precision', 0.0)*100:>8.2f}% | "
                f"{metrics.get('recall', 0.0)*100:>8.2f}% | "
                f"{metrics.get('f1_score', 0.0)*100:>8.2f}%"
            )

        print("-" * 88)
    except Exception as e:
        print(f"❌ Error reading catalog: {e}")


# ============================================================================
# 8. COMMAND: PREPARE DATASET
# ============================================================================
@app.command("prepare-data")
def prepare_data_cmd(
    max_samples: int = typer.Option(
        100000,
        "--max-samples",
        "-m",
        help="Maximum sample count per class (Normal/Anomaly) when subsampling dataset",
    ),
):
    """Clean raw CSV files and extract 14 LSMP network feature vectors"""
    try:
        dataset_path = prepare_dataset(max_samples_per_class=max_samples)
        print(f"[SUCCESS] Dataset preparation completed! Stored at: [DATA] {dataset_path}")
    except Exception as e:
        logger.error(f"Dataset preparation failed: {e}")
        print(f"❌ [ERROR] Dataset preparation failed: {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 9. COMMAND: THREAT SUMMARY REPORT
# ============================================================================
@app.command("threat-summary")
def threat_summary_cmd():
    """Display Device Risk Index (DRI) Threat Summary Report across monitored hosts"""
    print("=" * 80)
    print("🛡️ LSMP DEVICE RISK INDEX (DRI) THREAT SUMMARY REPORT")
    print("=" * 80)
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("⚠️ DATABASE_URL is not set. Showing fallback cached summary report.")

    try:
        from lsmp_ai.io.db_client import DBClient
        client = DBClient()
        df_risk = client.fetch_latest_risk_scores(limit=100)

        if not df_risk.empty:
            print(f"{'Source IP':<18} | {'Risk Score':<10} | {'Class':<10} | {'Timestamp':<25}")
            print("-" * 70)
            for idx, row in df_risk.iterrows():
                print(
                    f"{str(row.get('src_ip', 'N/A')):<18} | "
                    f"{float(row.get('score', 0.0)):>9.2f} | "
                    f"{str(row.get('risk_class', 'Low')):<10} | "
                    f"{str(row.get('timestamp', '')):<25}"
                )
            print("-" * 70)
        else:
            print("ℹ️ No active risk score records stored in database yet.")
    except Exception as err:
        print(f"ℹ️ Could not query live database: {err}")
    print("=" * 80)


# ============================================================================
# 10. COMMAND: INTERACTIVE TERMINAL UI DASHBOARD
# ============================================================================
@app.command("dashboard")
def dashboard_cmd():
    """Launch interactive real-time Terminal UI (TUI) Dashboard"""
    try:
        from lsmp_ai.ui.tui_dashboard import launch_tui_dashboard
        launch_tui_dashboard()
    except Exception as e:
        logger.error(f"Dashboard launch failed: {e}")
        print(f"❌ [ERROR] Dashboard launch failed: {e}")
        raise typer.Exit(code=1)


@app.command("ui", hidden=True)
def ui_cmd():
    """Alias for dashboard command."""
    dashboard_cmd()


# ============================================================================
# 11. COMMAND: VERSION
# ============================================================================
@app.command("version")
def version_cmd():
    """Display LSMP AI Engine Version, Architecture Specs, and Platform Metadata"""
    print("=" * 65)
    print("LSMP AI Engine — Security Platform for SMEs")
    print("• Engine Version:     1.0.0")
    print("• Architecture:       2-Stage Cascade (Isolation Forest + OCSVM)")
    print("• Feature Vector:     14 LSMP Network Security Features")
    print("• Authors:            Ngo Duc Vuong & Phan Ngoc My")
    print("• License:            MIT License")
    print("=" * 65)


if __name__ == "__main__":
    app()
