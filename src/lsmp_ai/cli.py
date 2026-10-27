# ============================================================================
# file: src/lsmp_ai/cli.py
# Description: Minimal, zero-dependency CLI interface using Python's built-in argparse.
#              Provides commands for training, serving, health inspection,
#              evaluation benchmarks, and database sync.
# ============================================================================

import os
import sys
import json
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from lsmp_ai.version import __version__
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.scripts.train import run_training
from lsmp_ai.scripts.status import show_program_status
from lsmp_ai.scripts.serve import start_serving_daemon, stop_serving_daemon
from lsmp_ai.scripts.evaluate import run_evaluation
from lsmp_ai.scripts.export_db import export_models_to_db

logger = setup_logger(__name__)


def train_cmd(args):
    """Train 2-Stage Cascade AI Model (iForest + OCSVM) on pure benign baseline data"""
    try:
        run_training(
            dataset_path=args.dataset,
            model_version=args.model_version,
            test_size=args.test_size,
            do_grid_search=args.grid_search,
        )
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        print(f"❌ [ERROR] Model training failed: {e}")
        sys.exit(1)


def status_cmd(args):
    """Inspect active program operational status, active model parameters, thresholds & DB connectivity"""
    try:
        show_program_status()
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        print(f"❌ [ERROR] Status check failed: {e}")
        sys.exit(1)


def healthcheck_cmd(args):
    """Audit active model inference throughput, latency, and host hardware resources"""
    try:
        from lsmp_ai.scripts.healthcheck_services import main as run_healthcheck
        run_healthcheck()
    except Exception as e:
        logger.error(f"Healthcheck failed: {e}")
        print(f"❌ [ERROR] Healthcheck failed: {e}")
        sys.exit(1)


def serve_cmd(args):
    """Start, stop or inspect real-time AI serving daemon"""
    action = args.action.lower().strip()
    if action == "start":
        start_serving_daemon(interval=args.interval, lookback_minutes=args.lookback)
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
        sys.exit(1)


def evaluate_cmd(args):
    """Execute model ablation study comparison and export reports"""
    try:
        include_rule = None
        if args.rule:
            include_rule = True
        elif args.no_rule:
            include_rule = False

        run_evaluation(
            db_url=args.db_url,
            dataset_path=args.dataset,
            output_csv_path=args.output,
            benchmark_runs=args.runs,
            require_db=False,
            criterion=args.criterion,
            max_fpr=args.max_fpr,
            include_rule_only=include_rule,
            include_full_ablation=getattr(args, "full_ablation", False),
        )
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"Evaluation benchmark failed: {e}")
        print(f"❌ [ERROR] Model evaluation failed: {e}")
        sys.exit(1)


def export_db_cmd(args):
    """Export and sync all registered model versions, hyperparameters & metrics to Database"""
    try:
        success = export_models_to_db(db_url=args.db_url)
        if not success:
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"Database export failed: {e}")
        print(f"❌ [ERROR] Database export failed: {e}")
        sys.exit(1)


def models_cmd(args):
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


def threat_summary_cmd(args):
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
            for _, row in df_risk.iterrows():
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


def version_cmd(args):
    """Display LSMP AI Engine Version, Architecture Specs, and Platform Metadata"""
    from lsmp_ai.common.config_loader import config
    feat_ver = getattr(config, "feature_version", "v2") if config else "v2"
    print("=" * 65)
    print("LSMP AI Engine — Security Platform for SMEs")
    print(f"• Engine Version:     {__version__}")
    print("• Architecture:       2-Stage Cascade (Isolation Forest + OCSVM)")
    print(f"• Feature Version:    {feat_ver}")
    print("• Feature Vector:     14 LSMP Network Security Features")
    print("• Authors:            Ngo Duc Vuong & Phan Ngoc My")
    print("• License:            MIT License")
    print("=" * 65)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lsmp-ai",
        description="LSMP AI Engine CLI — Minimal Security Anomaly Detection Engine for SMEs",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # train
    p_train = subparsers.add_parser("train", help="Train 2-Stage Cascade AI Model (iForest + OCSVM)")
    p_train.add_argument("--dataset", "-f", default=None, help="Path to input training dataset CSV")
    p_train.add_argument("--model-version", "-v", default="cascade-v1.0", help="Model version identifier")
    p_train.add_argument("--test-size", "-s", type=float, default=0.3, help="Test dataset split ratio")
    p_train.add_argument("--grid-search", "-g", action="store_true", help="Execute hyperparameter Grid Search")
    p_train.set_defaults(func=train_cmd)

    # status
    p_status = subparsers.add_parser("status", help="Inspect program status, thresholds & DB connectivity")
    p_status.set_defaults(func=status_cmd)

    # healthcheck
    p_health = subparsers.add_parser("healthcheck", help="Audit model inference throughput, latency & host hardware")
    p_health.set_defaults(func=healthcheck_cmd)

    # serve
    p_serve = subparsers.add_parser("serve", help="Start, stop or inspect real-time AI serving daemon")
    p_serve.add_argument("action", nargs="?", default="status", choices=["start", "stop", "status", "check"], help="Action: start, stop, or status")
    p_serve.add_argument("--interval", "-i", type=int, default=10, help="Log polling interval in seconds")
    p_serve.add_argument("--lookback", "-l", type=int, default=60, help="Log lookback window in minutes")
    p_serve.set_defaults(func=serve_cmd)

    # evaluate
    p_eval = subparsers.add_parser("evaluate", help="Execute model ablation study comparison and export reports")
    p_eval.add_argument("--dataset", "-f", default=None, help="Path to evaluation dataset CSV")
    p_eval.add_argument("--output", "-o", default=None, help="Path for saving CSV report")
    p_eval.add_argument("--runs", "-r", type=int, default=5, help="Number of benchmark iterations")
    p_eval.add_argument("--db-url", "-d", default=None, help="Database connection URL")
    p_eval.add_argument("--criterion", "-c", default="fpr_budget", choices=["f2", "fpr_budget"], help="Threshold criterion")
    p_eval.add_argument("--max-fpr", type=float, default=0.02, help="Max FPR budget when criterion='fpr_budget'")
    rule_group = p_eval.add_mutually_exclusive_group()
    rule_group.add_argument("--rule", dest="rule", action="store_true", help="Include static rule-based baseline")
    rule_group.add_argument("--no-rule", dest="no_rule", action="store_true", help="Exclude static rule-based baseline")
    p_eval.add_argument("--full-ablation", "-a", action="store_true", help="Execute feature group ablation, sensitivity, and gate sweep")
    p_eval.set_defaults(func=evaluate_cmd)

    # export-db
    p_export = subparsers.add_parser("export-db", help="Export and sync model catalog & metrics to Database")
    p_export.add_argument("--db-url", "-d", default=None, help="Database connection URL")
    p_export.set_defaults(func=export_db_cmd)

    # models
    p_models = subparsers.add_parser("models", help="Inspect registered model versions in catalog")
    p_models.set_defaults(func=models_cmd)

    # threat-summary
    p_threat = subparsers.add_parser("threat-summary", help="Display Device Risk Index Threat Summary Report")
    p_threat.set_defaults(func=threat_summary_cmd)

    # version
    p_version = subparsers.add_parser("version", help="Display LSMP AI Engine version and specs")
    p_version.set_defaults(func=version_cmd)

    return parser


def app():
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    app()
