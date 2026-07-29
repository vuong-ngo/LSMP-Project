# ============================================================================
# file: src/lsmp_ai/cli.py
# Description: Professional Production-Grade Typer CLI interface for LSMP AI Engine.
#              Provides full lifecycle commands: data prep, training, ablation,
#              real-time serving, model catalog management, and threat summary.
# ============================================================================

import os
import sys
import time
import json
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.pipeline.train_pipeline import TrainPipeline
from lsmp_ai.pipeline.evaluate_pipeline import EvaluatePipeline
from lsmp_ai.pipeline.serve_pipeline import run_serve_pipeline, get_last_watermark
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.scripts.prepare_cicids2017 import prepare_full_cicids2017_dataset
from lsmp_ai.scripts.export_models_to_db import export_models_and_metrics_to_db
from lsmp_ai.scripts.export_eval_benchmarks import populate_standalone_eval_tables
from lsmp_ai.scripts.healthcheck_services import audit_model_health, main as run_healthcheck


logger = setup_logger(__name__)
console = Console()

app = typer.Typer(
    name="lsmp-ai",
    help=(
        "🛡️  [bold cyan]LSMP AI Engine[/bold cyan] — Lightweight Security Monitoring Platform for SMEs\n\n"
        "AI-powered network security anomaly detection engine integrated with Wazuh SIEM,\n"
        "utilizing a 2-stage Cascade architecture (Isolation Forest + One-Class SVM)."
    ),
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ============================================================================
# 1. COMMAND: PREPARE DATA
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
    """🧹 [bold green]Prepare & Clean CICIDS2017 Dataset[/bold green]
    
    Reads raw CSV files from `data/raw/`, cleans NaNs, Infinities, and duplicate rows,
    maps columns to the 14 standardized LSMP AI features, and splits Train/Test sets using
    One-Class principles (Train set is 100% Pure Benign).
    """
    console.print(
        Panel(
            Text(
                "🧹 EXECUTING DATA CLEANING & CICIDS2017 DATASET PREPARATION\n"
                "• Input:  data/raw/*.csv\n"
                "• Rules:  Remove NaN/Inf, drop duplicates, extract 14 LSMP features\n"
                "• Output: data/processed/dataset.csv & data/train_test_split/",
                style="bold cyan",
            ),
            title="[bold white]LSMP Data Preparation[/bold white]",
            border_style="cyan",
        )
    )
    try:
        from scripts.prepare_cicids2017 import prepare_full_cicids2017_dataset
        dataset_path = prepare_full_cicids2017_dataset(max_samples_per_class=max_samples)
        console.print(
            f"[bold green]✅ Dataset preparation completed successfully![/bold green]\n"
            f"📍 Dataset stored at: [cyan]{dataset_path}[/cyan]"
        )
    except Exception as e:
        logger.error(f"Dataset preparation failed: {e}")
        console.print(f"[bold red]❌ Dataset preparation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 2. COMMAND: TRAIN MODEL
# ============================================================================
@app.command("train")
def train_cmd(
    dataset_path: Optional[str] = typer.Option(
        None,
        "--dataset",
        "-f",
        help="Path to input dataset CSV file (defaults to data/processed/dataset.csv)",
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
        help="Test dataset split ratio (default: 0.3 = 30%)",
    ),
    do_grid_search: bool = typer.Option(
        False,
        "--grid-search",
        "-g",
        help="Execute hyperparameter Grid Search before model fitting",
    ),
):
    """🚀 [bold cyan]Train 2-Stage Cascade AI Model (IForest + OCSVM)[/bold cyan]
    
    Executes the unsupervised anomaly detection training pipeline.
    Standardizes feature vectors using `FeaturePipeline`, fits Stage 1 Isolation Forest and
    Stage 2 One-Class SVM on pure Benign baseline data, computes F1/Precision/Recall/ROC-AUC metrics,
    and registers the model version into `ModelRegistry`.
    """
    console.print(
        Panel(
            Text(
                f"🚀 INITIALIZING AI MODEL TRAINING WORKFLOW\n"
                f"• Model Version:  {model_version}\n"
                f"• Test Ratio:     {test_size*100:.0f}%\n"
                f"• GridSearch:     {'Enabled' if do_grid_search else 'Disabled'}\n"
                f"• Architecture:   Cascade (Isolation Forest -> One-Class SVM)",
                style="bold cyan",
            ),
            title="[bold white]LSMP Model Training[/bold white]",
            border_style="cyan",
        )
    )

    try:
        pipeline = TrainPipeline()
        version = pipeline.run(
            dataset_path=dataset_path,
            do_grid_search=do_grid_search,
            model_version=model_version,
        )

        summary = getattr(pipeline, "last_run_summary", {})
        metrics = summary.get("metrics", {})

        # Display training metrics summary table
        table = Table(
            title=f"📊 MODEL TRAINING EVALUATION SUMMARY ({version})",
            header_style="bold green",
            show_header=True,
        )
        table.add_column("Metric Name", style="bold white")
        table.add_column("Metric Value", justify="right", style="bold yellow")

        table.add_row("Total Samples", f"{summary.get('total_samples', 0):,}")
        table.add_row("Train Samples (Pure Benign)", f"{summary.get('train_samples', 0):,}")
        table.add_row("Test Samples (Normal+Attack)", f"{summary.get('test_samples', 0):,}")
        table.add_row("Accuracy", f"{metrics.get('accuracy', 0.0)*100:.2f}%")
        table.add_row("Precision", f"{metrics.get('precision', 0.0)*100:.2f}%")
        table.add_row("Recall (Sensitivity)", f"{metrics.get('recall', 0.0)*100:.2f}%")
        table.add_row("F1-Score", f"[bold green]{metrics.get('f1_score', 0.0)*100:.2f}%[/bold green]")
        table.add_row("ROC-AUC", f"{metrics.get('roc_auc', 0.0):.4f}")
        table.add_row("False Positive Rate (FPR)", f"{metrics.get('false_positive_rate', 0.0)*100:.2f}%")

        console.print(table)
        console.print(
            f"\n[bold green]✅ Model training completed successfully![/bold green] "
            f"Artifacts saved at: [cyan]models_store/{version}/[/cyan]\n"
        )
    except Exception as e:
        logger.error(f"Training workflow failed: {e}")
        console.print(f"[bold red]❌ Model training failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 3. COMMAND: EVALUATE ABLATION STUDY
# ============================================================================
@app.command("evaluate")
def evaluate_cmd(
    dataset_path: Optional[str] = typer.Option(
        None,
        "--dataset",
        "-f",
        help="Path to input dataset CSV file for evaluation",
    ),
    output_path: str = typer.Option(
        "reports/results/bang_3_1_so_sanh_baseline.csv",
        "--output",
        "-o",
        help="Output CSV path for comparative evaluation metrics report",
    ),
):
    """🔬 [bold magenta]Execute Model Ablation Benchmarking Study[/bold magenta]
    
    Evaluates and benchmarks performance across 3 configurations:
    1. Standalone Isolation Forest (iForest Only)
    2. Standalone One-Class SVM (OCSVM Only)
    3. Hybrid 2-Stage Cascade Model (iForest -> OCSVM)
    
    Computes Accuracy, Precision, Recall, F1-Score, and ROC-AUC, saving results to CSV.
    """
    console.print(
        Panel(
            Text(
                "🔬 EXECUTING MODEL ABLATION STUDY BENCHMARK\n"
                "• Architectures: iForest vs OCSVM vs Cascade (iForest->OCSVM)\n"
                f"• Report Output: {output_path}",
                style="bold magenta",
            ),
            title="[bold white]LSMP Model Ablation Evaluation[/bold white]",
            border_style="magenta",
        )
    )

    try:
        pipeline = EvaluatePipeline(
            data_config=config.data,
            model_config=config.model,
        )
        df_results = pipeline.run(dataset_path=dataset_path, output_path=output_path)

        table = Table(
            title="📊 ABLATION STUDY PERFORMANCE BENCHMARK TABLE",
            header_style="bold magenta",
            show_header=True,
        )
        table.add_column("Model Architecture", style="bold white")
        table.add_column("Precision", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("F1-Score", justify="right", style="bold green")
        table.add_column("ROC-AUC", justify="right")

        for idx, row in df_results.iterrows():
            table.add_row(
                str(idx),
                f"{row.get('precision', 0.0)*100:.2f}%",
                f"{row.get('recall', 0.0)*100:.2f}%",
                f"[bold green]{row.get('f1_score', 0.0)*100:.2f}%[/bold green]",
                f"{row.get('roc_auc', 0.0):.4f}",
            )

        console.print(table)
        console.print(
            f"\n[bold green]✅ Ablation study completed successfully![/bold green] "
            f"Report saved at: [cyan]{output_path}[/cyan]\n"
        )
    except Exception as e:
        logger.error(f"Evaluation pipeline failed: {e}")
        console.print(f"[bold red]❌ Model evaluation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 4. COMMAND: SERVE REAL-TIME INFERENCE
# ============================================================================
@app.command("serve")
def serve_cmd(
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        "-d",
        help="TimescaleDB/PostgreSQL database connection URL",
    ),
    model_version: Optional[str] = typer.Option(
        None,
        "--model-version",
        "-v",
        help="Model version to load for inference (defaults to latest active)",
    ),
    lookback_minutes: int = typer.Option(
        60,
        "--lookback-minutes",
        "-l",
        help="Log retrieval lookback window in minutes",
    ),
    daemon: bool = typer.Option(
        False,
        "--daemon",
        "-D",
        help="Run continuously in background daemon polling mode",
    ),
    interval: int = typer.Option(
        60,
        "--interval",
        "-i",
        help="Daemon polling interval in seconds",
    ),
):
    """⚡ [bold yellow]Execute AI Real-Time Inference & Risk Scoring[/bold yellow]
    
    Loads feature vectors from DB/File, scores anomalies using Cascade Model,
    computes Device Risk Index (DRI), and persists predictions.
    Supports Watermark Timestamp tracking to prevent duplicate computation.
    """
    # Automatically sync model catalog and metrics to database on service start
    try:
        from scripts.export_models_to_db import export_models_and_metrics_to_db
        export_models_and_metrics_to_db(db_url=db_url)
    except Exception as db_sync_err:
        logger.warning(f"Auto DB sync on service start: {db_sync_err}")

    if daemon:
        console.print(
            Panel(
                Text(
                    f"🔄 STARTING CONTINUOUS AI SERVING DAEMON\n"
                    f"• Polling Interval: {interval}s\n"
                    f"• Active Model:     {model_version or 'Latest'}\n"
                    f"• Watermark Sync:   Enabled (skips processed logs)",
                    style="bold yellow",
                ),
                title="[bold white]LSMP Continuous AI Serving Daemon[/bold white]",
                border_style="yellow",
            )
        )

        running = True

        def handle_signal(sig, frame):
            nonlocal running
            console.print(
                "\n[bold red]🛑 Graceful shutdown signal received. Stopping serving daemon...[/bold red]"
            )
            running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        loop_count = 0
        while running:
            loop_count += 1
            try:
                wm = get_last_watermark()
                wm_str = wm.strftime("%Y-%m-%d %H:%M:%S UTC") if wm else "Beginning of time"
                console.print(
                    f"[dim white][Loop {loop_count}] Polling for new raw logs (Watermark: {wm_str})...[/dim white]"
                )

                df_results = run_serve_pipeline(
                    model_version=model_version,
                    db_url=db_url,
                    allow_simulation_fallback=False,
                )
                if not df_results.empty:
                    console.print(
                        f"[bold green]✨ Processed and stored {len(df_results)} new risk score records.[/bold green]"
                    )
                else:
                    console.print(
                        "[dim green]🟢 Idle: No new raw logs found. Resting (No duplicate calculation).[/dim green]"
                    )
            except Exception as e:
                logger.error(f"Serving daemon loop error: {e}")
                console.print(f"[bold red]⚠️ Serving daemon warning:[/bold red] {e}")

            time.sleep(interval)

        console.print("[bold green]✅ Serving daemon stopped cleanly.[/bold green]")
    else:
        console.print(
            Panel(
                Text(
                    f"⚡ EXECUTING SINGLE BATCH INFERENCE\n"
                    f"• Model Version:    {model_version or 'Latest'}\n"
                    f"• Lookback Window:  {lookback_minutes} minutes",
                    style="bold yellow",
                ),
                title="[bold white]LSMP Batch Inference[/bold white]",
                border_style="yellow",
            )
        )
        try:
            df_results = run_serve_pipeline(
                model_version=model_version,
                db_url=db_url,
                allow_simulation_fallback=True,
            )
            console.print(
                f"[bold green]✅ Serving batch finished successfully![/bold green] "
                f"Processed [cyan]{len(df_results)}[/cyan] feature records."
            )
        except Exception as e:
            logger.error(f"Serving execution failed: {e}")
            console.print(f"[bold red]❌ Serving execution failed:[/bold red] {e}")
            raise typer.Exit(code=1)


# ============================================================================
# 5. COMMAND: MODELS CATALOG
# ============================================================================
@app.command("models")
def models_cmd():
    """📦 [bold magenta]Inspect Registered AI Model Version Catalog[/bold magenta]
    
    Lists all registered model versions stored in `models_store/`, current active version,
    registration timestamps, and evaluation metrics.
    """
    console.print(
        Panel(
            Text("📦 REGISTERED AI MODEL CATALOG INSPECTOR", style="bold magenta"),
            border_style="magenta",
        )
    )
    try:
        models_dir = BASE_DIR / "models_store"
        catalog_path = models_dir / "catalog.json"

        t_models = Table(
            title="🗃️ LSMP Model Registry Catalog",
            show_header=True,
            header_style="bold magenta",
        )
        t_models.add_column("Version", style="bold white")
        t_models.add_column("Registered At", style="dim white")
        t_models.add_column("Accuracy", justify="right")
        t_models.add_column("Precision", justify="right")
        t_models.add_column("Recall", justify="right")
        t_models.add_column("F1-Score", justify="right", style="bold green")

        if catalog_path.exists():
            with open(catalog_path, "r") as f:
                catalog = json.load(f)

            latest = catalog.get("latest_version")
            for ver, info in catalog.items():
                if ver == "latest_version":
                    continue
                met = info.get("metrics", {})
                ver_str = f"[bold green]{ver} (ACTIVE)[/bold green]" if ver == latest else ver
                t_models.add_row(
                    ver_str,
                    str(info.get("registered_at", "N/A"))[:19],
                    f"{met.get('accuracy', 0.0)*100:.2f}%",
                    f"{met.get('precision', 0.0)*100:.2f}%",
                    f"{met.get('recall', 0.0)*100:.2f}%",
                    f"{met.get('f1_score', 0.0)*100:.2f}%",
                )
            console.print(t_models)
        else:
            console.print(
                "[bold yellow]⚠️ catalog.json not found. Run `lsmp-ai train` to train and register a model.[/bold yellow]"
            )
    except Exception as e:
        logger.error(f"Models catalog query failed: {e}")
        console.print(f"[bold red]❌ Model catalog query failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 6. COMMAND: HEALTHCHECK
# ============================================================================
@app.command("healthcheck")
def healthcheck_cmd():
    """🏥 [bold cyan]Run AI Model Engine & System Health Check[/bold cyan]
    
    Audits AI model status, memory usage (RAM/CPU), DB connectivity,
    and inference latency/throughput benchmarks.
    """
    console.print(
        Panel(
            Text("🏥 EXECUTING LSMP AI MODEL ENGINE & RESOURCE AUDIT", style="bold cyan"),
            border_style="cyan",
        )
    )
    try:
        script_path = BASE_DIR / "scripts" / "healthcheck_services.py"
        subprocess.run([sys.executable, str(script_path)], check=False)
    except Exception as e:
        logger.error(f"Healthcheck failed: {e}")
        console.print(f"[bold red]❌ Healthcheck failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 7. COMMAND: THREAT SUMMARY
# ============================================================================
@app.command("threat-summary")
def threat_summary_cmd(
    top: int = typer.Option(
        10,
        "--top",
        "-n",
        help="Number of top high-risk hosts/devices to display",
    ),
):
    """📊 [bold red]Display Device Risk Index (DRI) Threat Summary Report[/bold red]
    
    Renders an executive summary ranking table of top monitored hosts by Device Risk Index (DRI),
    combining AI Anomaly Score (60%) and Wazuh Rule Severity (40%).
    """
    console.print(
        Panel(
            Text(
                f"📊 LSMP SECURITY PLATFORM — DEVICE RISK INDEX (DRI) SUMMARY REPORT\n"
                f"Formula: DRI = 100 * [0.6 * AI_Anomaly + 0.4 * Rule_Severity]",
                style="bold red",
            ),
            title="[bold white]LSMP Security Threat Report[/bold white]",
            border_style="red",
        )
    )
    try:
        fallback_path = BASE_DIR / "data" / "interim" / "predictions_fallback.csv"
        df_risk = pd.DataFrame()

        if fallback_path.exists():
            df_risk = pd.read_csv(fallback_path)

        t_summary = Table(
            title=f"🚨 Top {top} Monitored Hosts by Device Risk Index (DRI)",
            show_header=True,
            header_style="bold yellow",
        )
        t_summary.add_column("Host / Source IP", style="bold white")
        t_summary.add_column("Asset ID", style="dim white")
        t_summary.add_column("Device Risk Index (DRI)", justify="right")
        t_summary.add_column("Risk Level", justify="center")
        t_summary.add_column("AI Component (60%)", justify="right", style="cyan")
        t_summary.add_column("Rule Component (40%)", justify="right", style="magenta")

        if not df_risk.empty and "score" in df_risk.columns:
            df_top = df_risk.sort_values(by="score", ascending=False).head(top)
            for _, row in df_top.iterrows():
                score = float(row.get("score", 0.0))
                risk_class = str(row.get("risk_class", "Low"))

                if risk_class in ["High", "Critical"]:
                    style_class = f"[bold red]{risk_class}[/bold red]"
                elif risk_class == "Medium":
                    style_class = f"[bold yellow]{risk_class}[/bold yellow]"
                else:
                    style_class = f"[bold green]{risk_class}[/bold green]"

                t_summary.add_row(
                    str(row.get("src_ip", "192.168.1.100")),
                    str(row.get("asset_id", "agent-001")),
                    f"[bold red]{score:.1f} / 100[/bold red]" if score > 50 else f"{score:.1f} / 100",
                    style_class,
                    f"{float(row.get('ai_component', 0.0)):.1f}",
                    f"{float(row.get('rule_component', 0.0)):.1f}",
                )
        else:
            t_summary.add_row("192.168.1.100 (Sample)", "agent-001", "72.4 / 100", "[bold red]High[/bold red]", "42.0", "30.4")
            t_summary.add_row("192.168.1.105 (Sample)", "agent-002", "35.1 / 100", "[bold yellow]Medium[/bold yellow]", "20.1", "15.0")

        console.print(t_summary)
        console.print("\n[bold green]✅ Threat summary report rendered successfully.[/bold green]\n")
    except Exception as e:
        logger.error(f"Threat summary generation failed: {e}")
        console.print(f"[bold red]❌ Threat summary generation failed:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 8. COMMAND: TUI (TERMINAL USER INTERFACE)
# ============================================================================
@app.command("tui")
def tui_cmd():
    """🖥️ [bold cyan]Launch Live Terminal User Interface (TUI Dashboard)[/bold cyan]
    
    Launches the interactive TUI live monitoring dashboard directly inside the terminal
    for real-time security tracking and resource statistics.
    """
    console.print(
        Panel(
            Text("🖥️ LAUNCHING LSMP LIVE TERMINAL DASHBOARD (TUI)...", style="bold cyan"),
            border_style="cyan",
        )
    )
    try:
        tool_path = BASE_DIR / "tools" / "lsmp_tui.py"
        subprocess.run([sys.executable, str(tool_path)])
    except Exception as e:
        logger.error(f"Failed to launch TUI: {e}")
        console.print(f"[bold red]❌ Failed to launch TUI:[/bold red] {e}")
        raise typer.Exit(code=1)


# ============================================================================
# 9. COMMAND: VERSION
# ============================================================================
@app.command("version")
def version_cmd():
    """ℹ️ [bold white]Display LSMP AI Engine Version & Platform Metadata[/bold white]"""
    console.print(
        Panel(
            Text(
                "🛡️ LSMP AI Engine — Security Platform for SMEs\n"
                "• Engine Version:     1.0.0\n"
                "• Model Architecture: 2-Stage Cascade (Isolation Forest + One-Class SVM)\n"
                "• Feature Dimensions: 14 LSMP Feature Vectors\n"
                "• Authors:            Ngo Duc Vuong & Phan Ngoc My\n"
                "• License:            MIT License",
                style="bold white",
            ),
            title="[bold cyan]LSMP Version Metadata[/bold cyan]",
            border_style="cyan",
        )
    )


# ============================================================================
# 10. COMMAND: EXPORT DB
# ============================================================================
@app.command("export-db")
def export_db_cmd(
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        "-d",
        help="TimescaleDB/PostgreSQL database connection URL",
    ),
):
    """🗄️ [bold green]Export Model Registry & Evaluation Metrics to Database[/bold green]
    
    Reads all registered model versions, metadata, and evaluation metrics from `models_store/`
    and pushes them directly into PostgreSQL / TimescaleDB `evaluation_metrics` & `risk_score` tables.
    """
    console.print(
        Panel(
            Text("🗄️ EXPORTING ALL REGISTERED MODEL METRICS TO DATABASE", style="bold green"),
            border_style="green",
        )
    )
    try:
        from scripts.export_models_to_db import export_models_and_metrics_to_db
        success = export_models_and_metrics_to_db(db_url=db_url)
        if success:
            console.print("[bold green]✅ Model export to database completed successfully![/bold green]")
        else:
            console.print("[bold yellow]⚠️ Model export completed with warnings. Check DATABASE_URL environment variable.[/bold yellow]")
    except Exception as e:
        logger.error(f"Export to database failed: {e}")
        console.print(f"[bold red]❌ Database export failed:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

