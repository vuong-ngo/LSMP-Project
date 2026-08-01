# ============================================================================
# file: src/lsmp_ai/scripts/serve.py
# Description: Real-Time AI Serving Daemon & Process Control (Pure Python).
#              Combines Wazuh Rule-Based Severity + AI Anomaly Score to calculate RiskScore.
#              Verifies Database Connectivity & Table Existence BEFORE Execution.
# ============================================================================

import os
import sys
import time
import json
import signal
import subprocess
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.pipeline.serve_pipeline import run_serve_pipeline, get_last_watermark

logger = setup_logger(__name__)

PID_FILE = BASE_DIR / "logs" / "service.pid"
SERVICE_LOG = BASE_DIR / "logs" / "service.log"


def verify_database_readiness() -> bool:
    """Checks if DATABASE_URL is set, DB is online, and required tables exist before starting serve daemon."""
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("\n❌ [DATABASE ERROR] DATABASE_URL is not set in environment or .env file.")
        print("   Please configure DATABASE_URL in .env before running the serving daemon.")
        return False

    try:
        from lsmp_ai.io.db_client import DBClient
        db_client = DBClient()
        if not db_client.db_url:
            print("\n❌ [DATABASE ERROR] DBClient could not initialize connection URL.")
            return False

        required_tables = ["log_event", "feature_vectors", "anomaly_result", "risk_score"]
        from sqlalchemy import inspect
        inspector = inspect(db_client.engine)
        existing_tables = inspector.get_table_names()

        missing_tables = [t for t in required_tables if t not in existing_tables]
        if missing_tables:
            print(f"\n❌ [DATABASE ERROR] Required database tables are MISSING: {', '.join(missing_tables)}")
            print("   Please initialize the database schema first using schema.sql in infrastructure/database_stack/schema.sql")
            return False

        logger.info("Database connection and required tables successfully verified.")
        return True
    except Exception as err:
        print(f"\n❌ [DATABASE ERROR] Failed to connect to Database: {err}")
        return False


def start_serving_daemon(interval: int = 10, lookback_minutes: int = 60) -> None:
    """Starts the real-time AI serving daemon process in the background using pure Python."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            import psutil
            if psutil.pid_exists(pid):
                print(f"⚠️ LSMP Real-time Serving Daemon is ALREADY RUNNING with PID: {pid}")
                print(f"   Log file: {SERVICE_LOG}")
                return
            else:
                PID_FILE.unlink(missing_ok=True)
        except Exception:
            PID_FILE.unlink(missing_ok=True)

    # Mandatory DB Presence Check before starting
    print("🔍 Verifying Database Connectivity & Table Schema...")
    if not verify_database_readiness():
        print("❌ Serving daemon start ABORTED due to Database check failure.")
        sys.exit(1)

    print("=================================================================")
    print("🚀 STARTING LSMP AI REAL-TIME SERVING DAEMON (PURE PYTHON)")
    print("=================================================================")
    print(f"  • Polling Interval: {interval} seconds")
    print(f"  • Log File:         {SERVICE_LOG}")
    print("=================================================================")

    # Spawn background daemon process running this script in 'run' mode
    cmd = [
        sys.executable, "-m", "lsmp_ai.scripts.serve",
        "run", "--interval", str(interval), "--lookback", str(lookback_minutes)
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BASE_DIR / "src")

    with open(SERVICE_LOG, "a") as log_out:
        proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=log_out, stderr=log_out, env=env)

    PID_FILE.write_text(str(proc.pid))
    time.sleep(2)

    if proc.poll() is None:
        print(f"✅ LSMP AI Real-time Service started successfully! PID: {proc.pid}")
        print(f"   To view live logs, run: tail -f {SERVICE_LOG}")
        print("   To stop service, run: lsmp-ai serve stop")
    else:
        print(f"❌ Daemon process exited unexpectedly. Check log at: {SERVICE_LOG}")
        if SERVICE_LOG.exists():
            print("--- LOG OUTPUT ---")
            print(SERVICE_LOG.read_text()[-500:])
        sys.exit(1)


def stop_serving_daemon() -> None:
    """Stops the running real-time serving daemon smoothly."""
    print("=================================================================")
    print("🛑 STOPPING LSMP AI REAL-TIME SERVING DAEMON")
    print("=================================================================")

    stopped = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            import psutil
            if psutil.pid_exists(pid):
                print(f"Stopping daemon process (PID: {pid})...")
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                if psutil.pid_exists(pid):
                    os.kill(pid, signal.SIGKILL)
                print(f"✅ Process {pid} stopped.")
                stopped = True
            else:
                print(f"Process {pid} is not running.")
        except Exception as e:
            print(f"Warning while stopping process: {e}")
        PID_FILE.unlink(missing_ok=True)

    if stopped:
        print("✅ LSMP AI Real-time Service stopped successfully.")
    else:
        print("ℹ️ No active LSMP AI serving daemon was found running.")


def run_daemon_loop(interval: int = 10, lookback_minutes: int = 60) -> None:
    """Continuous background loop for real-time log polling, feature calculation, and risk scoring."""
    logger.info(f"Starting LSMP Real-time Serving Loop with polling interval {interval}s...")

    running = True

    def handle_shutdown(sig, frame):
        nonlocal running
        logger.info("Shutdown signal received. Gracefully stopping daemon loop...")
        running = False

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    while running:
        try:
            now_utc = datetime.now(timezone.utc)
            last_wm = get_last_watermark()
            start_time = last_wm if last_wm else (now_utc - timedelta(minutes=lookback_minutes))

            df_res = run_serve_pipeline(start_time=start_time, end_time=now_utc)
            if not df_res.empty:
                logger.info(f"Processed batch of {len(df_res)} host vectors and calculated Risk Scores.")
            else:
                logger.info("No new log events in this window. Standing by.")
        except Exception as err:
            logger.error(f"Error in serving daemon loop: {err}")

        for _ in range(interval):
            if not running:
                break
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="LSMP Real-Time AI Serving Daemon Service (Pure Python)")
    parser.add_argument("action", nargs="?", choices=["start", "stop", "status", "run"], default="status", help="Service control action")
    parser.add_argument("--interval", "-i", type=int, default=10, help="Polling interval in seconds (default: 10)")
    parser.add_argument("--lookback", "-l", type=int, default=60, help="Initial lookback window in minutes (default: 60)")
    args = parser.parse_args()

    if args.action == "start":
        start_serving_daemon(interval=args.interval, lookback_minutes=args.lookback)
    elif args.action == "stop":
        stop_serving_daemon()
    elif args.action == "run":
        if not verify_database_readiness():
            sys.exit(1)
        run_daemon_loop(interval=args.interval, lookback_minutes=args.lookback)
    else:
        # Status check
        if PID_FILE.exists():
            pid = PID_FILE.read_text().strip()
            print(f"LSMP AI Serving Daemon is running with PID: {pid}")
        else:
            print("LSMP AI Serving Daemon is STOPPED")


if __name__ == "__main__":
    main()
