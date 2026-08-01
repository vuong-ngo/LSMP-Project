# ============================================================================
# file: src/lsmp_ai/scripts/autotrain.py
# Description: Background Auto-Retraining Service Daemon (Pure Python).
#              Periodically re-trains Cascade Model on new data every N hours/seconds.
# ============================================================================

import os
import sys
import time
import signal
import subprocess
import argparse
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.scripts.train import run_training

logger = setup_logger(__name__)

PID_FILE = BASE_DIR / "logs" / "autotrain.pid"
LOG_FILE = BASE_DIR / "logs" / "autotrain.log"


def start_autotrain_daemon(interval_hours: float = 24.0, interval_seconds: int = None) -> None:
    """Starts the auto-retraining daemon service in the background."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            import psutil
            if psutil.pid_exists(pid):
                print(f"⚠️ LSMP Auto-Retraining Daemon is ALREADY RUNNING with PID: {pid}")
                print(f"   Log file: {LOG_FILE}")
                return
            else:
                PID_FILE.unlink(missing_ok=True)
        except Exception:
            PID_FILE.unlink(missing_ok=True)

    seconds = interval_seconds if interval_seconds is not None else int(interval_hours * 3600)

    print("=================================================================")
    print("🚀 STARTING LSMP AUTO-RETRAIN DAEMON SERVICE (PURE PYTHON)")
    print("=================================================================")
    print(f"  • Retrain Interval: {interval_hours:.1f} hours ({seconds} seconds)")
    print(f"  • Log File:         {LOG_FILE}")
    print("=================================================================")

    cmd = [
        sys.executable, "-m", "lsmp_ai.scripts.autotrain",
        "run", "--seconds", str(seconds)
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BASE_DIR / "src")

    with open(LOG_FILE, "a") as log_out:
        proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=log_out, stderr=log_out, env=env)

    PID_FILE.write_text(str(proc.pid))
    time.sleep(1)

    if proc.poll() is None:
        print(f"✅ Auto-Retraining Daemon started successfully! PID: {proc.pid}")
        print(f"   To view live logs, run: tail -f {LOG_FILE}")
        print("   To stop service, run: lsmp-ai autotrain stop")
    else:
        print(f"❌ Daemon process exited unexpectedly. Check log at: {LOG_FILE}")
        sys.exit(1)


def stop_autotrain_daemon() -> None:
    """Stops the running auto-retraining daemon service."""
    print("=================================================================")
    print("🛑 STOPPING LSMP AUTO-RETRAIN DAEMON SERVICE")
    print("=================================================================")

    stopped = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            import psutil
            if psutil.pid_exists(pid):
                print(f"Stopping autotrain process (PID: {pid})...")
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
        print("✅ Auto-Retraining Daemon stopped successfully.")
    else:
        print("ℹ️ No active auto-retraining daemon was found running.")


def run_autotrain_loop(seconds: int = 86400) -> None:
    """Continuous background loop for periodic model auto-retraining."""
    logger.info(f"Starting LSMP Auto-Retrain Daemon loop with interval {seconds}s ({seconds/3600:.1f}h)...")

    running = True

    def handle_shutdown(sig, frame):
        nonlocal running
        logger.info("Shutdown signal received. Stopping autotrain loop...")
        running = False

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    while running:
        try:
            now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            ver_name = f"cascade-auto-{now_str}"
            logger.info(f"Triggering scheduled model retraining for version: {ver_name}...")
            run_training(model_version=ver_name)
            logger.info(f"Scheduled model retraining completed successfully for version: {ver_name}.")
        except Exception as err:
            logger.error(f"Error during auto-retraining loop: {err}")

        # Sleep interval with interrupt handling
        for _ in range(seconds):
            if not running:
                break
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="LSMP Auto-Retraining Service Daemon (Pure Python)")
    parser.add_argument("action", nargs="?", choices=["start", "stop", "status", "run"], default="status", help="Service control action")
    parser.add_argument("--hours", "-H", type=float, default=24.0, help="Retrain interval in hours (default: 24.0)")
    parser.add_argument("--seconds", "-S", type=int, default=None, help="Retrain interval in seconds (overrides hours)")
    args = parser.parse_args()

    if args.action == "start":
        start_autotrain_daemon(interval_hours=args.hours, interval_seconds=args.seconds)
    elif args.action == "stop":
        stop_autotrain_daemon()
    elif args.action == "run":
        sec = args.seconds if args.seconds is not None else int(args.hours * 3600)
        run_autotrain_loop(seconds=sec)
    else:
        if PID_FILE.exists():
            pid = PID_FILE.read_text().strip()
            print(f"LSMP Auto-Retraining Daemon is running with PID: {pid}")
        else:
            print("LSMP Auto-Retraining Daemon is STOPPED")


if __name__ == "__main__":
    main()
