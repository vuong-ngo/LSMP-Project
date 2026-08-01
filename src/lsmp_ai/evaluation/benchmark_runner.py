# ============================================================================
# file: evaluation/benchmark_runner.py
# Description: Inference latency and throughput benchmarking tool.
# ============================================================================

# ===== IMPORT MODULES =====
import time
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from lsmp_ai.common.logger import setup_logger

logger = setup_logger(__name__)


# ===== DATACLASS =====
@dataclass
class BenchmarkResult:
    model_name: str = ""
    latency_mean_ms: float = 0.0
    latency_std_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    throughput_rows_per_sec: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0


# ===== BENCHMARK INFERENCE FUNCTION =====
def benchmark_inference(
    model,
    X: np.ndarray | pd.DataFrame,
    n_runs: int = 100,
    model_name: str = "model",
) -> BenchmarkResult:
    import os, threading
    latencies = []
    cpu_samples = []
    running = True

    try:
        import psutil
        process = psutil.Process(os.getpid())
        # Initial call to prime psutil cpu_percent
        process.cpu_percent(interval=None)

        def _monitor():
            while running:
                try:
                    cpu_samples.append(process.cpu_percent(interval=0.05))
                except Exception:
                    break

        monitor_thread = threading.Thread(target=_monitor, daemon=True)
        monitor_thread.start()
        has_psutil = True
    except ImportError:
        has_psutil = False
        t_start_cpu = os.times()

    start_wall = time.perf_counter()
    for _ in range(n_runs):
        start = time.perf_counter()
        _ = model.predict(X)
        elapsed = (time.perf_counter() - start) * 1000
        latencies.append(elapsed)
    total_wall_sec = time.perf_counter() - start_wall

    running = False

    latencies = np.array(latencies)

    # Memory usage
    try:
        import psutil
        process = psutil.Process(os.getpid())
        ram_mb = float(process.memory_info().rss / (1024.0 * 1024.0))
    except Exception:
        import resource
        ram_mb = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0)

    # CPU usage calculation
    if has_psutil and cpu_samples:
        avg_cpu = float(np.mean(cpu_samples))
    else:
        try:
            t_end_cpu = os.times()
            cpu_time = (t_end_cpu.user - t_start_cpu.user) + (t_end_cpu.system - t_start_cpu.system)
            avg_cpu = float(min(100.0 * (psutil.cpu_count() if 'psutil' in locals() else 1), (cpu_time / max(total_wall_sec, 1e-6)) * 100.0))
        except Exception:
            avg_cpu = 0.0

    result = BenchmarkResult(
        model_name=model_name,
        latency_mean_ms=float(np.mean(latencies)),
        latency_std_ms=float(np.std(latencies)),
        latency_p95_ms=float(np.percentile(latencies, 95)),
        latency_p99_ms=float(np.percentile(latencies, 99)),
        throughput_rows_per_sec=float((len(X) * n_runs) / max(total_wall_sec, 1e-6)),
        memory_usage_mb=ram_mb,
        cpu_usage_percent=round(avg_cpu, 2),
    )

    logger.info(
        f"Benchmark {model_name}: "
        f"mean={result.latency_mean_ms:.2f}ms, "
        f"p95={result.latency_p95_ms:.2f}ms, "
        f"p99={result.latency_p99_ms:.2f}ms, "
        f"throughput={result.throughput_rows_per_sec:.0f} rows/sec, "
        f"cpu={result.cpu_usage_percent}%, "
        f"ram={result.memory_usage_mb:.2f}MB"
    )

    return result
