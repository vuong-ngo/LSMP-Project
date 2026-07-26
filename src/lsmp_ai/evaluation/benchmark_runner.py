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
    latency_p99_ms: float = 0.0
    throughput_rows_per_sec: float = 0.0
    memory_usage_mb: float = 0.0


# ===== BENCHMARK INFERENCE FUNCTION =====
def benchmark_inference(
    model,
    X: np.ndarray | pd.DataFrame,
    n_runs: int = 100,
    model_name: str = "model",
) -> BenchmarkResult:
    latencies = []

    for _ in range(n_runs):
        start = time.perf_counter()
        _ = model.predict(X)
        elapsed = (time.perf_counter() - start) * 1000
        latencies.append(elapsed)

    latencies = np.array(latencies)
    import resource
    ram_mb = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0)

    result = BenchmarkResult(
        model_name=model_name,
        latency_mean_ms=float(np.mean(latencies)),
        latency_std_ms=float(np.std(latencies)),
        latency_p99_ms=float(np.percentile(latencies, 99)),
        throughput_rows_per_sec=float(len(X) / (np.mean(latencies) / 1000)),
        memory_usage_mb=ram_mb,
    )

    logger.info(
        f"Benchmark {model_name}: "
        f"mean={result.latency_mean_ms:.2f}ms, "
        f"p99={result.latency_p99_ms:.2f}ms, "
        f"throughput={result.throughput_rows_per_sec:.0f} rows/sec"
    )

    return result
