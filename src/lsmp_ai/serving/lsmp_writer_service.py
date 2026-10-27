# ============================================================================
# file: serving/lsmp_writer_service.py
# Description: Asynchronous AI Writer & Inference Service (FastAPI).
# ============================================================================

# ===== IMPORT MODULES =====
import os
import secrets
import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from lsmp_ai.common.logger import logger
from lsmp_ai.pipeline.serve_pipeline import run_serve_pipeline
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.version import __version__


# ===== API KEY AUTHENTICATION (FAIL-CLOSED SECURITY POLICY) =====
def is_insecure_dev_allowed() -> bool:
    """Checks if insecure development mode is explicitly enabled via environment variable."""
    return os.getenv("LSMP_ALLOW_INSECURE_DEV", "0").lower() in ("1", "true", "yes")

def get_configured_api_key() -> str:
    """Retrieves server-side configured API key."""
    return os.getenv("LSMP_API_KEY", "").strip()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> Optional[str]:
    """Validates the API key from X-API-Key header using constant-time comparison (Fail-Closed).

    Authentication is mandatory by default (S1 defense).
    If LSMP_API_KEY is not configured and LSMP_ALLOW_INSECURE_DEV=1 is NOT explicitly set,
    all protected requests are rejected with 500 to prevent unauthenticated access.
    When LSMP_ALLOW_INSECURE_DEV=1 is explicitly set, authentication is bypassed for dev testing only.
    """
    if is_insecure_dev_allowed():
        return None

    configured_key = get_configured_api_key()
    if not configured_key:
        logger.error(
            "Authentication rejected: LSMP_API_KEY is not configured (fail-closed). "
            "Set LSMP_API_KEY in .env, or set LSMP_ALLOW_INSECURE_DEV=1 for dev testing."
        )
        raise HTTPException(
            status_code=500,
            detail="Server authentication misconfiguration: LSMP_API_KEY is required but unset. "
                   "Configure LSMP_API_KEY or explicitly set LSMP_ALLOW_INSECURE_DEV=1 for dev mode.",
        )

    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header. Authentication required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not secrets.compare_digest(api_key.encode("utf-8"), configured_key.encode("utf-8")):
        logger.warning("Rejected invalid API key attempt.")
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )

    return api_key


# ===== SECURE IP RESOLUTION & RATE LIMITER (S4 DEFENSE) =====
def get_client_ip(request: Request) -> str:
    """Extracts client IP address safely, supporting reverse-proxy headers when explicitly trusted.

    If LSMP_TRUST_PROXY_HEADERS=1 is enabled, prioritizes X-Forwarded-For (client IP) or X-Real-IP.
    Otherwise, defaults to direct peer connection IP (request.client.host) to prevent header spoofing.
    """
    trust_proxy = os.getenv("LSMP_TRUST_PROXY_HEADERS", "0").lower() in ("1", "true", "yes")
    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For may contain multiple proxies: client, proxy1, proxy2
            return forwarded_for.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


class RateLimiter:
    """Bounded, memory-safe in-memory sliding window rate limiter with LRU eviction.

    Prevents unbounded memory growth (DoS) from rotating/spoofed IP addresses:
    1. Prunes expired timestamps and deletes empty IP buckets.
    2. Enforces a maximum number of simultaneously tracked client IPs.
    3. Evicts stale entries when capacity is reached.

    Note: In multi-worker or distributed deployments, rate limiting should be delegated
    to an API Gateway / Ingress Controller (e.g., Nginx, Traefik, Kong, Envoy).
    """

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        max_tracked_ips: int = 10000,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tracked_ips = max_tracked_ips
        self._requests: Dict[str, list] = {}

    def is_allowed(self, client_ip: str) -> bool:
        """Checks if the client IP is within rate limits and records the request."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        # Memory bound check: purge expired keys if capacity is reached
        if len(self._requests) >= self.max_tracked_ips and client_ip not in self._requests:
            expired_keys = [
                ip for ip, timestamps in self._requests.items()
                if not timestamps or timestamps[-1] <= cutoff
            ]
            for ip in expired_keys:
                del self._requests[ip]
            # If still saturated, evict oldest entry
            if len(self._requests) >= self.max_tracked_ips:
                first_key = next(iter(self._requests))
                del self._requests[first_key]

        timestamps = self._requests.get(client_ip, [])
        valid_timestamps = [ts for ts in timestamps if ts > cutoff]

        if len(valid_timestamps) >= self.max_requests:
            self._requests[client_ip] = valid_timestamps
            return False

        valid_timestamps.append(now)
        self._requests[client_ip] = valid_timestamps
        return True


rate_limiter = RateLimiter(
    max_requests=int(os.getenv("LSMP_RATE_LIMIT_MAX", "30")),
    window_seconds=int(os.getenv("LSMP_RATE_LIMIT_WINDOW", "60")),
    max_tracked_ips=int(os.getenv("LSMP_RATE_LIMIT_MAX_IPS", "10000")),
)


async def check_rate_limit(request: Request) -> None:
    """FastAPI dependency that enforces per-IP rate limiting on protected endpoints."""
    client_ip = get_client_ip(request)
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for IP {client_ip}.")
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
        )


# ===== LIFESPAN CONTEXT MANAGER =====
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan handler: preloads ML binaries on startup, cancels tasks on shutdown."""
    global active_model, feature_pipeline, background_loop_task
    logger.info("Starting up LSMP Writer Service...")

    if not is_insecure_dev_allowed() and get_configured_api_key():
        logger.info("API Key authentication is ENABLED (Fail-Closed). Protected endpoints require X-API-Key header.")
    elif is_insecure_dev_allowed():
        logger.warning("API Key authentication is BYPASSED due to LSMP_ALLOW_INSECURE_DEV=1.")
    else:
        logger.warning("LSMP_API_KEY is unset! Protected endpoints will reject requests with HTTP 500.")


    try:
        registry = ModelRegistry()
        active_model = registry.load_model(model_version)
        version = active_model.model_version

        from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
        pipeline_path = os.path.join(registry.registry_dir, version, "feature_pipeline.joblib")
        if os.path.exists(pipeline_path):
            feature_pipeline = FeaturePipeline.load(pipeline_path)
            logger.info(f"Loaded model version {version} and feature pipeline successfully.")
        else:
            logger.warning(f"Feature pipeline binary not found at {pipeline_path}.")

        try:
            from lsmp_ai.scripts.export_db import export_models_to_db
            export_models_to_db()
            logger.info("Automatically exported active model catalog and metrics to Database on startup.")
        except Exception as db_err:
            logger.warning(f"Automatic DB export on service startup: {db_err}")


    except Exception as e:
        logger.error(f"Failed to preload model/pipeline binaries on startup: {e}. Running in standby.")

    background_loop_task = asyncio.create_task(run_background_pipeline())


    yield  # App is running

    # Shutdown
    logger.info("Shutting down LSMP Writer Service...")
    if background_loop_task:
        background_loop_task.cancel()
        try:
            await background_loop_task
        except asyncio.CancelledError:
            logger.info("Background serve daemon task stopped successfully.")


# ===== FASTAPI APP INITIALIZATION =====
app = FastAPI(
    title="LSMP AI High-Throughput Writer Service",
    description="Asynchronous serving service for Cascade iForest-OCSVM model & Risk Scoring",
    version=__version__,
    lifespan=lifespan
)

# Global model state
active_model = None
feature_pipeline = None
model_version = os.getenv("MODEL_VERSION", "cascade-v1.0")
db_url = os.getenv("DATABASE_URL", None)
polling_interval = int(os.getenv("POLLING_INTERVAL_SECONDS", "60"))

# Background daemon task reference
background_loop_task = None


# ===== REQUEST SCHEMAS =====
class ProcessRequest(BaseModel):
    start_time: str
    end_time: str
    model_version: Optional[str] = None


# ===== BACKGROUND WORKER DAEMON =====
async def run_background_pipeline():
    """
    Asynchronous daemon polling PostgreSQL/TimescaleDB for new log_events,
    aggregating features, computing anomaly scores and saving risk outputs.
    """
    logger.info(f"Initializing background serve daemon with interval {polling_interval}s...")
    await asyncio.sleep(5)  # Wait for startup and other containers to initialize

    while True:
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(seconds=polling_interval)

            logger.info(f"Triggering background serving pipeline window: {start_time.isoformat()} to {end_time.isoformat()}")

            # ML predictions and database fetches run in thread pool via asyncio.to_thread
            df_results = await asyncio.to_thread(
                run_serve_pipeline,
                start_time=start_time,
                end_time=end_time,
                model_version=model_version,
                db_url=db_url
            )

            if not df_results.empty:
                logger.info(f"Successfully processed batch of {len(df_results)} host vectors.")
            else:
                logger.info("No active log records found in this window. Standing by.")

        except Exception as e:
            logger.error(f"Error encountered in background AI pipeline loop: {e}")

        await asyncio.sleep(polling_interval)




# ===== REST ENDPOINTS =====
@app.get("/health")
async def health_check():
    """Minimal unauthenticated health check endpoint for container probes (S5 Defense).

    Reconnaissance details (model_version, model_loaded, database_configured) are omitted
    from public unauthenticated responses and protected under authenticated /metadata.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }



@app.get("/metadata", dependencies=[Depends(check_rate_limit), Depends(verify_api_key)])
async def get_metadata():
    """Retrieves active model version info, hyper-parameters, and thresholds."""
    if active_model is None:
        raise HTTPException(status_code=503, detail="Model binaries not loaded on host.")

    return {
        "engine_version": __version__,
        "model_version": active_model.model_version,
        "anomaly_threshold": getattr(active_model, "anomaly_threshold", None),
        "normal_threshold": getattr(active_model, "normal_threshold", None),
        "parameters": getattr(active_model, "params", {})
    }


@app.post("/process", dependencies=[Depends(check_rate_limit), Depends(verify_api_key)])
async def trigger_manual_process(req: ProcessRequest, background_tasks: BackgroundTasks):
    try:
        start_dt = datetime.fromisoformat(req.start_time)
        end_dt = datetime.fromisoformat(req.end_time)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid timestamp formats. Use ISO-8601 (e.g. YYYY-MM-DDTHH:MM:SS)"
        )

    if start_dt > end_dt:
        raise HTTPException(
            status_code=400,
            detail="start_time must be earlier than or equal to end_time."
        )

    # Prevent DoS through excessively large window queries
    max_window_hours = 168  # 7 days
    if (end_dt - start_dt) > timedelta(hours=max_window_hours):
        raise HTTPException(
            status_code=400,
            detail=f"Requested time window exceeds maximum allowed limit of {max_window_hours} hours."
        )

    v_to_use = req.model_version or model_version
    import re
    if v_to_use and not re.match(r"^[a-zA-Z0-9_\-\.]+$", v_to_use):
        raise HTTPException(
            status_code=400,
            detail="Invalid model_version format. Only alphanumeric characters, dashes, and underscores allowed."
        )

    background_tasks.add_task(
        run_serve_pipeline,
        start_time=start_dt,
        end_time=end_dt,
        model_version=v_to_use,
        db_url=db_url
    )

    return {
        "status": "queued",
        "message": "Serving pipeline triggered in the background.",
        "window": f"{start_dt} to {end_dt}",
        "model_version": v_to_use
    }
