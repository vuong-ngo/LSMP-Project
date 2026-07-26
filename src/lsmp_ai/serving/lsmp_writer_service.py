# ============================================================================
# file: serving/lsmp_writer_service.py
# Description: Asynchronous AI Writer & Inference Service (FastAPI).
# ============================================================================

# ===== IMPORT MODULES =====
import os
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel

from lsmp_ai.common.logger import logger
from lsmp_ai.pipeline.serve_pipeline import run_serve_pipeline
from lsmp_ai.models.registry import ModelRegistry

# ===== FASTAPI APP INITIALIZATION =====
app = FastAPI(
    title="LSMP AI High-Throughput Writer Service",
    description="Asynchronous serving service for Cascade iForest-OCSVM model & Risk Scoring",
    version="1.0.0"
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


# ===== LIFECYCLE HOOKS =====
@app.on_event("startup")
async def startup_event():
    """Lifecycle hook: Preloads ML binaries and starts background time-series worker."""
    global active_model, feature_pipeline, background_loop_task
    logger.info("Starting up LSMP Writer Service...")
    
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
    except Exception as e:
        logger.error(f"Failed to preload model/pipeline binaries on startup: {e}. Running in standby.")

    background_loop_task = asyncio.create_task(run_background_pipeline())


@app.on_event("shutdown")
async def shutdown_event():
    """Lifecycle hook: Cancels running background tasks and releases resources."""
    logger.info("Shutting down LSMP Writer Service...")
    if background_loop_task:
        background_loop_task.cancel()
        try:
            await background_loop_task
        except asyncio.CancelledError:
            logger.info("Background serve daemon task stopped successfully.")


# ===== REST ENDPOINTS =====
@app.get("/health")
async def health_check():
    """Status endpoint used by Docker Compose and monitoring stacks."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_loaded": active_model is not None,
        "model_version": model_version,
        "database_configured": db_url is not None
    }


@app.get("/metadata")
async def get_metadata():
    """Retrieves active model version info, hyper-parameters, and thresholds."""
    if active_model is None:
        raise HTTPException(status_code=503, detail="Model binaries not loaded on host.")
        
    return {
        "model_version": active_model.model_version,
        "anomaly_threshold": getattr(active_model, "anomaly_threshold", None),
        "normal_threshold": getattr(active_model, "normal_threshold", None),
        "parameters": getattr(active_model, "params", {})
    }


@app.post("/process")
async def trigger_manual_process(req: ProcessRequest, background_tasks: BackgroundTasks):
    """
    Manual pipeline trigger. Processes logs in specified datetime window
    asynchronously without blocking the HTTP response.
    """
    try:
        start_dt = datetime.fromisoformat(req.start_time)
        end_dt = datetime.fromisoformat(req.end_time)
    except ValueError:
        raise HTTPException(
            status_code=400, 
            detail="Invalid timestamp formats. Use ISO-8601 (e.g. YYYY-MM-DDTHH:MM:SS)"
        )
        
    v_to_use = req.model_version or model_version
    
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
