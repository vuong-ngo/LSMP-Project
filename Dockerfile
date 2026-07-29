# ============================================================================
# file: Dockerfile
# Description: Production Dockerfile for LSMP AI Engine.
# ============================================================================

FROM python:3.12-slim as base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition files
COPY pyproject.toml requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and resources
COPY src/ ./src/
COPY configs/ ./configs/
COPY infrastructure/database_stack/schema.sql ./infrastructure/database_stack/schema.sql
COPY data/ ./data/
COPY models_store/ ./models_store/

# Install package in editable mode
RUN pip install --no-cache-dir -e .

RUN mkdir -p /app/logs /app/reports /app/models_store

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "lsmp_ai.serving.lsmp_writer_service:app", "--host", "0.0.0.0", "--port", "8000"]
