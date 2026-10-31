# ============================================================================
# file: Dockerfile
# Description: Dockerfile for LSMP Wazuh DB Writer service (Redis -> PostgreSQL).
# ============================================================================

# ====== Base Image & System Dependencies ======
FROM python:3.11-slim

# Install system dependencies for building python packages if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# ====== Working Directory ======
WORKDIR /app

# ====== Python Dependencies ======
RUN pip install --no-cache-dir \
    redis==5.0.1 \
    SQLAlchemy==2.0.25 \
    psycopg2-binary==2.9.9

# ====== Application Code ======
COPY wazuh_db_writer.py /app/wazuh_db_writer.py

# ====== Service Execution ======
CMD ["python", "wazuh_db_writer.py"]
