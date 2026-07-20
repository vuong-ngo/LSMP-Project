FROM python:3.11-slim

# Install system dependencies for building python packages if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install python requirements
RUN pip install --no-cache-dir \
    redis==5.0.1 \
    SQLAlchemy==2.0.25 \
    psycopg2-binary==2.9.9

# Copy the service script
COPY wazuh_db_writer.py /app/wazuh_db_writer.py

# Run the writer
CMD ["python", "wazuh_db_writer.py"]
