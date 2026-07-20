# LSMP Ingestion Server & Database Writer

This directory contains the services deployed on **Server B** (Database & AI Server) that receive security alert logs from Fluent-bit (on Server A), buffer them in a Redis stream queue, and write them in optimized batches to the TimescaleDB/PostgreSQL database.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/server/database_server/
├── docker-compose.yml       # Docker Compose service definition for Server B
├── .env.example             # Environment configurations template
├── Dockerfile               # Production Dockerfile for the db writer
├── Dockerfile.ingest        # Production Dockerfile for the HTTP ingest receiver
├── ingest_receiver.py       # Python HTTP server to receive logs and append to Redis
├── wazuh_db_writer.py       # Python script consuming Redis and batch inserting into PostgreSQL
└── requirements.txt         # Pinned Python package dependencies
```

---

## 🏛 Component Architecture

The database server stack runs **three core components** that communicate internally over the shared Docker network:

| Component | Container Name | Default Ports | Description |
| :--- | :--- | :--- | :--- |
| **Ingest Receiver** | `lsmp-ingest` | `8080/tcp` (Exposed) | A lightweight HTTP endpoint `/ingest` that validates incoming request tokens and appends raw log lines into Redis. |
| **Redis Queue Cache** | `lsmp-redis` | `6379/tcp` (Internal) | A secured, persistent in-memory stream buffer (`wazuh_stream`) acting as a backpressure safety valve. |
| **Database Writer** | `lsmp-db-writer` | None | A background daemon consuming events from Redis and performing batch INSERT transactions into the database. |

---

## 🚀 Getting Started

Follow these steps to deploy the ingestion services on Server B:

### 1. Prerequisites

Ensure you have created the shared external bridge network before starting the stack:
```bash
docker network create lsmp_backend
```

### 2. Environment Setup

Copy the environment template and set your credentials:
```bash
cp .env.example .env
```

Open the `.env` file and configure the parameters:
```env
# Strong Redis authentication password
REDIS_PASSWORD=SecretRedisPassword123

# Ingest token for Fluent-bit webhook verification (Must match Server A)
INGEST_TOKEN=CHANGE_ME_RANDOM_LONG_SECRET

# Connection credentials for the PostgreSQL service (lsmp-postgres)
DB_USER=postgres
DB_PASSWORD=CHANGE_ME_STRONG_POSTGRES_PASSWORD
DB_NAME=lsmp_db
```

### 3. Startup & Build

To build the custom Python runner images and start the containers in the background:
```bash
docker compose up -d --build
```

---

## 🛑 Teardown & Maintenance

To safely stop the database server ingestion stack:
```bash
docker compose down
```

To stop the services and purge the Redis persistent data volume:
```bash
docker compose down -v
```
