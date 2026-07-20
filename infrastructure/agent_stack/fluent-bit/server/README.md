# LSMP Fluent-bit Ingestion Pipeline

This directory contains the server-side log ingestion infrastructure responsible for collecting Wazuh Manager security alerts and streaming them into the LSMP PostgreSQL database. It is designed for a **2-server deployment model** where the Wazuh Manager (Server A) and the Database & AI engine (Server B) run on separate physical machines.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/server/
├── wazuh_server/                    # Deployed on Server A (Wazuh Manager host)
│   ├── docker-compose.yml           # Fluent-bit service definition
│   ├── .env.example                 # Environment variables template
│   └── config/
│       ├── fluent-bit.conf          # Fluent-bit INPUT/OUTPUT configuration
│       └── parsers.conf             # JSON parser for Wazuh alerts
│
└── database_server/                 # Deployed on Server B (Database & AI host)
    ├── docker-compose.yml           # Redis, Ingest Receiver & DB Writer services
    ├── .env.example                 # Environment variables template
    ├── Dockerfile                   # Image for lsmp-db-writer (Python + SQLAlchemy)
    ├── Dockerfile.ingest            # Image for lsmp-ingest (Python + Redis only)
    ├── ingest_receiver.py           # HTTP endpoint → Redis Stream (XADD)
    └── wazuh_db_writer.py           # Redis Stream consumer → PostgreSQL batch INSERT
```

---

## 🏛 Component Architecture

The log ingestion pipeline operates across two physical hosts:

| Component | Container Name | Host | Default Ports | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Fluent-bit Shipper** | `lsmp-fluent-bit` | Server A | None | Tails Wazuh manager logs and forwards alerts as JSON lines over HTTP. |
| **Ingest Receiver** | `lsmp-ingest` | Server B | `8080/tcp` (Exposed) | A lightweight HTTP endpoint `/ingest` that validates tokens and writes to Redis. |
| **Redis Queue** | `lsmp-redis` | Server B | `6379/tcp` (Internal) | Capped, secure in-memory Stream queue (`wazuh_stream`) acting as a buffer. |
| **Database Writer** | `lsmp-db-writer` | Server B | None | Consumes logs from Redis and performs batch INSERTs into PostgreSQL. |

---

## 🔒 Security Architecture

### 1. Token-Based HTTP Authentication

Since the HTTP endpoint (`/ingest`) is exposed on the network interface of Server B, a shared-secret token mechanism is implemented to protect it:
* **Fluent-bit** (Server A) sends the token in the `X-Ingest-Token` HTTP header with every request.
* **Ingest Receiver** (Server B) validates the token. Mismatched requests receive `HTTP 401`.
* The `INGEST_TOKEN` environment variable **must be identical** in both `wazuh_server/.env` and `database_server/.env`.

### 2. Internal Network Isolation

* Redis (`6379`) is not exposed to the host network; it is only accessible internally via the `lsmp_backend` bridge network.
* PostgreSQL is bound to loopback only (`127.0.0.1:5432`) on the host, restricting remote access.

---

## 🚀 Deployment Guide

### 1. Environment Setup

Configure Server B (Database & AI Server):
```bash
docker network create lsmp_backend
cd database_server/
cp .env.example .env
```

Configure Server A (Wazuh Server):
```bash
cd wazuh_server/
cp .env.example .env
```

Ensure configuration credentials (like `INGEST_TOKEN` and `DB_PASSWORD`) are synchronized across servers.

### 2. Start the Ingestion Pipeline

#### A. Start Ingestion services (Server B)
First, ensure your `database_stack` database container is running and healthy. Then run:
```bash
cd database_server/
docker compose up -d --build
```

#### B. Start Log Forwarding agent (Server A)
Once Server B is healthy and listening on port `8080`, start the Fluent-bit shipper:
```bash
cd wazuh_server/
docker compose up -d
```

### 3. Verification & Testing

#### A. Check Ingest Receiver Logs
```bash
docker logs lsmp-ingest -f
```

#### B. Check Redis Stream Queue Length
```bash
docker exec -it lsmp-redis redis-cli -a <REDIS_PASSWORD> XLEN wazuh_stream
```

#### C. Manual Ingestion Webhook Test
```bash
curl -X POST http://<SERVER_B_IP>:8080/ingest \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Ingest-Token: <TOKEN>" \
  -d '{"timestamp":"2026-07-20T12:00:00.000+0700","rule":{"level":5,"id":"5501"},"agent":{"id":"001","ip":"10.0.0.5"},"location":"/var/log/auth.log","full_log":"test log entry","data":{"srcip":"10.0.0.99","dstuser":"root"}}'
```

---

## 🛑 Teardown & Maintenance

To stop services on Server A:
```bash
cd wazuh_server/
docker compose down
```

To stop services on Server B (preserves database data but stops queue):
```bash
cd database_server/
docker compose down
```

To fully stop, destroy containers, and wipe local Docker configurations/caching volumes:
```bash
cd database_server/
docker compose down -v
```
