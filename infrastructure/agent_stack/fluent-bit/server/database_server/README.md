# LSMP Ingestion Server & Database Writer

This directory contains the services deployed on **Server B** (Database & AI Server) that receive security alert logs securely via HTTPS from Fluent-bit (on Server A), buffer them in a Redis stream queue, and write them in optimized batches to the TimescaleDB/PostgreSQL database.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/server/database_server/
├── docker-compose.yml       # Docker Compose service definition for Server B
├── .env.example             # Environment configurations template
├── generate_keys.sh         # Standalone script to generate TLS certs & INGEST_TOKEN
├── Dockerfile               # Production Dockerfile for the db writer
├── Dockerfile.ingest        # Production Dockerfile for the HTTPS ingest receiver
├── ingest_receiver.py       # Python HTTPS server (TLS + Token Auth + DoS Guard) -> Redis
├── wazuh_db_writer.py       # Python script consuming Redis and batch inserting into PostgreSQL
├── requirements.txt         # Pinned Python package dependencies
└── certs/                  # TLS Certificate & Key storage directory
    ├── ca.crt               # Root CA Certificate
    ├── ca.key               # Root CA Private Key
    ├── lsmp_ingest.crt      # Ingest Server SSL Certificate
    └── lsmp_ingest.key      # Ingest Server SSL Private Key
```

---

## 🏛 Component Architecture

The database server stack runs **three core components** that communicate internally over the shared Docker network:

| Component                   | Container Name     | Default Ports           | Description                                                                                                                |
| :-------------------------- | :----------------- | :---------------------- | :------------------------------------------------------------------------------------------------------------------------- |
| **Ingest Receiver**   | `lsmp-ingest`    | `8080/tcp` (Exposed)  | A secure HTTPS endpoint`/ingest` that validates tokens, enforces body size limits, and appends raw log lines into Redis. |
| **Redis Queue Cache** | `lsmp-redis`     | `6379/tcp` (Internal) | A secured, persistent in-memory stream buffer (`wazuh_stream`) acting as a backpressure safety valve.                    |
| **Database Writer**   | `lsmp-db-writer` | None                    | A background daemon consuming events from Redis and performing batch INSERT transactions into the database.                |

---

## 🔒 Security Features & Token Verification

1. **Transport Layer Encryption (TLS/HTTPS)**:
   - Configured via `USE_TLS=true`, `SSL_CERT_FILE=/etc/ssl/certs/lsmp_ingest.crt`, and `SSL_KEY_FILE=/etc/ssl/certs/lsmp_ingest.key`.
2. **Pre-Shared Token Authorization (`INGEST_TOKEN`)**:
   - High-entropy 64-character hex secret token.
   - Every incoming HTTP request must include the header `X-Ingest-Token: <INGEST_TOKEN>`. Requests missing or presenting an invalid token are rejected immediately with `HTTP 401 Unauthorized`.
3. **DoS & Memory Exhaustion Guard**:
   - `MAX_BODY_SIZE` limit (default: 10 MB) prevents malicious oversized HTTP payloads from consuming server RAM (`HTTP 413 Payload Too Large`).

---

## 🚀 Step-by-Step `INGEST_TOKEN` Generation & Deployment

### 1. Prerequisites

Ensure you have created the shared external bridge network before starting the stack:

```bash
docker network create lsmp_backend
```

---

### 2. Generating `INGEST_TOKEN` & TLS Certificates

Run the standalone key generator script on **Server B** (Database Server):

```bash
bash generate_keys.sh
```

#### **Script CLI Options & Flexibility**

The script supports several flags for customized or non-interactive setups:

```text
Usage: bash generate_keys.sh [OPTIONS]

Options:
  --token, -t <TOKEN>         Specify a custom INGEST_TOKEN (64-char hex recommended)
  --redis-pass, -r <PASS>     Specify a custom REDIS_PASSWORD
  --force, -f                 Force re-generation of TLS certificates and random tokens
  --help, -h                  Show this help message
```

#### **Key Generation Behavior & Safety:**

* **Token & Password Preservation**: If a valid `INGEST_TOKEN` or `REDIS_PASSWORD` already exists in `.env`, the script **retains them by default** so existing connected shippers (like Wazuh Fluent-Bit) are not disconnected.
* **Token Generation**: Generates a secure random 64-character hex `INGEST_TOKEN` (`openssl rand -hex 32`) if none exists.
* **Redis Password**: Generates a secure 24-character random password if none exists.
* **TLS Certificates**: Generates Root CA certificates (`ca.crt`, `ca.key`) and Ingest Server SSL certificates (`lsmp_ingest.crt`, `lsmp_ingest.key`) with SAN IP/DNS configuration. Certificates are preserved unless `--force` / `-f` is passed.
* **Environment File Sync**: Automatically updates `.env` with `INGEST_TOKEN`, `REDIS_PASSWORD`, and `USE_TLS=true`.

**Printed Output Example:**

```text
=================================================================
🔒  LSMP SECURITY: GENERATING DATABASE SERVER KEYS & CERTIFICATES
=================================================================
ℹ️  Retaining existing INGEST_TOKEN from .../database_server/.env
ℹ️  Retaining existing REDIS_PASSWORD from .../database_server/.env
✅ Existing TLS Certificates found in .../database_server/certs. Skipping certificate generation.
   (Use --force or -f to regenerate certificates)
⚙️  Updating environment file (.../database_server/.env)...
=================================================================
✅ DATABASE SERVER SECURITY KEYS SUCCESSFULLY CONFIGURED!
-----------------------------------------------------------------
📍 Certs Directory : .../database_server/certs
📄 Server Cert     : .../database_server/certs/lsmp_ingest.crt
🔑 Server Key      : .../database_server/certs/lsmp_ingest.key
📜 Root CA Cert    : .../database_server/certs/ca.crt
🔑 Configured Token: <TOKEN>
=================================================================
```

> [!TIP]
> **To retrieve the token at any time later:**
> Run: `grep "^INGEST_TOKEN=" .env | cut -d '=' -f2`

---

### 3. Startup & Build

To build the custom Python runner images and start the containers in the background:

```bash
docker compose up -d --build
```

Verify HTTPS listener in the logs:

```bash
docker logs lsmp-ingest
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
