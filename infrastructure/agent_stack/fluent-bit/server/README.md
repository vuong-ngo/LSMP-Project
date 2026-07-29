# LSMP Fluent-bit Ingestion Pipeline

This directory contains the server-side log ingestion infrastructure responsible for collecting Wazuh Manager security alerts and streaming them into the LSMP PostgreSQL database. It is designed for a **2-server deployment model** where the Wazuh Manager (Server A) and the Database & AI engine (Server B) run on separate physical machines.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/server/
├── wazuh_server/                   # Deployed on Server A (Wazuh Manager host)
│   ├── docker-compose.yml          # Fluent-bit service definition
│   ├── .env.example                # Environment variables template
│   ├── generate_keys.sh            # Standalone Key & CA cert sync script for Server A
│   ├── certs/                      # TLS Root CA certificate directory
│   │   └── ca.crt                  # Root CA Certificate (verifies Server B)
│   └── config/
│       ├── fluent-bit.conf         # Fluent-bit INPUT/OUTPUT TLS configuration
│       └── parsers.conf            # JSON parser for Wazuh alerts
│
└── database_server/                # Deployed on Server B (Database & AI host)
    ├── docker-compose.yml          # Redis, Ingest Receiver & DB Writer services
    ├── .env.example                # Environment variables template
    ├── generate_keys.sh            # Standalone TLS cert & token generator for Server B
    ├── Dockerfile                  # Image for lsmp-db-writer (Python + SQLAlchemy)
    ├── Dockerfile.ingest           # Image for lsmp-ingest (Python + TLS + Redis)
    ├── ingest_receiver.py          # HTTPS endpoint → Redis Stream (XADD)
    ├── wazuh_db_writer.py          # Redis Stream consumer → PostgreSQL batch INSERT
    └── certs/                      # TLS Certificates & Keys directory
        ├── ca.crt                  # Root CA Certificate
        ├── ca.key                  # Root CA Private Key
        ├── lsmp_ingest.crt         # Server SSL/TLS Certificate
        └── lsmp_ingest.key         # Server SSL/TLS Private Key
```

---

## 🏛 Component Architecture

The log ingestion pipeline operates across two physical hosts:

| Component | Container Name | Host | Default Ports | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Fluent-bit Shipper** | `lsmp-fluent-bit` | Server A | None | Tails Wazuh manager logs and forwards alerts as JSON lines over encrypted HTTPS. |
| **Ingest Receiver** | `lsmp-ingest` | Server B | `8080/tcp` (Exposed) | A secure HTTPS endpoint `/ingest` that validates tokens, limits payload size, and writes to Redis. |
| **Redis Queue** | `lsmp-redis` | Server B | `6379/tcp` (Internal) | Capped, secure in-memory Stream queue (`wazuh_stream`) acting as a buffer. |
| **Database Writer** | `lsmp-db-writer` | Server B | None | Consumes logs from Redis and performs batch INSERTs into PostgreSQL. |

---

## 🔒 Security Architecture

### 1. Transport-Layer Encryption (TLS / HTTPS)
* Traffic between Server A (Wazuh) and Server B (Database) is encrypted using **TLS 1.2/1.3 (HTTPS)**.
* Server B presents an SSL/TLS certificate (`lsmp_ingest.crt`) signed by a dedicated Root CA (`ca.crt`).
* Fluent-Bit on Server A verifies Server B's identity against `ca.crt` (`tls.verify On`), preventing Man-in-the-Middle (MITM) attacks.

### 2. Token-Based HTTP Authentication
* **Fluent-bit** (Server A) sends a 64-character pre-shared secret token in the `X-Ingest-Token` HTTP header with every request.
* **Ingest Receiver** (Server B) validates the token. Unauthenticated requests receive `HTTP 401 Unauthorized`.
* The `INGEST_TOKEN` environment variable **must be identical** in both `wazuh_server/.env` and `database_server/.env`.

### 3. Denial of Service (DoS) & Memory Protection
* The `lsmp-ingest` receiver enforces a maximum request body size limit (`MAX_BODY_SIZE=10MB`). Requests exceeding the threshold are immediately rejected with `HTTP 413 Payload Too Large`, protecting against memory exhaustion attacks.

### 4. Network Isolation
* Redis (`6379`) is not exposed to the public host network; it is accessible only internally via the `lsmp_backend` bridge network.
* PostgreSQL is restricted to loopback/internal bridge connections.

---

## 🚀 Step-by-Step Deployment Guide

### 1. Standalone Key & Certificate Provisioning

#### On Server B (Database & AI Server):
```bash
cd database_server/
bash generate_keys.sh
```
This generates high-entropy `INGEST_TOKEN`, `REDIS_PASSWORD`, TLS Certificates (`lsmp_ingest.crt`/`.key`), and configures `.env`.

#### On Server A (Wazuh Manager Server):
Copy `ca.crt` to `wazuh_server/certs/ca.crt` and execute:
```bash
cd wazuh_server/
bash generate_keys.sh --token <TOKEN_FROM_SERVER_B>
```

---

### 2. Start the Ingestion Pipeline

#### A. Start Ingestion services (Server B)
Ensure your `database_stack` PostgreSQL container is running and healthy. Then run:
```bash
cd database_server/
docker compose up -d --build
```
> Verify HTTPS status: `docker logs lsmp-ingest`  
> Expected line: `LSMP Ingest Receiver listening securely (HTTPS/TLS) at https://0.0.0.0:8080/ingest`

#### B. Start Log Forwarding agent (Server A)
Once Server B is listening securely on port `8080`, start the Fluent-bit shipper:
```bash
cd wazuh_server/
docker compose up -d --build
```

---

### 3. Verification & Testing

#### A. Check Ingest Receiver Logs
```bash
docker logs lsmp-ingest -f
```

#### B. Check Redis Stream Queue Length
```bash
docker exec -it lsmp-redis redis-cli -a <REDIS_PASSWORD> XLEN wazuh_stream
```

#### C. Manual Ingestion HTTPS Webhook Test
```bash
curl -X POST https://<SERVER_B_IP>:8080/ingest \
  --cacert database_server/certs/ca.crt \
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
