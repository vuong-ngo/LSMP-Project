# LSMP Agent Stack — Fluent-Bit & Security Ingestion Infrastructure

This directory contains the **Fluent-Bit log collection, forwarding, and security alert ingestion infrastructure** for the **LSMP** (Log-based Security Monitoring Platform) project. It coordinates secure, decoupled log pipelines across monitored hosts, the Wazuh SIEM manager, and the central database/AI analytical platform.

---

## 🏛 System Architecture & Agent Roles

The architecture implements a clear separation of concerns between raw log retention and deep security analysis by deploying **two complementary agents** on each monitored host:

```text
┌────────────────────────────────────────────────────────┐
│               MONITORED HOSTS (Endpoints)              │
│                                                        │
│   ┌───────────────────────────┐                        │
│   │    Fluent-Bit Client      │                        │
│   │ (Tails auth.log & nginx)  │───────┐ (HTTPS TLS)    │
│   └───────────────────────────┘       │                │
│                                       │                │
│   ┌───────────────────────────┐       │                │
│   │       Wazuh Agent         │       │                │
│   │ (Logs + FIM + Sys + SCA)  │───┐   │                │
│   └───────────────────────────┘   │   │                │
└───────────────────────────────────┼───┼────────────────┘
                                    │   │
                     (Wazuh Port 1514)  │
                                    │   │
                                    v   │
┌───────────────────────────────────────┼────────────────┐
│         SERVER A (Wazuh SIEM)         │                │
│                                       │                │
│   ┌───────────────────────────────┐   │                │
│   │ Wazuh Manager (wazuh_stack)   │   │                │
│   │ • SIEM Rules & Decoders       │   │                │
│   │ • Severity Scoring (0-16)     │   │                │
│   │ • Output: alerts.json         │   │                │
│   └───────────────┬───────────────┘   │                │
│                   │ alerts.json       │                │
│                   v                   │                │
│   ┌───────────────────────────────┐   │                │
│   │  Fluent-Bit (wazuh_server)    │───┼────────────┐   │
│   │ (Tails enriched alerts)       │   │            │   │
│   └───────────────────────────────┘   │            │   │
└───────────────────────────────────────┼────────────┼───┘
                                        │            │ (HTTPS :8080 + Token)
                                        v            v
┌────────────────────────────────────────────────────────┐
│      SERVER B (Database, AI & Observability Layer)     │
│                                                        │
│   ┌───────────────────────────────┐                    │
│   │  Loki Gateway (Nginx :3100)   │                    │
│   │  ➔ Loki Write ➔ SeaweedFS S3  │ ➔ Grafana (:3000)  │
│   │  (Centralized Raw Log Search) │                    │
│   └───────────────────────────────┘                    │
│                                                        │
│   ┌────────────────────────────────────────────────┐   │
│   │  lsmp-ingest (Ingest Receiver HTTPS :8080)     │   │
│   │  • Validates Token (hmac.compare_digest)       │   │
│   │  • Buffers alerts into Redis Stream (XADD)     │   │
│   └───────────────────────┬────────────────────────┘   │
│                           │                            │
│                           v                            │
│   ┌────────────────────────────────────────────────┐   │
│   │  lsmp-redis (Redis Stream: wazuh_stream)       │   │
│   │  (Decoupling queue, absorbs alert bursts)      │   │
│   └───────────────────────┬────────────────────────┘   │
│                           │ Batch (500 items/batch)    │
│                           v                            │
│   ┌────────────────────────────────────────────────┐   │
│   │  lsmp-db-writer (Python Worker)                │   │
│   │  ➔ Bulk INSERT into PostgreSQL (database_stack)│   │
│   │  (Structured storage for AI Anomaly Detection) │   │
│   └────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
```

### 🔍 Distinct Roles of the Two Endpoint Agents

| Evaluation Criteria | 1. Fluent-Bit Client Agent | 2. Wazuh Security Agent |
|---|---|---|
| **Collected Data** | **Raw System & Service Logs:**<br>• `/var/log/auth.log` (SSH/sudo authentication)<br>• `/var/log/nginx/access.log` (HTTP web requests) | **Raw Logs + Deep Security Telemetry:**<br>• System logs (`auth.log`, `access.log`)<br>• **FIM (File Integrity Monitoring):** Real-time tracking of sensitive file modifications<br>• **Syscollector:** Hardware inventory, active processes, open listening ports, installed packages<br>• **SCA (Security Configuration Assessment):** Misconfiguration and CIS benchmark audit checks<br>• **Rootcheck / Malware Detection:** Hidden rootkits and trojan signatures |
| **Destination** | **Grafana Loki** on Server B via Nginx Gateway (`port 3100` over TLS) | **Wazuh Manager** on Server A via proprietary encrypted protocol (`port 1514`) |
| **Core Objective** | **Centralized Raw Log Retention & Search:**<br>Provides SOC analysts with full log history for forensic investigation and ad-hoc LogQL queries in Grafana Explore. | **Deep SIEM Rule-Based Analysis:**<br>Decodes, correlates, and maps events against security rules, computing threat **Severity scores (levels 0–16)**. |

---

## 📂 Directory Structure & Component Roles

```text
infrastructure/agent_stack/
├── README.md                                  # Stack documentation and operational runbook
└── fluent-bit/
    ├── client/                                # [DEPLOYED ON MONITORED HOSTS]
    │   ├── docker-compose.yml                 # Fluent-Bit client container definition
    │   ├── .env.example                       # Environment template (Loki host, port, hostname)
    │   ├── generate_keys.sh                   # Helper script to fetch/verify Loki Gateway Root CA
    │   ├── certs/ca.crt                       # Trusted Root CA certificate for Loki Gateway
    │   └── config/
    │       ├── fluent-bit.conf                # Ingests /var/log/auth.log & nginx -> forwards to Loki
    │       └── parsers.conf                   # Regex parsers for syslog and standard Nginx log formats
    │
    └── server/
        ├── wazuh_server/                      # [DEPLOYED ON SERVER A - WAZUH SIEM]
        │   ├── docker-compose.yml             # Fluent-Bit shipper for analyzed Wazuh alerts
        │   ├── .env.example                   # Connection template (Ingest token, host, port)
        │   ├── generate_keys.sh               # Helper script to sync CA certificate from Server B
        │   ├── certs/ca.crt                   # Root CA cert verifying Server B's Ingest Receiver
        │   └── config/
        │       ├── fluent-bit.conf            # Tails /var/ossec/logs/alerts/alerts.json -> HTTPS POST
        │       └── parsers.conf               # JSON parser for enriched Wazuh alert records
        │
        └── database_server/                   # [DEPLOYED ON SERVER B - DATABASE & AI LAYER]
            ├── docker-compose.yml             # Ingestion trio: Ingest Receiver + Redis Buffer + DB Writer
            ├── .env.example                   # Configuration template (Redis password, Ingest token, DB URL)
            ├── generate_keys.sh               # Generates TLS certificates (SAN IP/DNS) and random secure tokens
            ├── Dockerfile.ingest              # Container image for Ingest Receiver (Python Fast HTTP API)
            ├── Dockerfile                     # Container image for DB Writer (Python psycopg2 Worker)
            ├── ingest_receiver.py             # HTTP endpoint: Validates Bearer token & XADDs into Redis Stream
            ├── wazuh_db_writer.py             # Consumer worker: Batch reads Redis Stream (500 items) -> Postgres
            └── certs/                         # Server certificate and private key storage
```

---

## 🌐 Services, Port Matrix & Security Policies

| Service Name | Host Machine | Exposed Port | Internal Port | Security & Capability Policies |
|---|---|---|---|---|
| **lsmp-client-fluent-bit** | Monitored Hosts | *None* | *None* | Runs non-root with Linux capability `DAC_READ_SEARCH` (read-only file access); ships via TLS to Loki |
| **lsmp-fluent-bit** (wazuh) | Server A | *None* | *None* | Runs non-root (`DAC_READ_SEARCH`); authenticates via `X-Ingest-Token` header over HTTPS |
| **lsmp-ingest** | Server B | `8080` | `8080` | External ingestion port for Server A; TLS-encrypted; constant-time token comparison via `hmac.compare_digest()` |
| **lsmp-redis** | Server B | *None* | `6379` | Internal to Docker network `lsmp_backend`; mandatory password authentication via `--requirepass` |
| **lsmp-db-writer** | Server B | *None* | *None* | Internal worker container; communicates with Redis and PostgreSQL over private bridge network |

---

## 🚀 Step-by-Step Deployment Guide (7 Critical Steps)

Because components depend on services initialized in preceding stages, **you must execute the deployment in this exact sequence**:

```text
Step 1: Create shared Docker network: docker network create lsmp_backend (Server B)
          │
Step 2: Deploy database_stack (Server B): PostgreSQL database must be healthy
          │
Step 3: Deploy grafana_stack (Server B): Loki Gateway & SeaweedFS must be listening
          │
Step 4: Deploy wazuh_stack (Server A): Wazuh Manager starts & provisions wazuh_logs volume
          │
Step 5: Deploy database_server (Server B): Generate TLS keys, start Ingest Receiver, Redis & DB Writer
          │
Step 6: Deploy wazuh_server shipper (Server A): Sync CA cert & Token -> Forward alerts to Server B
          │
Step 7: Deploy client shipper (Monitored Hosts): Sync Loki CA cert -> Forward raw auth logs to Loki
```

---

### Step 1: Create Shared Docker Network (Execute on Server B)
Create the external bridge network enabling cross-stack communication:

```bash
docker network create lsmp_backend
```
*Expected output:* Returns the newly created network ID hash (or reports `network already exists`, which is safe to ignore).

---

### Step 2: Deploy PostgreSQL Database Stack (Execute on Server B)
PostgreSQL must be running before the Database Writer starts:

```bash
cd infrastructure/database_stack
cp .env.example .env
# Edit .env to set POSTGRES_USER and POSTGRES_PASSWORD
docker compose up -d
```
*Verification:*
```bash
docker compose ps
```
*Expected status:* `lsmp-postgres` displays `Up (healthy)`.

---

### Step 3: Deploy Grafana & Loki Stack (Execute on Server B)
Loki Gateway (port `3100`) and SeaweedFS must be active before client log forwarders connect:

```bash
cd infrastructure/grafana_stack
cp .env.example .env
# Edit .env to configure AWS_ACCESS_KEY_ID=loki and AWS_SECRET_ACCESS_KEY
docker compose up -d
```
*Verification:*
```bash
docker compose ps
curl -s http://localhost:3100
```
*Expected status:* Containers report `Up (healthy)` and curl responds with `OK`.

---

### Step 4: Deploy Wazuh SIEM Manager (Execute on Server A)
Wazuh Manager initializes rule evaluation and provisions the shared log volume:

```bash
# On Server A:
sudo sysctl -w vm.max_map_count=262144
cd infrastructure/wazuh_stack
cp .env.example .env
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
*Verification:*
```bash
docker volume inspect wazuh_logs
```
*Expected output:* Confirms volume metadata with `"Name": "wazuh_logs"`.

---

### Step 5: Provision TLS Keys & Deploy Ingestion Stack (Execute on Server B)

#### 5a. Generate TLS Certificates and Authentication Token:
```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
bash generate_keys.sh --domain <SERVER_B_IP_OR_DOMAIN> --extra-ip <SERVER_B_IP>
```
*Expected output:* Generates `certs/ca.crt`, `certs/lsmp_ingest.crt`, private keys, and writes an automatically generated `INGEST_TOKEN` to `.env`.

#### 5b. Retrieve Generated Credentials (Required for Step 6):
```bash
echo "INGEST_TOKEN: $(grep '^INGEST_TOKEN=' .env | cut -d= -f2)"
```

#### 5c. Start Ingestion Containers:
```bash
docker compose up -d --build
docker compose ps
```
*Expected status:*
```text
NAME             SERVICE          STATUS          PORTS
lsmp-redis       lsmp-redis       Up (healthy)
lsmp-ingest      lsmp-ingest      Up              0.0.0.0:8080->8080/tcp
lsmp-db-writer   lsmp-db-writer   Up
```

---

### Step 6: Deploy Wazuh Server Fluent-Bit Shipper (Execute on Server A)

#### 6a. Copy Root CA Certificate from Server B to Server A:
```bash
# Run on Server B (or manually copy ca.crt):
scp infrastructure/agent_stack/fluent-bit/server/database_server/certs/ca.crt \
    user@<SERVER_A_IP>:infrastructure/agent_stack/fluent-bit/server/wazuh_server/certs/ca.crt
```

#### 6b. Configure Environment Variables:
```bash
cd infrastructure/agent_stack/fluent-bit/server/wazuh_server
cp .env.example .env
```
Edit `.env` using values obtained from Step 5:
```dotenv
INGEST_HOST=<SERVER_B_IP>
INGEST_PORT=8080
INGEST_TOKEN=<TOKEN_RETRIEVED_IN_STEP_5B>
ENABLE_TLS=On
TLS_VERIFY=On
```

#### 6c. Launch Alert Forwarder:
```bash
docker compose up -d
docker logs lsmp-fluent-bit --tail 20
```
*Expected output:* Confirms `inotify_fs_add()` successfully monitoring `/var/ossec/logs/alerts/alerts.json`.

---

### Step 7: Deploy Client Fluent-Bit (Execute on Each Monitored Host)

#### 7a. Transfer Loki Gateway CA Certificate:
```bash
# On monitored client host:
mkdir -p infrastructure/agent_stack/fluent-bit/client/certs/
scp user@<SERVER_B_IP>:infrastructure/grafana_stack/certs/ca.crt \
    infrastructure/agent_stack/fluent-bit/client/certs/ca.crt
```

#### 7b. Configure Client Environment:
```bash
cd infrastructure/agent_stack/fluent-bit/client
cp .env.example .env
```
Edit `.env`:
```dotenv
LOKI_HOST=<SERVER_B_IP>
LOKI_PORT=3100
CLIENT_HOSTNAME=monitored-client-01
ENABLE_TLS=On
TLS_VERIFY=On
```

#### 7c. Launch Client Log Forwarder:
```bash
docker compose up -d
docker logs lsmp-client-fluent-bit --tail 20
```
*Expected output:* Confirms active monitoring of `/var/log/auth.log` and `/var/log/nginx/access.log`.

---

## 🛠️ Daily Operations & Maintenance

### 1. Real-time Pipeline Monitoring
```bash
# Monitor Ingest Receiver requests (Server B):
docker compose logs -f lsmp-ingest

# Monitor Database Writer batch inserts (Server B):
docker compose logs -f lsmp-db-writer

# Monitor Alert Forwarder activity (Server A):
docker compose logs -f lsmp-fluent-bit

# Monitor Client Log Shipper (Monitored Host):
docker compose logs -f lsmp-client-fluent-bit
```

### 2. Redis Stream Queue Inspection
Inspect queue backlog to identify alert bursts or processing bottlenecks:
```bash
# Check current message count in stream queue:
docker exec -it lsmp-redis redis-cli -a "<REDIS_PASSWORD>" XLEN wazuh_stream

# Inspect consumer group lag:
docker exec -it lsmp-redis redis-cli -a "<REDIS_PASSWORD>" XINFO GROUPS wazuh_stream
```

### 3. Service Restarts After Configuration Changes
When updating parsing rules or certificate files:
```bash
docker compose restart lsmp-ingest lsmp-db-writer
```

### 4. Safe Shutdown (Preserving Queued Data)
```bash
docker compose down
```
> [!NOTE]
> Stopping containers preserves uncommitted stream items in the `redis_data` volume and file read offsets in `fluent_bit_db`.
