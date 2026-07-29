# LSMP Security Agent & Log Ingestion Stack

This directory contains the complete end-to-end log shipping, security monitoring, and ingestion stack for the **Lightweight Security Monitoring Platform (LSMP)**. It provides components for both monitored SME endpoint machines and central SIEM/Database servers.

---

## 📂 Architecture & Directory Structure

```text
infrastructure/agent_stack/
├── fluent-bit/                     # High-performance log forwarder & ingest stack
│   ├── server/                     # Server-side ingestion components
│   │   ├── wazuh_server/           # Deployed on Server A (Wazuh SIEM Manager host)
│   │   │   ├── docker-compose.yml  # Fluent-bit alert shipper service
│   │   │   ├── generate_keys.sh    # Standalone script to sync Root CA & INGEST_TOKEN
│   │   │   └── certs/              # Root CA certificate storage
│   │   │
│   │   └── database_server/        # Deployed on Server B (Database & AI Engine host)
│   │       ├── docker-compose.yml  # Ingest Receiver (HTTPS), Redis & DB Writer
│   │       ├── generate_keys.sh    # Standalone TLS cert & token generator
│   │       ├── ingest_receiver.py  # Python HTTPS Ingest endpoint (DoS & Token protected)
│   │       ├── wazuh_db_writer.py  # Redis Stream -> PostgreSQL batch writer
│   │       └── certs/              # Server SSL certificates & private keys
│   │
│   └── client/                     # Deployed on Monitored Endpoint Hosts (Client Nodes)
│       ├── docker-compose.yml      # Fluent-bit client agent service
│       ├── generate_keys.sh        # Standalone client TLS configuration script
│       └── certs/                  # Root CA certificate storage
│
└── wazuh-agent/                    # Deployed on Monitored Endpoint Hosts
    ├── docker-compose.yml          # Wazuh host monitoring agent container
    ├── .env.example                # Endpoint registration configuration template
    └── config/                     # OSSEC XML agent configuration
```

---

## 🏛 End-to-End Component Matrix

| Sub-system | Location | Target Machine | Core Function | Security Protocols |
| :--- | :--- | :--- | :--- | :--- |
| **Ingest Receiver** | `fluent-bit/server/database_server` | Server B (Database/AI) | Receives raw alerts over HTTPS, validates tokens, queues into Redis. | **TLS 1.2/1.3 (HTTPS)**<br>`X-Ingest-Token`<br>Max Body Size limit (10MB) |
| **Database Writer** | `fluent-bit/server/database_server` | Server B (Database/AI) | Batch consumes logs from Redis and performs parameterized SQL inserts into TimescaleDB. | Parameterized SQL<br>Internal Docker Network<br>Row-by-Row Fallback |
| **Alert Shipper** | `fluent-bit/server/wazuh_server` | Server A (Wazuh Host) | Tails Wazuh manager `alerts.json` and forwards records to Server B. | **TLS Verification (`ca.crt`)**<br>Pre-Shared Token Header |
| **Client Agent** | `fluent-bit/client` | Monitored Endpoints | Collects host logs (`/var/log/auth.log`, Nginx) and forwards to Loki & Wazuh. | **TLS Encryption (`ca.crt`)**<br>HTTP Basic Auth<br>Read-Only `/var/log` Mount |
| **Wazuh Agent** | `wazuh-agent` | Monitored Endpoints | Host security monitoring, File Integrity Monitoring (FIM), and SCA. | **AES Encryption (Port 1514)**<br>`authd` Enrolment Verification |

---

## 🔒 Multi-Layer Security Architecture

### 1. Transport Encryption (TLS / HTTPS)
- All log transport channels between endpoint agents, Wazuh manager, and the Database ingestion server are strictly encrypted over **TLS 1.2/1.3 (HTTPS)**.
- Central endpoints use server certificates (`lsmp_ingest.crt`) signed by a dedicated Root CA (`ca.crt`).

### 2. Header Token Authentication (`INGEST_TOKEN`)
- Ingest endpoints enforce strict authentication via a 64-character hex pre-shared secret token (`INGEST_TOKEN`) passed in the `X-Ingest-Token` HTTP header.

### 3. Denial of Service & Memory Protection
- The Ingest Receiver service enforces a hard upper bound on HTTP POST body payloads (`MAX_BODY_SIZE=10MB`), dropping oversized requests (`HTTP 413`) to prevent memory exhaustion attacks.

### 4. Database Injection Immunity
- All database writes strictly utilize **SQLAlchemy parameterized queries**, immunizing the database layer against SQL Injection threats.

---

## 🚀 Step-by-Step Distributed Deployment Guide

### Step 1: Initialize Database Server (Server B)
On Server B:
```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
bash generate_keys.sh
docker compose up -d --build
```

### Step 2: Configure SIEM Manager Forwarder (Server A)
On Server A:
```bash
cd infrastructure/agent_stack/fluent-bit/server/wazuh_server
bash generate_keys.sh --token <TOKEN_FROM_SERVER_B>
docker compose up -d --build
```

### Step 3: Deploy Endpoint Client Agents
On monitored SME endpoint hosts:
```bash
cd infrastructure/agent_stack/fluent-bit/client
bash generate_keys.sh
docker compose up -d --build
```
