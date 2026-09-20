# LSMP Agent Stack — Fluent-Bit Log Shipping Infrastructure

This directory contains the **Fluent-Bit log collection and forwarding infrastructure** for the LSMP (Log Security Monitoring Platform) project. It handles shipping security logs from monitored hosts and the Wazuh SIEM to the central database for AI-driven anomaly detection.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/
└── fluent-bit/
    ├── client/                      # Client agent (deployed on monitored hosts)
    │   ├── docker-compose.yml       # Fluent-Bit client container
    │   ├── .env.example             # Environment template
    │   ├── generate_keys.sh         # TLS cert generator for Loki
    │   └── config/
    │       ├── fluent-bit.conf      # Tails /var/log/auth.log → Loki
    │       └── parsers.conf         # Log parsers
    │
    ├── server/
    │   ├── wazuh_server/            # Wazuh Server shipper (deployed on Server A)
    │   │   ├── docker-compose.yml   # Fluent-Bit container for Wazuh alerts
    │   │   ├── .env.example         # Environment template
    │   │   └── config/
    │   │       ├── fluent-bit.conf  # Tails Wazuh alerts → HTTP Ingest
    │   │       └── parsers.conf     # JSON parser for Wazuh alerts
    │   │
    │   └── database_server/         # Database Server ingest (deployed on Server B)
    │       ├── docker-compose.yml   # Redis + Ingest Receiver + DB Writer
    │       ├── .env.example         # Environment template
    │       ├── generate_keys.sh     # TLS cert + token generator
    │       ├── Dockerfile           # DB Writer image
    │       ├── Dockerfile.ingest    # Ingest Receiver image
    │       ├── ingest_receiver.py   # HTTP endpoint → Redis Stream
    │       └── wazuh_db_writer.py   # Redis Stream → PostgreSQL batch insert
    │
    └── default.bak/                 # Backup of default Fluent-Bit configs
```

---

## 🏛 Architecture

```
┌─────────────────┐    ┌─────────────────────┐    ┌──────────────────────────┐
│  Monitored Host  │    │  Wazuh Server (A)    │    │  Database Server (B)     │
│                  │    │                      │    │                          │
│  Fluent-Bit      │    │  Fluent-Bit          │    │  ┌─────────────────┐     │
│  (client)        │    │  (wazuh_server)      │    │  │ Ingest Receiver │     │
│                  │    │                      │    │  │ (HTTPS:8080)    │     │
│  /var/log ──────►│──► Loki (Grafana Stack)   │    │  └────────┬────────┘     │
│                  │    │                      │    │           │              │
│                  │    │  /var/ossec/logs ────►│──► │  ┌────────▼────────┐     │
│                  │    │  alerts.json     HTTP │    │  │ Redis Stream    │     │
│                  │    │                      │    │  └────────┬────────┘     │
│                  │    │                      │    │           │              │
│                  │    │                      │    │  ┌────────▼────────┐     │
│                  │    │                      │    │  │ DB Writer       │     │
│                  │    │                      │    │  │ → PostgreSQL    │     │
│                  │    │                      │    │  └─────────────────┘     │
└─────────────────┘    └─────────────────────┘    └──────────────────────────┘
```

| Component | Purpose | Protocol |
|---|---|---|
| **Client Fluent-Bit** | Monitors host auth/web logs, ships to Grafana Loki | HTTPS to Loki |
| **Wazuh Server Fluent-Bit** | Tails Wazuh alert logs, ships to Ingest Receiver | HTTPS with token auth |
| **Ingest Receiver** | Receives alerts via HTTP, buffers in Redis Stream | TLS + token auth |
| **DB Writer** | Consumes Redis Stream, batch inserts into PostgreSQL | Internal |

---

## 🔧 What Was Changed in This Branch (`agent_stack_fix`)

| Finding ID | File | Problem | Fix | Commit |
|---|---|---|---|---|
| AGENT-01 | `wazuh_server/config/fluent-bit.conf` | Config was copy-paste of client (tailing auth.log, outputting to Loki) | Rewrote to tail Wazuh alerts and forward via HTTP to Ingest Receiver | `fix(agent_stack): rewrite wazuh server fluent-bit config` |
| AGENT-02 | `database_server/generate_keys.sh` | TLS cert SANs hardcoded to localhost only | Added `--domain`/`--extra-ip` CLI flags for dynamic SANs | `feat(agent_stack): add dynamic SAN support to TLS cert generation` |
| AGENT-03 | `database_server/docker-compose.yml` | Redis password visible in `docker top` via `-a` flag | Use `REDISCLI_AUTH` env var in healthcheck | `fix(agent_stack): hide redis password from healthcheck` |
| AGENT-04 | `wazuh_server/docker-compose.yml`, `client/docker-compose.yml` | Containers running as `root` | Replaced with `DAC_READ_SEARCH` Linux capability | `fix(agent_stack): replace root user with DAC_READ_SEARCH` |
| AGENT-05 | `database_server/ingest_receiver.py` | Token comparison used `!=` (timing attack risk) | Use `hmac.compare_digest()` for constant-time comparison | `fix(agent_stack): use constant-time comparison for ingest token` |

---

## 🚀 Step-by-Step Deployment Guide

### Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- At least 2 servers: **Server A** (Wazuh Manager) and **Server B** (Database + AI)
- The `database_stack` and `wazuh_stack` must be deployed first

### Step 1: Create the shared Docker network

```bash
docker network create lsmp_backend
```

**Expected result:** A network ID hash is printed. If the network already exists, you'll see an error — that's fine.

---

### Step 2: Deploy Database Stack (Server B) — see `database_stack/README.md`

```bash
cd infrastructure/database_stack
cp .env.example .env
# Edit .env with strong credentials
docker compose up -d
```

**Expected result:** Container `lsmp-postgres` starts and shows `Up (healthy)`.

**Verify:**
```bash
docker compose ps
```
**Expected output:**
```
NAME            SERVICE        STATUS          PORTS
lsmp-postgres   lsmp-postgres   Up (healthy)   0.0.0.0:5432->5432/tcp
```

---

### Step 3: Generate TLS Certificates and Tokens (Server B)

```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
bash generate_keys.sh --domain ingest.your-domain.com --extra-ip <SERVER_B_IP>
```

**Expected result:**
```
=================================================================
🔒  LSMP SECURITY: GENERATING DATABASE SERVER KEYS & CERTIFICATES
=================================================================
🔑 Generating secure random INGEST_TOKEN...
🔑 Generating secure random REDIS_PASSWORD...
📜 Generating Root CA Private Key and Certificate (ca.crt)...
🔐 Generating LSMP Ingest Server Private Key (lsmp_ingest.key)...
🛡️ Signing Server Certificate (lsmp_ingest.crt) with Root CA...
⚙️  Updating environment file (.env)...
=================================================================
✅ DATABASE SERVER SECURITY KEYS SUCCESSFULLY CONFIGURED!
-----------------------------------------------------------------
📍 Certs Directory : .../certs
📄 Server Cert     : .../certs/lsmp_ingest.crt
🔑 Server Key      : .../certs/lsmp_ingest.key
📜 Root CA Cert    : .../certs/ca.crt
🔑 Configured Token: <64-char-hex-token>
=================================================================
```

**Verify TLS cert has your custom SANs:**
```bash
openssl x509 -in certs/lsmp_ingest.crt -text -noout | grep -A5 "Subject Alternative Name"
```
**Expected output includes:**
```
X509v3 Subject Alternative Name:
    DNS:localhost, DNS:lsmp-ingest, DNS:ingest.your-domain.com, IP:127.0.0.1, IP:0.0.0.0, IP:<SERVER_B_IP>
```

---

### Step 4: Start the Database Server Stack (Server B)

```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
docker compose up -d
```

**Expected result:** Three containers start: `lsmp-redis`, `lsmp-ingest`, `lsmp-db-writer`.

**Verify:**
```bash
docker compose ps
```
**Expected output:**
```
NAME            SERVICE        STATUS          PORTS
lsmp-redis      lsmp-redis     Up (healthy)   
lsmp-ingest     lsmp-ingest    Up             0.0.0.0:8080->8080/tcp
lsmp-db-writer  lsmp-db-writer Up             
```

**Verify Redis password is NOT visible:**
```bash
docker top lsmp-redis
```
**Expected:** The CMD column should NOT show a `-a <password>` argument.

---

### Step 5: Copy CA certificate and token to Server A

```bash
# On Server B, copy ca.crt to Server A:
scp certs/ca.crt user@server-a:infrastructure/agent_stack/fluent-bit/server/wazuh_server/certs/

# Note the INGEST_TOKEN from .env:
grep INGEST_TOKEN .env
```

---

### Step 6: Configure and Deploy Wazuh Server Fluent-Bit (Server A)

```bash
cd infrastructure/agent_stack/fluent-bit/server/wazuh_server
cp .env.example .env
# Edit .env — set INGEST_HOST, INGEST_PORT, and INGEST_TOKEN
docker compose up -d
```

**Expected result:** Container `lsmp-fluent-bit` starts and connects to the Ingest Receiver on Server B.

**Verify:**
```bash
docker logs lsmp-fluent-bit --tail 20
```
**Expected output includes:**
```
[2026/09/20 ...] [ info] [input:tail:tail.0] inotify_fs_add(): inode=... watch_fd=... /var/ossec/logs/alerts/alerts.json
[2026/09/20 ...] [ info] [output:http:http.0] <INGEST_HOST>:8080, ...
```

---

### Step 7: Deploy Client Fluent-Bit (Monitored Hosts)

```bash
cd infrastructure/agent_stack/fluent-bit/client
cp .env.example .env
# Edit .env — set LOKI_HOST, LOKI_PORT, CLIENT_HOSTNAME
docker compose up -d
```

**Expected result:** Container `lsmp-client-fluent-bit` starts monitoring `/var/log/auth.log`.

**Verify:**
```bash
docker logs lsmp-client-fluent-bit --tail 10
```
**Expected output includes:**
```
[2026/09/20 ...] [ info] [input:tail:tail.0] inotify_fs_add(): ... /var/log/auth.log
```

---

## ⚠️ Impact and Risks

| Change | Impact | Risk |
|---|---|---|
| AGENT-01: New Fluent-Bit config | Wazuh alerts now flow to ingest pipeline | Must verify end-to-end after deployment |
| AGENT-02: Dynamic SANs | TLS certs can now include external IPs | Existing certs must be regenerated with `--force` |
| AGENT-03: Redis healthcheck | No functional change — password is just hidden | None |
| AGENT-04: No more root | Fluent-Bit runs with limited capabilities | If log files have restrictive permissions, Fluent-Bit may fail to read them. Check with `docker logs` |
| AGENT-05: Constant-time token comparison | No functional change | None |

---

## 📋 Known Issues / Not Fixed

No findings were rejected. All 5 findings were implemented.
