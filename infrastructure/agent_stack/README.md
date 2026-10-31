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

## 🌐 Services, Port Matrix & Networking Policies

| Service Name | Host Machine | Exposed Port | Internal Port | Security & Capability Policies |
|---|---|---|---|---|
| **wazuh-agent** | Monitored Hosts | *None* | *None* | System service; establishes persistent TLS tunnel to Server A (`1514/tcp`) |
| **lsmp-client-fluent-bit** | Monitored Hosts | *None* | *None* | Runs non-root with Linux capability `DAC_READ_SEARCH` (read-only log access); ships via TLS to Loki |
| **wazuh-manager** | Server A | `1514` | `1514` | Listens for incoming agent telemetry and registration |
| **lsmp-fluent-bit** (wazuh) | Server A | *None* | *None* | Tails `wazuh_logs` volume; authenticates via `X-Ingest-Token` header over HTTPS |
| **lsmp-ingest** | Server B | `8080` | `8080` | External ingestion port for Server A; TLS-encrypted; constant-time token comparison via `hmac.compare_digest()` |
| **lsmp-redis** | Server B | *None* | `6379` | Internal to Docker network `lsmp_backend`; mandatory password authentication via `--requirepass` |
| **lsmp-db-writer** | Server B | *None* | *None* | Internal worker container; communicates with Redis and PostgreSQL over private bridge network |

> [!IMPORTANT]
> **Docker Bridge vs. Multi-Host Network Architecture:**
> - The Docker bridge network `lsmp_backend` is **local to Server B**. It isolates Redis, PostgreSQL, and DB Writer from public access.
> - **Server A** and **Monitored Hosts** are physically or virtually separate machines. They **cannot** attach to Server B's `lsmp_backend` Docker bridge. Instead, they communicate over the physical network to Server B's published host ports (`8080` for `lsmp-ingest`, `3100` for `loki-gateway`) secured by TLS and authentication tokens.

---

## 🚀 Step-by-Step Deployment Guide (Multi-Host Production)

To ensure smooth service startup without connection errors, follow this 8-step sequence across Server B, Server A, and your Monitored Hosts:

```text
Server B:  [Step 1: Network] ➔ [Step 2: Database] ➔ [Step 3: Grafana/Loki] ➔ [Step 5: Ingest Stack]
                                                                                      │
Server A:  [Step 4: Wazuh Manager] ──────────────────────────────────────────➔ [Step 6: Alert Shipper]
                                                                                      │
Client:    [Step 7: Wazuh Agent] ➔ [Step 8: Client Fluent-Bit] ───────────────────────┘
```

---

### Step 1: Create Shared Docker Network (Execute on Server B)
Create the external bridge network that connects the database, observability stack, and ingestion receiver on Server B:

```bash
docker network create lsmp_backend
```
*Expected output:* Prints network ID hash (or indicates `network already exists`, which is safe to proceed).

---

### Step 2: Deploy PostgreSQL Database Stack (Execute on Server B)
PostgreSQL stores processed security alerts and must be operational before starting consumers:

```bash
cd infrastructure/database_stack
cp .env.example .env
# Verify POSTGRES_DB=lsmp_db, POSTGRES_USER, and POSTGRES_PASSWORD in .env
docker compose up -d
```
*Verification:*
```bash
docker compose ps
```
*Expected status:* `lsmp-postgres` displays `Up (healthy)`.

---

### Step 3: Deploy Grafana & Loki Stack (Execute on Server B)
Deploy Loki Gateway (port `3100`) and SeaweedFS object storage to receive raw client logs:

```bash
cd infrastructure/grafana_stack
cp .env.example .env
# Verify AWS_ACCESS_KEY_ID=loki and AWS_SECRET_ACCESS_KEY in .env
bash generate_certs.sh
docker compose up -d
```
*Verification:*
```bash
docker compose ps
curl -k -s https://localhost:3100/ready || curl -s http://localhost:3100/ready
```
*Expected status:* Services report `Up (healthy)` and ready endpoint returns `ready`.

---

### Step 4: Deploy Wazuh SIEM Manager (Execute on Server A)
On Server A, start the Wazuh SIEM stack. The manager analyzes logs and writes enriched alerts to the shared Docker volume `wazuh_logs`.

```bash
# Set required virtual memory for OpenSearch/Indexer
sudo sysctl -w vm.max_map_count=262144

cd infrastructure/wazuh_stack
# Generate indexer TLS certificates (required on first run)
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
*Verification:*
```bash
docker compose ps
docker volume inspect wazuh_logs
```
*Expected status:* Wazuh Manager is `Up`, and `wazuh_logs` Docker volume exists.

---

### Step 5: Provision TLS Keys & Deploy Ingestion Stack (Execute on Server B)

#### 5a. Generate Ingestion TLS Certificates and Token:
Run `generate_keys.sh` specifying Server B's external IP or DNS domain name (used by Server A for TLS verification):

```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
bash generate_keys.sh --domain <SERVER_B_IP_OR_DOMAIN> --extra-ip <SERVER_B_IP>
```
*Expected output:* Generates `certs/ca.crt`, `certs/lsmp_ingest.crt`, private keys, and automatically populates `INGEST_TOKEN` in `.env`.

#### 5b. Retrieve Generated Credentials:
Print the generated token (needed for Server A in Step 6):
```bash
echo "INGEST_TOKEN: $(grep '^INGEST_TOKEN=' .env | cut -d= -f2)"
```

#### 5c. Start Ingestion Trio:
```bash
docker compose up -d --build
docker compose ps
```
*Expected status:*
```text
NAME             SERVICE          STATUS          PORTS
lsmp-redis       lsmp-redis       Up (healthy)    6379/tcp
lsmp-ingest      lsmp-ingest      Up              0.0.0.0:8080->8080/tcp
lsmp-db-writer   lsmp-db-writer   Up              
```

---

### Step 6: Deploy Wazuh Server Fluent-Bit Shipper (Execute on Server A)

#### 6a. Network Adjustment for Multi-Host Setup:
Because Server A is a separate machine, its Fluent-Bit container cannot join Server B's `lsmp_backend` Docker bridge.
In `infrastructure/agent_stack/fluent-bit/server/wazuh_server/docker-compose.yml`, remove or comment out the external `networks` block so it uses the host's default bridge:

```yaml
# In docker-compose.yml on Server A:
services:
  lsmp-fluent-bit:
    # ...
    # networks: [lsmp_backend] -> remove or comment out
```

#### 6b. Transfer Root CA Certificate & Configure Keys:
Transfer `ca.crt` generated on Server B in Step 5:
```bash
# On Server A:
mkdir -p infrastructure/agent_stack/fluent-bit/server/wazuh_server/certs/
scp user@<SERVER_B_IP>:infrastructure/agent_stack/fluent-bit/server/database_server/certs/ca.crt \
    infrastructure/agent_stack/fluent-bit/server/wazuh_server/certs/ca.crt
```

Configure connection parameters using the helper script:
```bash
cd infrastructure/agent_stack/fluent-bit/server/wazuh_server
bash generate_keys.sh \
    --host <SERVER_B_IP> \
    --port 8080 \
    --token <INGEST_TOKEN_FROM_STEP_5B> \
    --ca-cert ./certs/ca.crt
```

#### 6c. Launch Alert Shipper:
```bash
docker compose up -d
docker logs lsmp-fluent-bit --tail 20
```
*Expected output:* Confirms `inotify_fs_add()` successfully monitoring `/var/ossec/logs/alerts/alerts.json`.

---

### Step 7: Install & Enroll Wazuh Agent (Execute on Monitored Host)

On each monitored endpoint machine, install the official Wazuh Agent and connect it to Wazuh Manager on Server A:

```bash
# Add Wazuh GPG key and APT repository (Debian/Ubuntu)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Install agent with manager IP configuration
sudo apt-get update
sudo WAZUH_MANAGER='<SERVER_A_IP>' WAZUH_AGENT_NAME='client-01' apt-get install -y wazuh-agent

# Enable and start agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

*Verification:*
```bash
sudo systemctl status wazuh-agent
```
*Expected status:* `active (running)`.

---

### Step 8: Deploy Fluent-Bit Client (Execute on Monitored Host)

#### 8a. Transfer Loki Gateway Root CA:
```bash
# On Monitored Host:
mkdir -p infrastructure/agent_stack/fluent-bit/client/certs/
scp user@<SERVER_B_IP>:infrastructure/grafana_stack/certs/ca.crt \
    infrastructure/agent_stack/fluent-bit/client/certs/ca.crt
```

#### 8b. Configure Connection:
```bash
cd infrastructure/agent_stack/fluent-bit/client
bash generate_keys.sh --loki-host <SERVER_B_IP> --loki-port 3100 --ca-cert certs/ca.crt
```

#### 8c. Launch Client Container:
```bash
docker compose up -d
docker logs lsmp-client-fluent-bit --tail 20
```
*Expected output:* Confirms active tailing of `/var/log/auth.log` and `/var/log/nginx/access.log`.

---

## 💻 Single-Host (Dev / All-in-One) Quickstart

If you are developing or testing **all components on a single machine / VM**, the setup is streamlined because `generate_keys.sh` scripts auto-detect adjacent directories and auto-link certificates and tokens:

```bash
# 1. Server B stacks
docker network create lsmp_backend
cd infrastructure/database_stack && docker compose up -d
cd ../grafana_stack && bash generate_certs.sh && docker compose up -d

# 2. Server A stack (Wazuh Manager)
cd ../wazuh_stack
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

# 3. Database Server Ingestion (Auto-generates keys & token)
cd ../agent_stack/fluent-bit/server/database_server
bash generate_keys.sh
docker compose up -d --build

# 4. Wazuh Server Shipper (Auto-syncs token and ca.crt from database_server)
cd ../wazuh_server
bash generate_keys.sh
docker compose up -d

# 5. Client Shipper (Auto-syncs ca.crt)
cd ../../client
bash generate_keys.sh
docker compose up -d
```

---

## 🧪 Realistic End-to-End Verification (Testing from Client)

> [!CAUTION]
> **Do not test by sending direct `curl` requests to the Loki or Ingestion endpoints.** 
> Real-world verification must originate at the **Monitored Client Host** to validate the complete tail ➔ buffer ➔ parse ➔ transport ➔ store pipeline.

### Test Pipeline 1: Raw Log Pipeline (Client Host ➔ Loki ➔ Grafana)

#### 1. Generate an authentication event on the Monitored Host:
Run this on the monitored client machine to simulate an invalid SSH login attempt directly into `/var/log/auth.log`:
```bash
logger -p auth.warning -t sshd "Failed password for invalid user sec_auditor from 192.168.1.150 port 52341 ssh2"
```

#### 2. Confirm Fluent-Bit picked up the event:
Check the client container logs on the monitored host:
```bash
docker logs --tail 25 lsmp-client-fluent-bit
```
*Expected log:* Shows file offset increment for `/var/log/auth.log` and successful HTTP push (`204 No Content` / `200 OK`) to Loki.

#### 3. Query in Grafana Explore (Server B):
1. Navigate to `http://<SERVER_B_IP>:3000` and sign into Grafana.
2. Go to **Explore** ➔ select **Loki** datasource.
3. Run the following LogQL query:
   ```logql
   {job="auth_log"} |= "sec_auditor"
   ```
4. *Expected result:* The injected log message appears in the search results with correct timestamps and metadata labels.

---

### Test Pipeline 2: Security Alert Pipeline (Client Host ➔ Wazuh ➔ Ingest ➔ Redis ➔ PostgreSQL)

#### 1. Trigger a security alert on the Monitored Host:
Execute multiple failed `sudo` commands or touch a sensitive file monitored by Wazuh's FIM rule engine:
```bash
# Option A: Trigger failed sudo authentication
sudo -k
su - invalid_test_user_lsmp

# Option B: Trigger File Integrity Monitoring (FIM)
sudo touch /etc/pam.d/lsmp_fim_test && sudo rm -f /etc/pam.d/lsmp_fim_test
```

#### 2. Verify Wazuh Manager detection (Server A):
Verify that Wazuh Manager evaluated the event and emitted a rule violation alert:
```bash
docker exec -it wazuh.manager tail -n 5 /var/ossec/logs/alerts/alerts.json
```
*Expected output:* A JSON object with rule evaluation details (e.g., `rule.id`, `rule.level >= 3`).

#### 3. Verify Alert Shipper (Server A):
```bash
docker logs --tail 20 lsmp-fluent-bit
```
*Expected output:* Fluent-Bit tails the alert and sends an HTTPS `POST` with `X-Ingest-Token` to Server B `port 8080`.

#### 4. Verify Ingestion Receiver & DB Writer (Server B):
```bash
# Verify HTTP ingest received and pushed to Redis Stream:
docker logs --tail 20 lsmp-ingest

# Verify DB Writer batch consumption:
docker logs --tail 20 lsmp-db-writer
```
*Expected log:* `lsmp-ingest` reports `200 OK` (token validated and record XADDed), and `lsmp-db-writer` logs `Batch inserted X alerts into PostgreSQL`.

#### 5. Verify Persisted Alert in PostgreSQL Database:
Query the database directly on Server B:
```bash
docker exec -it lsmp-postgres psql -U postgres -d lsmp_db -c \
  "SELECT id, timestamp, rule_id, rule_level, agent_name, description FROM wazuh_alerts ORDER BY timestamp DESC LIMIT 3;"
```
*Expected output:* Displays tabular rows containing the alert, matching the client hostname and timestamp.

---

## 🛠️ Daily Operations & Troubleshooting Runbook

### 1. Real-time Pipeline Health Monitoring
```bash
# Monitor Ingest Receiver requests (Server B):
docker compose -f infrastructure/agent_stack/fluent-bit/server/database_server/docker-compose.yml logs -f lsmp-ingest

# Monitor Database Writer consumer (Server B):
docker compose -f infrastructure/agent_stack/fluent-bit/server/database_server/docker-compose.yml logs -f lsmp-db-writer

# Inspect Redis Stream backlog depth:
docker exec -it lsmp-redis redis-cli -a "<REDIS_PASSWORD>" XLEN wazuh_stream

# Inspect consumer group lag:
docker exec -it lsmp-redis redis-cli -a "<REDIS_PASSWORD>" XINFO CONSUMERS wazuh_stream db_writer_group
```

### 2. Common Troubleshooting Scenarios

| Issue Symptom | Root Cause | Resolution |
|---|---|---|
| `lsmp-ingest` logs `401 Unauthorized` | Token mismatch between Server A and Server B | Re-run `bash generate_keys.sh --token <TOKEN>` on Server A with the token from Server B's `.env`. |
| Fluent-Bit to Loki TLS handshake error | Client missing Loki Root CA or host IP not in SANs | Copy `grafana_stack/certs/ca.crt` from Server B to client's `certs/ca.crt` and ensure `generate_certs.sh --extra-ip <SERVER_B_IP>` was used on Server B. |
| Fluent-Bit to Ingest TLS handshake error | Hostname does not match certificate SAN IP/DNS | Re-run `bash generate_keys.sh --extra-ip <SERVER_B_IP>` on Server B (`database_server`) and re-sync `ca.crt` to Server A. |
| `network lsmp_backend not found` on Server A | `docker-compose.yml` on Server A references Server B's local bridge network | Remove `networks: [lsmp_backend]` on Server A; use standard Docker bridge. |
| Wazuh Agent status is `disconnected` | Port `1514` closed on Server A firewall or wrong IP configured | Run `sudo ufw allow 1514/tcp` on Server A; check `/var/ossec/etc/ossec.conf` on client. |
| Duplicate logs on container restart | DB tail offset volume not mounted | Ensure `fluent_bit_db` volume is mapped to `/fluent-bit/db/` in `docker-compose.yml`. |

### 3. Safe Shutdown & State Preservation
```bash
docker compose down
```
> [!NOTE]
> Stopping containers preserves uncommitted stream items in the `redis_data` volume and file read offsets in `fluent_bit_db`.
