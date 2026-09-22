# LSMP Agent Stack — Fluent-Bit Log Shipping Infrastructure

This directory contains the **Fluent-Bit log collection and forwarding infrastructure** for the LSMP (Log Security Monitoring Platform) project. It handles shipping security logs from monitored hosts and the Wazuh SIEM to the central database for AI-driven anomaly detection.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/
└── fluent-bit/
    ├── client/                      # Client agent (deployed on each monitored host)
    │   ├── docker-compose.yml       # Fluent-Bit client container
    │   ├── .env.example             # Environment template
    │   ├── generate_keys.sh         # TLS cert provisioning for Loki
    │   ├── certs/
    │   │   └── ca.crt               # Root CA cert (verifies Loki gateway)
    │   └── config/
    │       ├── fluent-bit.conf      # Tails /var/log/auth.log → Loki
    │       └── parsers.conf         # Log parsers (nginx, syslog)
    │
    ├── server/
    │   ├── wazuh_server/            # Wazuh Server shipper (deployed on Server A)
    │   │   ├── docker-compose.yml   # Fluent-Bit container for Wazuh alerts
    │   │   ├── .env.example         # Environment template
    │   │   ├── generate_keys.sh     # CA cert + token sync script
    │   │   ├── certs/
    │   │   │   └── ca.crt           # Root CA cert (verifies Server B)
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
    │       ├── wazuh_db_writer.py   # Redis Stream → PostgreSQL batch insert
    │       └── certs/               # Generated TLS certs
    │
    └── default.bak/                 # Backup of default Fluent-Bit configs
```

---

## 🏛 Architecture

```
┌────────────────────┐    ┌────────────────────────┐    ┌──────────────────────────┐
│ Monitored Hosts    │    │ Server A (Wazuh)       │    │ Server B (Database+AI)   │
│                    │    │                        │    │                          │
│ ┌────────────────┐ │    │ ┌────────────────────┐ │    │ ┌──────────────────┐     │
│ │ Fluent-Bit     │ │    │ │ Wazuh Manager      │ │    │ │ Grafana Loki     │     │
│ │ (client)       │ │    │ │ (wazuh_stack)      │ │    │ │ (grafana_stack)  │     │
│ │                │ │    │ └─────────┬──────────┘ │    │ │ gateway:3100     │     │
│ │ /var/log/      │ │    │           │ alert logs │    │ └───────▲──────────┘     │
│ │ auth.log ──────┼─┼────┼───────────┼────────────┼────┼─────────┘ (HTTPS)       │
│ │                │ │    │ ┌─────────▼──────────┐ │    │                          │
│ │          ──────┼─┼──► │ │ Fluent-Bit         │ │    │ ┌──────────────────┐     │
│ └────────────────┘ │    │ │ (wazuh_server)     │ │    │ │ Ingest Receiver  │     │
│       to Loki      │    │ │                    │─┼────┼►│ (HTTPS:8080)     │     │
│                    │    │ └────────────────────┘ │    │ └────────┬─────────┘     │
│                    │    │       to Ingest (HTTP) │    │          │               │
│                    │    │                        │    │ ┌────────▼─────────┐     │
│                    │    │                        │    │ │ Redis Stream     │     │
│                    │    │                        │    │ └────────┬─────────┘     │
│                    │    │                        │    │ ┌────────▼─────────┐     │
│                    │    │                        │    │ │ DB Writer        │     │
│                    │    │                        │    │ │ → PostgreSQL     │     │
│                    │    │                        │    │ └──────────────────┘     │
└────────────────────┘    └────────────────────────┘    └──────────────────────────┘
```

| Component | Where | What it does | Ships to |
|---|---|---|---|
| **Client Fluent-Bit** | Each monitored host | Tails `/var/log/auth.log` and nginx logs | Grafana Loki (HTTPS) |
| **Wazuh Server Fluent-Bit** | Server A | Tails `/var/ossec/logs/alerts/alerts.json` | Ingest Receiver on Server B (HTTPS + token) |
| **Ingest Receiver** | Server B | HTTPS endpoint, validates token, buffers in Redis | Redis Stream |
| **DB Writer** | Server B | Consumes Redis Stream, batch INSERTs | PostgreSQL (database_stack) |

---

## 🔧 What Was Changed in This Branch (`agent_stack_fix`)

| Finding ID | File | Problem | Fix |
|---|---|---|---|
| AGENT-01 | `wazuh_server/config/fluent-bit.conf` | Was a copy-paste of client config (wrong INPUT/OUTPUT) | Rewrote: tails Wazuh alerts → HTTP Ingest |
| AGENT-02 | `database_server/generate_keys.sh` | TLS cert SANs hardcoded to localhost only | Added `--domain`/`--extra-ip` CLI flags |
| AGENT-03 | `database_server/docker-compose.yml` | Redis password visible in `docker top` | Use `REDISCLI_AUTH` env var in healthcheck |
| AGENT-04 | `wazuh_server` + `client` docker-compose.yml | Containers running as `root` | Replaced with `DAC_READ_SEARCH` capability |
| AGENT-05 | `database_server/ingest_receiver.py` | Token compared with `!=` (timing attack) | Use `hmac.compare_digest()` |

---

## ⚠️ Deployment Order (CRITICAL)

You **must** deploy the stacks in this exact order. Each step depends on the previous one.

```
Step 1: docker network create lsmp_backend
          │
Step 2: database_stack  (PostgreSQL must be running first)
          │
Step 3: grafana_stack   (Loki must be accepting logs before client connects)
          │
Step 4: wazuh_stack     (Wazuh Manager must be running before its Fluent-Bit ships alerts)
          │
Step 5: database_server (Ingest Receiver + Redis + DB Writer on Server B)
          │
Step 6: wazuh_server    (Fluent-Bit on Server A → ships Wazuh alerts to Ingest Receiver)
          │
Step 7: client          (Fluent-Bit on each monitored host → ships auth logs to Loki)
```

**Why this order?**
- `database_stack` first: PostgreSQL must exist before `database_server`'s DB Writer can connect.
- `grafana_stack` second: Loki gateway (port 3100) must be listening before the `client` Fluent-Bit tries to push logs.
- `wazuh_stack` third: Wazuh Manager must create the `wazuh_logs` volume before the `wazuh_server` Fluent-Bit can mount it.
- `database_server` fourth: The Ingest Receiver must be listening (port 8080) before `wazuh_server` Fluent-Bit sends alerts.
- `wazuh_server` fifth: Ships Wazuh alerts to the running Ingest Receiver.
- `client` last: Ships auth logs to the running Loki gateway.

---

## 🚀 Step-by-Step Deployment Guide

### Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- **Server A**: runs Wazuh Manager + Wazuh Server Fluent-Bit
- **Server B**: runs PostgreSQL + Grafana/Loki + Ingest Receiver + Redis + DB Writer
- **Monitored hosts**: run Client Fluent-Bit (can be the same as Server A/B, or separate machines)

---

### Step 1: Create the shared Docker network (Server B)

```bash
docker network create lsmp_backend
```

**Expected result:**
```
a1b2c3d4e5f6...   (network ID hash)
```
If already exists: `Error response from daemon: network with name lsmp_backend already exists` — that's OK.

---

### Step 2: Deploy database_stack (Server B)

> 📖 Full details in `database_stack/README.md`

```bash
cd infrastructure/database_stack
cp .env.example .env
# Edit .env → set POSTGRES_USER, POSTGRES_PASSWORD (REQUIRED, no defaults)
docker compose up -d
```

**Verify:**
```bash
docker compose ps
```
**Expected:** `lsmp-postgres` shows `Up (healthy)`.

---

### Step 3: Deploy grafana_stack (Server B)

> 📖 Full details in `grafana_stack/README.md`

```bash
cd infrastructure/grafana_stack
cp .env.example .env
# Edit .env → set MINIO_ROOT_PASSWORD
docker compose up -d
```

**Verify Loki gateway is accepting connections:**
```bash
curl -s http://localhost:3100
```
**Expected:** `OK`

**Verify Grafana is running:**
```bash
curl -s http://localhost:3000/api/health | python3 -m json.tool
```
**Expected:** `{"commit":"...","database":"ok","version":"..."}`

---

### Step 4: Deploy wazuh_stack (Server A)

> 📖 Full details in `wazuh_stack/README.md`

```bash
# On Server A:
sudo sysctl -w vm.max_map_count=262144
cd infrastructure/wazuh_stack
cp .env.example .env
# Edit .env → set INDEXER_PASSWORD, API_PASSWORD, DASHBOARD_PASSWORD
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

**Verify:**
```bash
docker compose ps
```
**Expected:** `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` all show `Up (healthy)` (~2 min).

**Verify the `wazuh_logs` volume was created** (needed by wazuh_server Fluent-Bit in Step 6):
```bash
docker volume inspect wazuh_logs
```
**Expected:** JSON output with `"Name": "wazuh_logs"` and `"Driver": "local"`.

---

### Step 5: Generate TLS certs and deploy database_server (Server B)

#### 5a. Generate TLS certificates and tokens

```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
bash generate_keys.sh --domain ingest.your-domain.com --extra-ip <SERVER_B_IP>
```

**Expected output:**
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

**Verify TLS cert SANs include your custom entries:**
```bash
openssl x509 -in certs/lsmp_ingest.crt -text -noout | grep -A5 "Subject Alternative Name"
```
**Expected:**
```
X509v3 Subject Alternative Name:
    DNS:localhost, DNS:lsmp-ingest, DNS:ingest.your-domain.com, IP:127.0.0.1, IP:0.0.0.0, IP:<SERVER_B_IP>
```

**Save these values — you'll need them in Step 6:**
```bash
echo "INGEST_TOKEN: $(grep '^INGEST_TOKEN=' .env | cut -d= -f2)"
echo "CA cert path: $(pwd)/certs/ca.crt"
```

#### 5b. Start the Ingest pipeline

```bash
docker compose up -d --build
```

**Expected:** Three containers start.

**Verify all containers are running:**
```bash
docker compose ps
```
**Expected:**
```
NAME             SERVICE         STATUS           PORTS
lsmp-redis       lsmp-redis      Up (healthy)
lsmp-ingest      lsmp-ingest     Up               0.0.0.0:8080->8080/tcp
lsmp-db-writer   lsmp-db-writer  Up
```

**Verify Ingest Receiver is listening:**
```bash
docker logs lsmp-ingest --tail 5
```
**Expected output includes:**
```
[INFO] [ingest-receiver:...]: LSMP Ingest Receiver listening securely (HTTPS/TLS) at https://0.0.0.0:8080/ingest
```

**Verify Redis password is NOT visible in process list:**
```bash
docker top lsmp-redis
```
**Expected:** CMD column shows `redis-server *:6379` — NO `-a <password>` argument visible.

#### 5c. Test the Ingest endpoint manually (optional but recommended)

```bash
curl -k -X POST https://localhost:8080/ingest \
  --cacert certs/ca.crt \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Ingest-Token: $(grep '^INGEST_TOKEN=' .env | cut -d= -f2)" \
  -d '{"timestamp":"2026-01-01T00:00:00","rule":{"level":5,"id":"5501"},"agent":{"id":"001","ip":"10.0.0.5"},"location":"/var/log/auth.log","full_log":"Test log entry from curl","data":{"srcip":"10.0.0.99","dstuser":"root"}}'
```
**Expected:** `HTTP 200 OK` with response body: `{"status":"ok","count":1}`

**Verify it reached Redis:**
```bash
docker exec lsmp-redis sh -c 'REDISCLI_AUTH=$REDIS_PASSWORD redis-cli XLEN wazuh_stream'
```
**Expected:** `(integer) 1` (or more if you ran it multiple times)

**Verify it was written to PostgreSQL:**
```bash
docker exec lsmp-postgres psql -U lsmp_admin -d lsmp_db -c "SELECT event_id, source_ip, raw_log FROM log_event ORDER BY timestamp DESC LIMIT 1;"
```
**Expected:** One row with `source_ip = 10.0.0.99` and `raw_log` containing "Test log entry from curl".

**Test token rejection (invalid token):**
```bash
curl -k -X POST https://localhost:8080/ingest \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Ingest-Token: INVALID_TOKEN" \
  -d '{"test":"should be rejected"}'
```
**Expected:** `HTTP 401 Unauthorized`

---

### Step 6: Deploy wazuh_server Fluent-Bit (Server A)

This ships Wazuh Manager alerts to the Ingest Receiver on Server B.

#### 6a. Copy CA certificate from Server B to Server A

```bash
# Run this on Server B:
scp infrastructure/agent_stack/fluent-bit/server/database_server/certs/ca.crt \
    user@SERVER_A_IP:infrastructure/agent_stack/fluent-bit/server/wazuh_server/certs/ca.crt
```

> ℹ️ If both directories are on the same machine (dev setup), the `generate_keys.sh` script auto-syncs the cert.

#### 6b. Configure environment

```bash
# On Server A:
cd infrastructure/agent_stack/fluent-bit/server/wazuh_server
cp .env.example .env
```

Edit `.env` with the values from Step 5:
```env
# IP or hostname of Server B where lsmp-ingest is running
INGEST_HOST=<SERVER_B_IP>
# Port of the ingest receiver (default 8080)
INGEST_PORT=8080
# The 64-char hex token from Step 5a
INGEST_TOKEN=<paste-the-token-from-step-5>
# TLS settings
ENABLE_TLS=On
TLS_VERIFY=On
```

**Alternatively, use the generate_keys.sh helper:**
```bash
bash generate_keys.sh \
  --token <TOKEN_FROM_STEP_5> \
  --host <SERVER_B_IP> \
  --ca-cert /path/to/ca.crt
```

#### 6c. Start the Fluent-Bit shipper

```bash
docker compose up -d
```

**Verify container is running:**
```bash
docker compose ps
```
**Expected:**
```
NAME              SERVICE          STATUS    PORTS
lsmp-fluent-bit   lsmp-fluent-bit  Up
```

**Verify Fluent-Bit is tailing Wazuh alerts:**
```bash
docker logs lsmp-fluent-bit --tail 20
```
**Expected output includes:**
```
[info] [input:tail:tail.0] inotify_fs_add(): inode=... watch_fd=... /var/ossec/logs/alerts/alerts.json
[info] [output:http:http.0] <INGEST_HOST>:8080, ...
```

> ⚠️ If you see `[error] ... /var/ossec/logs/alerts/alerts.json: No such file or directory`, it means:
> - The `wazuh_logs` external volume is not available. Check that `wazuh_stack` is running (`docker volume ls | grep wazuh_logs`).
> - Or the volume is empty. Wait for Wazuh Manager to generate alerts.

#### 6d. Test: Trigger a Wazuh alert and verify end-to-end flow

Generate a failed SSH login on a machine with a Wazuh agent:
```bash
ssh nonexistent_user@localhost
# Type any password, then ctrl+c
```

**Wait 5-10 seconds**, then verify the alert flowed through:

1. **Check Ingest Receiver logs (Server B):**
```bash
docker logs lsmp-ingest --tail 5
```
**Expected:** `[INFO] ... Accepted 1 log line(s) from ...`

2. **Check PostgreSQL (Server B):**
```bash
docker exec lsmp-postgres psql -U lsmp_admin -d lsmp_db \
  -c "SELECT event_id, severity, source_ip, username FROM log_event ORDER BY timestamp DESC LIMIT 3;"
```
**Expected:** Recent rows with SSH-related alert data.

---

### Step 7: Deploy Client Fluent-Bit (Each Monitored Host)

The client agent ships host authentication logs (`/var/log/auth.log`) and optionally web server logs to **Grafana Loki** for visualization.

> ℹ️ **Where to deploy:** Install this on every machine you want to monitor. This can be Server A, Server B, or any other host in your network.

#### 7a. Provision TLS certificate for Loki connection

The client needs a Root CA certificate to verify the Grafana Loki gateway's TLS connection.

**Option A — Same machine as grafana_stack (dev/single-host setup):**
```bash
cd infrastructure/agent_stack/fluent-bit/client
bash generate_keys.sh
```
The script automatically detects and copies `ca.crt` from `../server/database_server/certs/`. If Loki uses a self-signed cert, it generates a fallback.

**Expected output:**
```
=================================================================
🔒  LSMP SECURITY: CONFIGURING CLIENT AGENT TLS & GRAFANA LOKI
=================================================================
📋 Auto-syncing Root CA Certificate from local database_server...
=================================================================
✅ LSMP CLIENT FLUENT-BIT SECURE CONNECTION CONFIGURED!
-----------------------------------------------------------------
📍 Certs Directory : .../client/certs
📜 Root CA File    : .../client/certs/ca.crt
🌐 Grafana Loki    : https://127.0.0.1:3100
=================================================================
```

**Option B — Remote host (multi-host production):**
```bash
cd infrastructure/agent_stack/fluent-bit/client

# 1. Copy the CA cert from Server B where Loki runs:
scp user@SERVER_B_IP:infrastructure/agent_stack/fluent-bit/server/database_server/certs/ca.crt ./certs/ca.crt

# 2. Run the setup script with Loki connection details:
bash generate_keys.sh \
  --loki-host <SERVER_B_IP> \
  --loki-port 3100 \
  --ca-cert ./certs/ca.crt
```

**Expected output:**
```
=================================================================
✅ LSMP CLIENT FLUENT-BIT SECURE CONNECTION CONFIGURED!
-----------------------------------------------------------------
📍 Certs Directory : .../client/certs
📜 Root CA File    : .../client/certs/ca.crt
🌐 Grafana Loki    : https://<SERVER_B_IP>:3100
=================================================================
```

**Option C — Manual setup (no script):**
```bash
cd infrastructure/agent_stack/fluent-bit/client

# 1. Copy CA cert into certs/
mkdir -p certs
cp /path/to/ca.crt ./certs/ca.crt

# 2. Create .env from template
cp .env.example .env
```

Edit `.env`:
```env
# ====== Grafana Loki Server Configuration ======
# IP or hostname of the server running grafana_stack (Loki gateway port)
LOKI_HOST=<SERVER_B_IP>
LOKI_PORT=3100
# Leave empty if Loki doesn't require auth, or set basic auth credentials
LOKI_USER=
LOKI_PASSWORD=

# ====== TLS / Security Configuration ======
# Set to "Off" if Loki gateway does NOT use TLS (e.g., local dev without HTTPS)
ENABLE_TLS=On
TLS_VERIFY=On

# ====== Wazuh Manager Syslog Configuration ======
# Only needed if you enable the Wazuh syslog output in fluent-bit.conf
WAZUH_HOST=<SERVER_A_IP>
WAZUH_PORT=514

# ====== Client Metadata & Differentiating Labels ======
# Unique name for THIS machine — appears as a label in Grafana dashboards
CLIENT_HOSTNAME=web-prod-01
ENV=production
```

> ⚠️ **`CLIENT_HOSTNAME` is important!** This label distinguishes logs from different machines in Grafana. Use a unique, meaningful name like `web-prod-01`, `db-server-b`, `vpn-gateway`, etc.

#### 7b. Verify the `.env` is correct

```bash
cat .env | grep -E '^(LOKI_HOST|LOKI_PORT|CLIENT_HOSTNAME|ENABLE_TLS)'
```
**Expected:**
```
LOKI_HOST=<your-server-b-ip>
LOKI_PORT=3100
CLIENT_HOSTNAME=<your-hostname>
ENABLE_TLS=On
```

#### 7c. Verify the CA certificate exists

```bash
ls -la certs/ca.crt
```
**Expected:** File exists and is non-empty (typically 1-2 KB).

If missing, Fluent-Bit will fail to start with a TLS error.

#### 7d. Start the client agent

```bash
docker compose up -d
```

**Verify container is running:**
```bash
docker compose ps
```
**Expected:**
```
NAME                      SERVICE                   STATUS    PORTS
lsmp-client-fluent-bit    lsmp-client-fluent-bit    Up
```

#### 7e. Verify Fluent-Bit is tailing logs

```bash
docker logs lsmp-client-fluent-bit --tail 20
```

**Expected output includes:**
```
[info] [fluent bit] version=3.0.x
[info] [input:tail:tail.0] inotify_fs_add(): inode=XXXXX watch_fd=1 /var/log/auth.log
[info] [output:loki:loki.0] configured, hostname=<LOKI_HOST>
```

> ⚠️ **Common errors and fixes:**
>
> | Error message | Cause | Fix |
> |---|---|---|
> | `[error] [tls] ... SSL routines ... certificate verify failed` | ca.crt is wrong or missing | Re-copy `ca.crt` from Server B |
> | `[error] [output:loki:loki.0] ... connection refused` | Loki is not running or wrong host/port | Verify `LOKI_HOST`/`LOKI_PORT` in `.env`, check `curl http://<LOKI_HOST>:3100` |
> | `[error] ... /var/log/auth.log: No such file or directory` | Host `/var/log` not mounted, or no auth.log on this OS | Check `volumes:` in compose, check if `/var/log/auth.log` exists on host |
> | `[warn] [input:tail:tail.0] ... Permission denied` | Container can't read log files | The `DAC_READ_SEARCH` capability should fix this. If not, check file permissions |

#### 7f. Test: Generate a log entry and verify it reaches Loki

**Generate a test auth event on the monitored host:**
```bash
logger -t sshd "Failed password for testuser from 192.168.1.99 port 22 ssh2"
```

This writes a test line to `/var/log/auth.log` (or syslog, depending on OS).

**Wait 2-3 seconds**, then verify in Grafana:

1. **Open Grafana:** `http://<SERVER_B_IP>:3000`
2. **Go to:** Explore (compass icon) → Select **Loki** datasource
3. **Run query:**
```
{job="auth", hostname="<CLIENT_HOSTNAME>"}
```
4. **Expected:** Your test log line `"Failed password for testuser from 192.168.1.99"` appears.

**Alternatively, verify via Loki API directly:**
```bash
curl -s "http://<SERVER_B_IP>:3100/loki/api/v1/query" \
  -H "X-Scope-OrgID: tenant1" \
  --data-urlencode 'query={job="auth"}' \
  --data-urlencode 'limit=5' | python3 -m json.tool
```
**Expected:** JSON response with `"result"` containing your log entries.

#### 7g. Test: Verify TLS connection is working

```bash
docker logs lsmp-client-fluent-bit 2>&1 | grep -i "tls\|ssl\|cert"
```
**Expected:** No TLS error lines. If TLS is working, you'll see nothing (or an info line about TLS init).

#### 7h. Disable TLS (Development only)

If you're running everything on localhost for development and Loki doesn't have TLS:
```env
# In .env:
ENABLE_TLS=Off
TLS_VERIFY=Off
```

Then restart:
```bash
docker compose down && docker compose up -d
```

---

### Step 8: Full End-to-End Verification

After all components are deployed, verify the complete data pipeline:

#### 8a. Verify Client → Loki path

```bash
# On any monitored host:
logger -t sshd "LSMP E2E Test: auth event $(date)"
```

**Check in Grafana** → Explore → Loki → `{job="auth"}`:
**Expected:** The test log appears within 5 seconds.

#### 8b. Verify Wazuh → Ingest → PostgreSQL path

```bash
# On a host with Wazuh agent, trigger a failed login:
ssh invalid_user@localhost
```

**Check in PostgreSQL (Server B):**
```bash
docker exec lsmp-postgres psql -U lsmp_admin -d lsmp_db \
  -c "SELECT count(*) FROM log_event WHERE timestamp > NOW() - INTERVAL '5 minutes';"
```
**Expected:** Count > 0 (new alerts were inserted).

#### 8c. Verify all containers are healthy

```bash
# Server B (run from infrastructure/):
echo "=== database_stack ===" && docker compose -f database_stack/docker-compose.yml ps
echo "=== grafana_stack ===" && docker compose -f grafana_stack/docker-compose.yaml ps
echo "=== database_server ===" && docker compose -f agent_stack/fluent-bit/server/database_server/docker-compose.yml ps

# Server A:
echo "=== wazuh_stack ===" && docker compose -f wazuh_stack/docker-compose.yml ps
echo "=== wazuh_server ===" && docker compose -f agent_stack/fluent-bit/server/wazuh_server/docker-compose.yml ps

# Each monitored host:
echo "=== client ===" && docker compose -f agent_stack/fluent-bit/client/docker-compose.yml ps
```

**Expected:** All containers show `Up` or `Up (healthy)`. No containers in `Restarting`.

---

## 🛑 Teardown & Maintenance

### Stop client agent (any monitored host)
```bash
cd infrastructure/agent_stack/fluent-bit/client
docker compose down
```

### Stop wazuh_server Fluent-Bit (Server A)
```bash
cd infrastructure/agent_stack/fluent-bit/server/wazuh_server
docker compose down
```

### Stop database_server pipeline (Server B)
```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
docker compose down       # preserves Redis data
docker compose down -v    # wipes Redis data
```

### Regenerate TLS certs (force)
```bash
cd infrastructure/agent_stack/fluent-bit/server/database_server
bash generate_keys.sh --force
# Then re-copy ca.crt to wazuh_server and client
```

---

## ⚠️ Impact and Risks

| Change | Impact | Risk |
|---|---|---|
| AGENT-01: New Fluent-Bit config | Wazuh alerts now flow to ingest pipeline | Must verify end-to-end after deployment |
| AGENT-02: Dynamic SANs | TLS certs can include external IPs/domains | Existing certs must be regenerated with `--force` |
| AGENT-03: Redis healthcheck | No functional change — password is just hidden from process list | None |
| AGENT-04: No more root | Fluent-Bit runs with `DAC_READ_SEARCH` capability instead of root | If log files have very restrictive permissions (<600), Fluent-Bit may fail to read. Check `docker logs` |
| AGENT-05: Constant-time token comparison | No functional change — prevents theoretical timing attacks | None |

---

## 📋 Known Issues / Not Fixed

No findings were rejected. All 5 findings were implemented.
