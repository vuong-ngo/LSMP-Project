# LSMP Fluent-bit Ingestion Client Agent

This directory contains the Docker Compose configurations and Fluent-bit settings for deploying the log ingestion client agent on LSMP host servers and monitored SME endpoints.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/client/
├── docker-compose.yml       # Docker Compose service definition
├── .env.example             # Environment variables template
├── generate_keys.sh         # Script to configure TLS CA certificate and credentials
├── certs/                   # Certificate directory
│   └── ca.crt               # Root CA Certificate (used to verify Loki/Wazuh servers)
└── config/                  # Configuration directory
    ├── fluent-bit.conf      # Service configuration with TLS, Loki, and Syslog outputs
    └── parsers.conf         # Parsers definition (Nginx, Syslog RFCs)
```

---

## ⚙️ Ingestion & Security Architecture

Fluent-bit operates as a lightweight, single agent (Sole Agent) running on client machines to collect local host logs (such as authentication logs and web server logs) and ship them securely to **Grafana Loki** (for log visualization) and **Wazuh Manager** (for security event detection).

### 1. Transport Encryption & Authentication (TLS / HTTPS & Basic Auth)

* **TLS Transport Encryption (`tls On`)**:
  - All log streams sent to Grafana Loki (`loki` plugin) and Wazuh Manager (`syslog` plugin) are encrypted in transit over SSL/TLS.
* **Certificate Verification (`tls.verify On`)**:
  - The client agent uses `ca.crt` mounted at `/fluent-bit/certs/ca.crt` to verify the authenticity of central server TLS certificates.
* **Grafana Loki Authentication (`http_user` / `http_passwd`)**:
  - Supports optional HTTP Basic Authentication credentials when shipping logs to protected Grafana Loki instances.

### 2. Log Collection & Parsing (Fluent-bit Inputs)

* **Authentication Logs (`/var/log/auth.log`)**
  * **Tag**: `client.auth`
  * **Destination**: Forwarded securely to Grafana Loki and Wazuh Manager.
  * **Storage**: Tail offsets are persisted in `/fluent-bit/db/auth_logs.db` to prevent log duplication upon container restarts.
* **Web Server Logs (`/var/log/nginx/access.log`)**
  * **Tag**: `client.nginx`
  * **Parser**: Custom regex-based `nginx` parser defined in `parsers.conf`.

---

## 🚀 Getting Started

### 1. Prerequisites

Ensure Docker and Docker Compose (v2+) are installed on the client machine.

### 2. Provision Security Credentials & Environment

The Fluent-Bit client uses the trusted Root CA (`ca.crt`) from the Loki Gateway (Server B) to verify TLS connections when pushing logs to port `3100`.

#### Option A: Single-Host (Dev / All-in-One Machine)
When running on the same machine as `grafana_stack`, the script automatically detects and syncs `grafana_stack/certs/ca.crt`:

```bash
bash generate_keys.sh
```

*Expected output:*
```text
=================================================================
🔒  LSMP SECURITY: CONFIGURING CLIENT AGENT TLS & GRAFANA LOKI
=================================================================
📋 Auto-syncing Root CA Certificate from local grafana_stack (.../grafana_stack/certs/ca.crt)...
=================================================================
✅ LSMP CLIENT FLUENT-BIT SECURE CONNECTION CONFIGURED!
-----------------------------------------------------------------
📍 Certs Directory : .../client/certs
📜 Root CA File    : .../client/certs/ca.crt
🌐 Grafana Loki    : https://127.0.0.1:3100
=================================================================
```

#### Option B: Multi-Host (Remote Monitored Client Machine)
When the client is deployed on a separate host/VM from Server B (Loki Gateway):

1. Transfer `ca.crt` generated on Server B (`grafana_stack/certs/ca.crt`) to the client:
   ```bash
   mkdir -p certs
   scp user@<SERVER_B_IP>:infrastructure/grafana_stack/certs/ca.crt ./certs/ca.crt
   ```

2. Run `generate_keys.sh` with connection parameters:
   ```bash
   bash generate_keys.sh --loki-host <SERVER_B_IP> --loki-port 3100 --ca-cert ./certs/ca.crt
   ```

*Available CLI Arguments:*
* `--loki-host <IP/DNS>`: IP or domain of Server B Loki Gateway.
* `--loki-port <PORT>`: External port for Loki Gateway (default: `3100`).
* `--ca-cert <PATH>`: Explicit path to Root CA certificate.
* `--loki-user <USER>`: Optional HTTP Basic Auth username.
* `--loki-pass <PASS>`: Optional HTTP Basic Auth password.

3. Verify `.env` configuration:
```env
# IP/port of the central Grafana Loki server
LOKI_HOST=192.168.1.100
LOKI_PORT=3100
LOKI_USER=
LOKI_PASSWORD=

# TLS / Security Configuration (Must be On)
ENABLE_TLS=On
TLS_VERIFY=On

# IP/port of the central Wazuh Manager syslog port
WAZUH_HOST=192.168.1.50
WAZUH_PORT=514

# Metadata label for this client machine
CLIENT_HOSTNAME=web-prod-01
ENV=production
```

### 3. Startup & Operations

#### A. Start the Agent Stack

To run the Fluent-bit client agent in background mode:

```bash
docker compose up -d --build
```

> **Important**: `docker-compose.yml` mounts the host directory `/var/log` as read-only (`ro`) so the agent can read host logs securely without write permissions.

#### B. Verify Container Logs

Check shipping status and TLS connection:
```bash
docker compose logs -f
```

#### C. Verify End-to-End Log Shipping to Loki

1. Generate a test authentication event on this host machine:
```bash
logger -p auth.warning -t sshd "Failed password for invalid user sec_auditor from 192.168.1.150 port 52341 ssh2"
```

2. Confirm Fluent-Bit forwarded the event to Loki:
```bash
docker logs --tail 25 lsmp-client-fluent-bit
```
*Expected output:* Shows active file offset increment and HTTP push to Loki returning `204 No Content` / `200 OK`.

3. Query on Grafana (`http://<SERVER_B_IP>:3000`) in **Explore** using LogQL:
```logql
{job="auth_log"} |= "sec_auditor"
```

#### D. Stop the Agent Stack

To stop the agent service:

```bash
docker compose down
```
