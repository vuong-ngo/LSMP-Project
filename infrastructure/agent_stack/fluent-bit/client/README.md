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

Run the client setup script to initialize certificates and environment configuration:

```bash
bash generate_keys.sh
```

If the client machine is deployed independently on a separate remote network:
1. Copy `ca.crt` generated from the Database Server into `./certs/ca.crt`.
2. Copy `.env.example` to `.env` and fill in your central server endpoints:

```env
# IP/port of the central Grafana Loki server
LOKI_HOST=192.168.1.100
LOKI_PORT=3100
LOKI_USER=
LOKI_PASSWORD=

# TLS / Security Configuration
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

#### C. Stop the Agent Stack

To stop the agent service:

```bash
docker compose down
```
