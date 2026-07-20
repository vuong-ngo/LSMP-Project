# LSMP Fluent-bit Ingestion Client

This directory contains the Docker Compose configurations and Fluent-bit settings for deploying the log ingestion client agent on LSMP host servers.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/client/
├── docker-compose.yml       # Docker Compose service definition
├── .env.example             # Environment variables template
└── config/                  # Configuration directory
    ├── fluent-bit.conf      # Main Fluent-bit service configuration
    └── parsers.conf         # Parsers definition (Nginx, Syslog RFCs)
```

---

## ⚙️ Ingestion & Security Architecture

Fluent-bit operates as a lightweight, single agent (Sole Agent) running on client machines to collect logs and ship them directly to **Grafana Loki** (for storage) and **Wazuh Manager** (for security event detection).

### 1. Security Mechanisms (No Password Authentication)

Since Fluent-bit forwards data directly to the Wazuh Manager via Syslog TCP (port 514)—a protocol that does not natively support password-based authentication—security must be established via infrastructure defenses:

* **IP Whitelisting**: On the Wazuh Manager host, configure the `<allowed-ips>` tag in `ossec.conf` to only accept incoming traffic from authorized client IP addresses. Unlisted traffic is dropped.
* **Firewall Filtering**: Use `ufw` or `iptables` on the Wazuh Manager server to restrict port `514/tcp` strictly to the IP addresses of authorized clients.
* **Syslog over TLS (Encryption)**: For transmission across untrusted public networks (WAN), secure the connection by enabling TLS in the Wazuh Manager's `<remote>` block and defining SSL/TLS credentials inside the Fluent-bit `syslog` output block.

### 2. Log Collection & Parsing (Fluent-bit Inputs)

* **Authentication Logs (`/var/log/auth.log`)**
  * **Tag**: `client.auth`
  * **Destination**: Forwarded to Grafana Loki and Wazuh Manager.
  * **Storage**: Tail offsets are persisted in `/fluent-bit/db/auth_logs.db` to prevent log duplication upon container restarts.
* **Web Server Logs (`/var/log/nginx/access.log`)**
  * **Tag**: `client.nginx`
  * **Parser**: Custom regex-based `nginx` parser defined in `parsers.conf`.
  * **Status**: Currently commented/disabled by default.

---

## 🚀 Getting Started

### 1. Prerequisites

Ensure you have Docker and Docker Compose (v2+) installed on the client machine.

### 2. Configuration

Copy the environment variables template and configure the endpoints:

```bash
cp .env.example .env
```

Open the `.env` file and set the target hosts:

```env
# IP/port of the central Grafana Loki server
LOKI_HOST=127.0.0.1
LOKI_PORT=3100

# IP/port of the central Wazuh Manager syslog port
WAZUH_HOST=127.0.0.1
WAZUH_PORT=514

# Metadata label for this client machine
CLIENT_HOSTNAME=client-01
ENV=production
```

### 3. Startup & Operations

#### A. Start the Agent Stack

To run the Fluent-bit client agent in background mode:

```bash
docker compose up -d
```

> **Important**: The `docker-compose.yml` mounts the host directory `/var/log` as read-only (`ro`) to ensure the agent can securely read host logs (e.g., `/var/log/auth.log`) without risk of modifying host files.

#### B. Stop the Agent Stack

To stop the agent service:

```bash
docker compose down
```
