# LSMP Wazuh Fluent-bit Shipper

This directory contains the Fluent-bit configurations deployed on **Server A** (Wazuh Manager Server) to tail security alert logs from Wazuh and stream them over HTTP to the ingestion receiver on Server B.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/server/wazuh_server/
├── docker-compose.yml       # Docker Compose service definition for Server A
├── .env.example             # Environment variables template for endpoint configs
└── config/                  # Fluent-bit settings directory
    ├── fluent-bit.conf      # Main service, INPUT (tail), and HTTP OUTPUT filters
    └── parsers.conf         # JSON format parsers for Wazuh alerts
```

---

## 🏛 Component Architecture

The log forwarding agent runs as a single lightweight container, sharing volume mounts with the Wazuh Manager:

| Component | Container Name | Default Ports | Description |
| :--- | :--- | :--- | :--- |
| **Fluent-bit Agent** | `lsmp-fluent-bit` | None | Mounts the Wazuh manager alert volume as read-only (`ro`) and ships JSON lines to Server B with transport-level token verification. |

---

## 🚀 Getting Started

Follow these steps to configure and start the log shipper on Server A:

### 1. Prerequisites

* Ensure that your main Wazuh Manager stack is running on Server A, which creates the external named volume `wazuh_logs`.
* Verify connectivity to the Ingestion Receiver on Server B at port `8080` (or your configured port).

### 2. Environment Setup

Copy the environment template file:
```bash
cp .env.example .env
```

Open the `.env` file and specify Server B's details:
```env
# IP or hostname of Server B (where lsmp-ingest runs)
INGEST_HOST=192.168.1.50
INGEST_PORT=8080

# Authorization token (Must match database_server/.env on Server B)
INGEST_TOKEN=CHANGE_ME_RANDOM_LONG_SECRET
```

### 3. Startup

Start the Fluent-bit shipper service:
```bash
docker compose up -d
```

Check the shipping agent container logs to verify active ingestion:
```bash
docker compose logs -f
```

---

## 🛑 Teardown & Maintenance

To stop the log forwarding agent:
```bash
docker compose down
```
