# LSMP Wazuh Fluent-bit Shipper

This directory contains the Fluent-bit configurations deployed on **Server A** (Wazuh Manager Server) to tail security alert logs from Wazuh and stream them over encrypted HTTPS to the ingestion receiver on Server B.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/fluent-bit/server/wazuh_server/
├── docker-compose.yml       # Docker Compose service definition for Server A
├── .env.example             # Environment variables template for endpoint configs
├── generate_keys.sh         # Standalone script to sync CA certificate and INGEST_TOKEN
├── certs/                   # Certificate directory
│   └── ca.crt               # Root CA Certificate (used to verify Server B)
└── config/                  # Fluent-bit settings directory
    ├── fluent-bit.conf      # Service configuration with TLS & HTTP Output
    └── parsers.conf         # JSON format parsers for Wazuh alerts
```

---

## 🏛 Component Architecture

The log forwarding agent runs as a single lightweight container, sharing volume mounts with the Wazuh Manager:

| Component | Container Name | Default Ports | Description |
| :--- | :--- | :--- | :--- |
| **Fluent-bit Agent** | `lsmp-fluent-bit` | None | Mounts the Wazuh manager alert volume as read-only (`ro`) and ships JSON lines to Server B with transport-level TLS encryption and token verification. |

---

## 🔒 Security & Token Authentication Architecture

1. **TLS Transport Encryption (`tls On`)**:
   - Encrypts all log data in transit between Server A and Server B over HTTPS (port 8080).
2. **CA Certificate Verification (`tls.verify On`)**:
   - Uses `ca.crt` mounted at `/fluent-bit/certs/ca.crt` to verify Server B's SSL certificate identity.
3. **HTTP Header Token Authentication (`X-Ingest-Token`)**:
   - Sends the 64-character pre-shared `INGEST_TOKEN` in every HTTP request header. Requests without a valid token are rejected with `HTTP 401 Unauthorized`.

---

## 🚀 Step-by-Step `INGEST_TOKEN` Provisioning & Startup

### 1. Prerequisites

* Ensure the Wazuh Manager stack is running on Server A, which creates the external volume `wazuh_logs`.
* Obtain the Root CA certificate (`ca.crt`) generated on Server B (Database Server).

---

### 2. Key & Certificate Configuration Script (`generate_keys.sh`)

The script configures TLS Root CA validation and sets the `INGEST_TOKEN` secret required to authenticate HTTP requests sent to Server B.

#### **Script CLI Options**
```text
Usage: bash generate_keys.sh [OPTIONS]

Options:
  --token, -t <TOKEN>         Specify the INGEST_TOKEN generated on Database Server
  --host, -h <HOST>           Specify the INGEST_HOST (Database Server IP/domain)
  --port, -p <PORT>           Specify the INGEST_PORT (default: 8080)
  --ca-cert, -c <PATH>        Path to Root CA Certificate (ca.crt) from Database Server
  --force, -f                 Force overwriting existing certs and configs
  --help                      Show this help message
```

#### **Provisioning Methods:**

#### **Method 1: Command-Line Flags (Recommended for Remote Deployment)**
Pass the token and optional Root CA certificate path directly:
```bash
bash generate_keys.sh \
  --token 7edf597441bc1d635d732d5174bd7dfd50df300b03b39b543849cf2d157fcdc6 \
  --host 192.168.1.50 \
  --ca-cert /path/to/ca.crt
```

#### **Method 2: Auto-Sync (Local Single-Host / Dev Deployments)**
If `wazuh_server` and `database_server` reside in the same repository tree (e.g., local development), simply run:
```bash
bash generate_keys.sh
```
The script will automatically detect `ca.crt` and extract `INGEST_TOKEN` from `database_server/.env`.

#### **Method 3: Interactive Prompt**
Run the script without arguments on a remote machine where `ca.crt` has been manually placed in `./certs/ca.crt`:
```bash
bash generate_keys.sh
```
```text
🔑 Enter INGEST_TOKEN generated on Database Server: 7edf597441bc1d635d732d5174bd7dfd50df300b03b39b543849cf2d157fcdc6
```

#### **Method 4: Manual `.env` Setup**
Copy `.env.example` to `.env` and configure variables manually:
```bash
cp .env.example .env
```
Edit `.env`:
```env
INGEST_HOST=192.168.1.50
INGEST_PORT=8080
INGEST_TOKEN=7edf597441bc1d635d732d5174bd7dfd50df300b03b39b543849cf2d157fcdc6
ENABLE_TLS=On
TLS_VERIFY=On
```

---

### 3. Startup & Verification

Start the Fluent-bit shipper service:
```bash
docker compose up -d --build
```

Check the shipping agent logs to verify successful HTTPS stream ingestion:
```bash
docker compose logs -f
```

---

## 🛑 Teardown & Maintenance

To stop the log forwarding agent:
```bash
docker compose down
```
