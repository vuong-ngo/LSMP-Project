# LSMP Wazuh Endpoint Agent

This directory contains the Docker Compose configurations and OSSEC XML settings for deploying the **Wazuh Agent** on SME endpoint host machines to perform continuous host security monitoring, file integrity monitoring (FIM), system security configuration assessment (SCA), and rootkit checking.

---

## 📂 Directory Structure

```text
infrastructure/agent_stack/wazuh-agent/
├── docker-compose.yml       # Docker Compose service definition
├── .env.example             # Environment configurations template
└── config/
    └── wazuh-agent-conf     # Custom OSSEC agent configuration (ossec.conf)
```

---

## 🏛 Component Architecture

The Wazuh Agent runs as a background service on endpoint host machines:

| Component             | Container Name  | Protocol & Port    | Description                                                                                                 |
| :-------------------- | :-------------- | :----------------- | :---------------------------------------------------------------------------------------------------------- |
| **Wazuh Agent** | `wazuh.agent` | `1514/tcp` (AES) | Performs active log collection, FIM, SCA, and pushes encrypted security alerts to Wazuh Manager (Server A). |

---

## 🔒 Security Architecture

1. **AES Encryption (`<crypto_method>aes</crypto_method>`)**:
   - All network communication between the endpoint agent and Wazuh Manager (Server A) on port 1514 is encrypted using AES symmetric keys.
2. **Automated Agent Enrollment & Password Verification (`authd`)**:
   - Automated registration uses an enrollment password (`etc/authd.pass`) to ensure only authorized endpoints can enroll into the SIEM manager.
3. **File Integrity Monitoring (FIM)**:
   - Tracks real-time checksum alterations on critical system binaries (`/etc`, `/bin`, `/usr/bin`), alerting on unauthorized file modifications.

---

## 🚀 Getting Started

### 1. Environment Setup

Copy the environment configuration template:

```bash
cp .env.example .env
```

Open `.env` and specify the IP address of your central **Wazuh Manager (Server A)**:

```env
WAZUH_MANAGER_IP=127.0.0.1
WAZUH_MANAGER_PORT=1514
AGENT_NAME=endpoint-web-01
AGENT_GROUP=default
```

### 2. Startup

Start the Wazuh Agent container:

```bash
docker compose up -d --build
```

### 3. Verification

Check container logs to verify active connection to Wazuh Manager:

```bash
docker compose logs -f
```

---

## 🛑 Teardown

To stop the agent container:

```bash
docker compose down
```
