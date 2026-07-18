# Wazuh SIEM Stack

This directory contains the Docker Compose configurations and environment files to deploy a single-node **Wazuh SIEM (Security Information and Event Management)** stack.

---

## 📂 Directory Structure

```text
infrastructure/wazuh_stack/
├── docker-compose.yml             # Main Wazuh stack (Manager, Indexer, Dashboard)
├── generate-indexer-certs.yml     # Cert generator service helper
├── README.md                      # This documentation file
└── config/                        # Security and service configuration mounts
    ├── certs.yml                  # Nodes certificate definition
    ├── wazuh_cluster/             # Wazuh manager cluster settings
    ├── wazuh_dashboard/           # Dashboard SSL/TLS config
    └── wazuh_indexer/             # OpenSearch/Indexer security configurations
```

---

## 🏛 Component Architecture

The stack consists of three major components communicating over secure TLS connections:

| Component                 | Container Name      | Default Ports                             | Description                                                                                             |
| :------------------------ | :------------------ | :---------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| **Wazuh Manager**   | `wazuh.manager`   | `1514/tcp`, `1515/tcp`, `55000/tcp` | Core manager receiving agent alerts, running decoding/rule matching engines, and hosting the Wazuh API. |
| **Wazuh Indexer**   | `wazuh.indexer`   | `9200/tcp`                              | High-performance search and analytics engine (OpenSearch) storing alerts and system events.             |
| **Wazuh Dashboard** | `wazuh.dashboard` | `443/tcp`                               | Web UI for threat detection analysis, visualization, and agent fleet monitoring.                        |

---

## 🚀 Deployment Guide

Follow these steps to generate certificates and launch the SIEM environment:

### 1. Prerequisites (Host Tuning)

Wazuh Indexer uses an embedded OpenSearch engine. You **must** increase the virtual memory mapping limit on your Linux host.

Run the following command as root (`sudo`):

```bash
sudo sysctl -w vm.max_map_count=262144
```

To make this setting permanent across system reboots, append the following line to `/etc/sysctl.conf`:

```text
vm.max_map_count=262144
```

### 2. Generate TLS Certificates

Wazuh components enforce TLS-only communications. Generate local certificates using the certs-generator container helper:

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

*This command creates node certificates in the `config/wazuh_indexer_ssl_certs/` directory and exits immediately.*

### 3. Start the Wazuh Stack

#### A. Run in the Foreground (for inspection/debugging)

```bash
docker compose -f docker-compose.yml up
```

#### B. Run in the Background (recommended for normal usage)

```bash
docker compose -f docker-compose.yml up -d
```

*Startup takes about 1-2 minutes on first run while the indexer initializes the core index pattern schemas.*

### 5. Accessing the Dashboard

Once the services are fully initialized and healthy:

1. Open your web browser and navigate to: `https://localhost` (Ignore the self-signed certificate warning).

---

## 🛑 Teardown & Maintenance

To stop and preserve the volume states:

```bash
docker compose -f docker-compose.yml down
```

To fully stop, destroy containers, and wipe local Docker configurations:

```bash
docker compose -f docker-compose.yml down -v
```
