# LSMP Observability Stack (Grafana, Loki & SeaweedFS)

This directory contains the Docker Compose deployment, service configurations, and operational runbook for the centralized observability and logging infrastructure of the **LSMP** (Log-based Security Monitoring Platform) project.

---

## 🏛 System Architecture

The stack is designed with a distributed, microservices-oriented architecture to balance ingestion throughput, query efficiency, and storage economy:

```text
               +-------------------------------------------------------------+
               |                       Client / Shippers                     |
               +-------------------------------------------------------------+
                                              |
                                              | POST /loki/api/v1/push
                                              v
+------------------------+        +------------------------------------------+
|  Host & Container      |        |          gateway (Nginx:3100)            |
|  Telemetry (Alloy,     |        +------------------------------------------+
|  Node Exporter)        |               /                            \
+------------------------+              / (push)                       \ (query)
            |                          v                                v
            |                  +---------------+                +---------------+
            v                  |  write (Loki) |                |  read (Loki)  |
     +--------------+          +---------------+                +---------------+
     |  Prometheus  |                  \                               /
     +--------------+                   \                             /
            |                            v                           v
            |                      +---------------------------------------+
            |                      |   seaweedfs (S3 Storage API :8333)    |
            |                      +---------------------------------------+
            |                                          ^
            |                                          |
            v                                  +---------------+
+------------------------+                     | backend (Loki)|
|  grafana (Web UI:3000) |                     +---------------+
+------------------------+                       (Compactor)
```

* **Metrics Pipeline:** `node-exporter` (host system hardware) and `alloy` (container metrics) ➔ `prometheus` (time-series storage) ➔ `grafana` (visual dashboards).
* **Logs Pipeline:** Applications & Shippers ➔ `gateway` (Nginx reverse proxy) ➔ routes ingest requests to `write` (TSDB indexing & chunk generation) ➔ flushes chunks to `seaweedfs` (S3 object storage) ➔ `read` queries chunks and serves results to `grafana`.
* **Index & Compaction:** `backend` performs retention enforcement, table compaction, and deduplication directly against SeaweedFS.

---

## 📂 Directory Structure

```text
infrastructure/grafana_stack/
├── docker-compose.yaml              # Multi-container orchestration definition
├── .env.example                     # Environment variables template
├── README.md                        # Documentation and operational runbook
├── generate_certs.sh                # TLS certificate generator for Loki Gateway (Nginx :3100)
├── certs/                           # TLS certificates & Root CA for Loki Gateway
│   ├── ca.crt                       # Root CA certificate (distributed to clients)
│   ├── loki_gateway.crt             # Signed TLS server certificate
│   └── loki_gateway.key             # Private key for Nginx TLS termination
├── config/
│   ├── loki-config.yaml             # Distributed Loki cluster (Read/Write/Backend) & S3 storage configuration
│   ├── prometheus.yml               # Prometheus scrape job definitions (Node Exporter, Alloy)
│   ├── alloy-local-config.yaml      # Grafana Alloy container discovery via /var/run/docker.sock
│   ├── grafana-datasources.yaml     # Declarative datasource provisioning for Loki and Prometheus
│   └── nginx.conf                   # Nginx gateway reverse proxy and path-routing rules
└── dashboard/                       # Pre-provisioned Grafana dashboard definitions (JSON format):
    ├── status_cpu_ram_container.json # Container CPU, memory, and runtime resource utilization
    ├── auth_logs_dashboard.json      # Security authentication events and login audit tracking
    ├── lsmp_soc_overview.json        # High-level Security Operations Center (SOC) telemetry overview
    └── lsmp_model_evaluation.json    # Machine learning model inference and evaluation metrics
```

---

## 🌐 Services & Network Matrix

In accordance with the principle of least privilege, all internal cluster and storage communication is restricted to the internal Docker bridge network (`loki`). Only two services publish ports to the host machine:

| Service | Component Role | Host Port | Internal Port | Security & Access Policy |
|---|---|---|---|---|
| **gateway** | Nginx Reverse Proxy | `3100` | `3100` | **Public entry point** for shippers pushing logs via `/loki/api/v1/push` |
| **grafana** | Visualization UI | `3000` | `3000` | Web UI; anonymous access is locked to the read-only `Viewer` role |
| **read** | Query Frontend & Engine | *None* | `3100, 7946, 9095` | Internal only; handles LogQL queries dispatched by the gateway |
| **write** | Ingester & Distributor | *None* | `3100, 7946, 9095` | Internal only; ingests, batches, and flushes log chunks to storage |
| **backend** | Compactor & Index Gateway | *None* | `3100, 7946` | Internal only; handles TSDB compaction and retention lifecycle |
| **seaweedfs** | S3-Compatible Object Store | *None* | `8333, 9333` | Internal only; S3 API endpoint for log chunk persistence |
| **prometheus** | Time-Series Metrics DB | *None* | `9090` | Internal only; scraped targets and queried internally by Grafana |
| **node-exporter** | Host Metrics Collector | *None* | `9100` | Internal only; mounts host `/proc` and `/sys` in read-only mode |
| **alloy** | Telemetry Shipper | *None* | `12345` | Internal only; gathers logs directly from `/var/run/docker.sock` |

---

## 🔐 Environment Variables Contract (`.env`)

Before launching the stack, create a local `.env` configuration file from [.env.example](file://./.env.example):

| Variable | Description | Default / Example | Required? |
|---|---|---|---|
| `AWS_ACCESS_KEY_ID` | Access key for SeaweedFS S3 object storage authentication | `loki` | **Yes** |
| `AWS_SECRET_ACCESS_KEY` | Secret key for SeaweedFS S3 object storage authentication | `supersecret` *(change in production)* | **Yes** |
| `LOKI_VERSION` | Docker image tag for Grafana Loki | `3.0.0` | No |
| `GRAFANA_VERSION` | Docker image tag for Grafana Dashboard | `11.1.0` | No |
| `SEAWEEDFS_VERSION` | Docker image tag for SeaweedFS | `latest` | No |
| `PROMETHEUS_VERSION` | Docker image tag for Prometheus | `v2.51.1` | No |
| `NODE_EXPORTER_VERSION`| Docker image tag for Node Exporter | `v1.8.0` | No |
| `ALLOY_VERSION` | Docker image tag for Grafana Alloy | `v1.2.1` | No |
| `NGINX_VERSION` | Docker image tag for Nginx reverse proxy | `1.27.0-alpine` | No |

> [!IMPORTANT]
> The Loki services and SeaweedFS consume S3 credentials via a shared YAML anchor (`x-s3-env`) enforcing required interpolation: `${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}`. If either credential variable is unset or empty, Docker Compose will immediately abort startup.

---

## 🚀 Step-by-Step Deployment Guide

### Prerequisites
* **Docker Engine** version `24.0+`
* **Docker Compose** V2 (`docker compose`, not legacy `docker-compose`)
* Minimum available RAM: **2 GB**

### Step 1: Initialize Environment File
```bash
cd infrastructure/grafana_stack
cp .env.example .env
```
Edit `.env` to define secure S3 credentials:
```dotenv
AWS_ACCESS_KEY_ID=loki
AWS_SECRET_ACCESS_KEY=<your-secure-production-password>
```

### Step 2: Generate Loki Gateway TLS Certificates
Run the automated certificate generator to create Root CA and signed TLS server certificates:
```bash
bash generate_certs.sh
```
*Optional SAN options for multi-host deployments:*
```bash
bash generate_certs.sh --domain loki.yourdomain.com --extra-ip <SERVER_B_IP>
```

> [!NOTE]
> If Docker previously created the `certs/` directory with `root` ownership, ensure write permission before running:
> ```bash
> sudo chown -R $(id -u):$(id -g) certs
> ```

*Expected output:*
```text
=================================================================
🔒  LSMP SECURITY: GENERATING TLS CERTS FOR LOKI GATEWAY
=================================================================
🔑 [1/4] Generating new LSMP Root CA (certs/ca.key, certs/ca.crt)...
✅ Root CA generated at .../certs/ca.crt
🌐 [2/4] Auto-detecting host network addresses for SANs...
🔐 [3/4] Generating Loki Gateway Private Key (certs/loki_gateway.key)...
📝 Preparing Subject Alternative Names (SANs) configuration...
🛡️  Signing Loki Gateway Server Certificate (certs/loki_gateway.crt)...
Certificate request self-signature ok
subject=C=VN, ST=Hanoi, L=Hanoi, O=LSMP Security, OU=Grafana Loki Gateway, CN=gateway
🔍 [4/4] Verifying generated certificate against Root CA...
certs/loki_gateway.crt: OK
✅ Certificate chain is 100% VALID!
=================================================================
✅ LOKI GATEWAY TLS CERTIFICATES READY!
-----------------------------------------------------------------
📍 Certs Directory : .../grafana_stack/certs
📄 Server Cert     : .../grafana_stack/certs/loki_gateway.crt
🔑 Server Key      : .../grafana_stack/certs/loki_gateway.key
📜 Root CA Cert    : .../grafana_stack/certs/ca.crt
```

### Step 3: Start the Stack
Spin up all services in detached mode:
```bash
docker compose up -d
```

### Step 4: Verify Container Health
Verify that all services report an `Up` or `Up (healthy)` state:
```bash
docker compose ps
```

*Expected output:*
```text
NAME            SERVICE        STATUS
read            read           Up (healthy)
write           write          Up (healthy)
backend         backend        Up (healthy)
gateway         gateway        Up (healthy)
seaweedfs       seaweedfs      Up (healthy)
grafana         grafana        Up (healthy)
prometheus      prometheus     Up
node-exporter   node-exporter  Up
alloy           alloy          Up
```

### Step 5: Verify Endpoint Connectivity
* **Grafana Web UI:** Open `http://localhost:3000` in a web browser. Datasources for Loki and Prometheus are automatically provisioned.
* **Loki Gateway Health (HTTPS port 3100):**
  ```bash
  curl -k -s https://localhost:3100
  # Or with Root CA verification:
  curl --cacert certs/ca.crt -s https://localhost:3100
  ```
  *Expected response:* `OK`
* **Internal Fallback (HTTP port 3101):**
  ```bash
  curl -s http://localhost:3101
  ```
  *Expected response:* `OK`

### Step 6: Distribute Root CA to Clients
Clients pushing logs to Loki (such as Fluent-Bit Client on monitored SME hosts) require `certs/ca.crt` to verify the TLS gateway:
```bash
# Example copying to a remote monitored host:
scp certs/ca.crt user@<CLIENT_IP>:infrastructure/agent_stack/fluent-bit/client/certs/ca.crt
```

---

## 🧪 Verifying Log Ingestion (Testing Pipeline)

You can push a synthetic test log line directly through the TLS gateway to verify the write-to-storage pipeline:

```bash
curl -k -X POST https://localhost:3100/loki/api/v1/push \
  -H "Content-Type: application/json" \
  -H "X-Scope-OrgID: tenant1" \
  -d "{\"streams\":[{\"stream\":{\"job\":\"lsmp-manual-test\",\"env\":\"production\"},\"values\":[[\"$(date +%s)000000000\",\"Hello from LSMP manual log pipeline test!\"]]}]}"
```

**Verification Steps:**
1. The `curl` command should return HTTP `204 No Content` indicating successful ingestion.
2. Navigate to `http://localhost:3000` ➔ **Explore** ➔ Select the **Loki** datasource.
3. Execute the LogQL query:
   ```logql
   {job="lsmp-manual-test"}
   ```
4. The test log entry will be displayed in the query results panel.

---

## 🛠️ Operational Runbook (Day-2 Operations)

### Viewing Service Logs
```bash
# Stream live logs for all running containers
docker compose logs -f

# Stream logs for a specific service
docker compose logs -f gateway
docker compose logs -f write
docker compose logs -f seaweedfs
```

### Applying Configuration Updates
When modifying files in `config/` (such as `nginx.conf` or `loki-config.yaml`), reload the affected containers:
```bash
docker compose restart gateway
docker compose restart read write backend
```

### Safe Shutdown (Preserving Log Data)
To halt all containers without deleting persistent storage:
```bash
docker compose down
```
> [!NOTE]
> Persistent log chunks and index files are stored in the Docker volume `data_seaweedfs` and will remain intact across restarts.

### Complete Teardown & Storage Purge (⚠️ Data Loss)
```bash
docker compose down -v
```
> [!CAUTION]
> The `-v` flag permanently removes the `data_seaweedfs` volume. All stored logs and compaction metadata will be permanently erased.

---

## 🛠️ Common Troubleshooting

| Issue Symptom | Root Cause | Resolution |
|---|---|---|
| `generate_certs.sh` fails with `Permission denied` | Directory `certs/` was created by Docker with `root:root` ownership | Run `sudo chown -R $(id -u):$(id -g) certs` and re-run `bash generate_certs.sh --force`. |
| Nginx gateway fails: `cannot load certificate ... loki_gateway.crt` | Stack was started before generating certificates | Run `bash generate_certs.sh` to generate keys and certificates, then restart gateway: `docker compose up -d gateway`. |
| Fluent-Bit client TLS verification fails | Client does not have Loki's `ca.crt` or host IP is not in SANs | Copy `certs/ca.crt` to client's `certs/ca.crt`, and ensure `generate_certs.sh --extra-ip <SERVER_IP>` was used. |
| Port `3100` or `3000` already allocated | Existing service occupying host ports | Inspect conflicting process with `sudo lsof -i :3100` or `sudo ss -tulpn | grep 3100`. |

