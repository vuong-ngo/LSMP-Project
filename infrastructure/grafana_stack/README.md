# LSMP Grafana & Loki Stack

This directory contains the Docker Compose configuration, Grafana dashboards, and Loki service configuration for the log storage and visualization layer of the LSMP project.

---

## 📂 Directory Structure

```text
infrastructure/grafana_stack/
├── docker-compose.yaml              # Docker Compose service definition
├── .env.example                     # Environment variables template
├── README.md                        # This documentation file
├── config/
│   ├── loki-config.yaml             # Grafana Loki distributed service configuration
│   ├── prometheus.yml               # Prometheus scrape configuration
│   ├── alloy-local-config.yaml      # Grafana Alloy telemetry config
│   ├── grafana-datasources.yaml     # Grafana datasource provisioning (Loki + Prometheus)
│   └── nginx.conf                   # Nginx reverse proxy gateway configuration
└── dashboard/
    ├── status_cpu_ram_container.json # Container resource monitoring dashboard
    ├── auth_logs_dashboard.json      # Authentication logs dashboard
    ├── lsmp_soc_overview.json        # SOC overview dashboard
    └── lsmp_model_evaluation.json    # AI model evaluation dashboard
```

---

## 🏛 Distributed Log Architecture

The log ingestion and querying system is built on a distributed **Grafana Loki** setup behind an Nginx reverse proxy gateway, backed by **MinIO** object storage.

| Service | Role | Exposed Port |
|---|---|---|
| **gateway** (Nginx) | Reverse proxy entry point, routes push→write, query→read | `3100` (host) |
| **write** | Ingests, indexes, and batches incoming log lines | Internal only |
| **read** | Executes LogQL queries and aggregates results | Internal only |
| **backend** | Manages compaction and index storage | Internal only |
| **minio** | S3-compatible storage for log chunks | Internal only |
| **grafana** | Visualization dashboard with Loki + Prometheus datasources | `3000` (host) |
| **prometheus** | Metrics scraping and storage | Internal only |
| **node-exporter** | Host system metrics collector | Internal only |
| **alloy** | Grafana telemetry agent | Internal only |
| **flog** | Mock JSON log generator for testing | Internal only |

---

## 🔧 What Was Changed in This Branch (`grafana_stack_fix`)

| Finding ID | File | Problem | Fix | Commit |
|---|---|---|---|---|
| GRAF-01 | `docker-compose.yaml` | Anonymous users get full Admin role | Changed to `Viewer` role | `fix(grafana_stack): downgrade anonymous access...` |
| GRAF-02 | `docker-compose.yaml` | Internal service ports exposed to host | Replaced `ports` with `expose` for all internal services | `fix(grafana_stack): downgrade anonymous access...` |
| GRAF-03 | `docker-compose.yaml`, `config/` | Grafana datasource + Nginx config inline in entrypoint | Extracted to `config/grafana-datasources.yaml` and `config/nginx.conf` | `refactor(grafana_stack): extract inline configs...` |
| GRAF-04 | `docker-compose.yaml` | Inconsistent restart policies | Added `restart: unless-stopped` to all services | `fix(grafana_stack): downgrade anonymous access...` |

---

## 🚀 Step-by-Step Deployment Guide

### Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- At least 2 GB RAM available

### Step 1: Configure environment variables

```bash
cd infrastructure/grafana_stack
cp .env.example .env
```

Edit `.env` and set custom MinIO credentials:
```env
MINIO_ROOT_USER=loki
MINIO_ROOT_PASSWORD=<your-strong-password>
```

**Expected result:** `.env` file created with custom credentials.

---

### Step 2: Start the stack

```bash
docker compose up -d
```

**Expected result:**
```
[+] Running 10/10
 ✔ Volume "grafana_stack_data_minio"  Created
 ✔ Container minio                    Started
 ✔ Container read                     Started
 ✔ Container write                    Started
 ✔ Container gateway                  Started
 ✔ Container backend                  Started
 ✔ Container grafana                  Started
 ✔ Container prometheus               Started
 ✔ Container node-exporter            Started
 ✔ Container alloy                    Started
```

MinIO starts first, then Loki read/write, then gateway, then Grafana.

---

### Step 3: Verify all services are healthy

```bash
docker compose ps
```

**Expected result:** All containers show `Up` or `Up (healthy)`. No containers in `Restarting` state.

```
NAME            SERVICE        STATUS
minio           minio          Up (healthy)
read            read           Up (healthy)
write           write          Up (healthy)
gateway         gateway        Up (healthy)
grafana         grafana        Up (healthy)
backend         backend        Up (healthy)
prometheus      prometheus     Up
node-exporter   node-exporter  Up
alloy           alloy          Up
flog            flog           Up
```

---

### Step 4: Verify Grafana is accessible

```bash
curl -s http://localhost:3000/api/health | python3 -m json.tool
```

**Expected result:**
```json
{
    "commit": "...",
    "database": "ok",
    "version": "11.1.0"
}
```

---

### Step 5: Verify anonymous access is Viewer-only

Open `http://localhost:3000` in an **incognito browser window**.

**Expected result:**
- ✅ Dashboards load and are viewable
- ✅ No admin gear icon in the sidebar
- ❌ Cannot access Admin → Server Admin
- ❌ Cannot create or modify datasources
- ❌ Cannot create users or change org settings

---

### Step 6: Verify Loki gateway is responding

```bash
curl -s http://localhost:3100
```

**Expected result:**
```
OK
```

---

### Step 7: Verify internal ports are NOT exposed to host

```bash
ss -tlnp | grep -E '9090|9100|9000|12345|3101|3102'
```

**Expected result:** **NO output** — none of these ports should be listening on the host. Only `3000` (Grafana) and `3100` (gateway) are exposed.

---

### Step 8: Verify datasources are provisioned

```bash
curl -s http://localhost:3000/api/datasources | python3 -m json.tool
```

**Expected result:** Returns JSON array with `Loki` and `Prometheus` datasources:
```json
[
    {
        "name": "Loki",
        "type": "loki",
        "url": "http://gateway:3100",
        ...
    },
    {
        "name": "Prometheus",
        "type": "prometheus",
        "url": "http://prometheus:9090",
        ...
    }
]
```

---

### Step 9: Test log ingestion (optional)

Send a test log to Loki via the gateway:

```bash
curl -X POST http://localhost:3100/loki/api/v1/push \
  -H "Content-Type: application/json" \
  -H "X-Scope-OrgID: tenant1" \
  -d '{"streams":[{"stream":{"job":"test"},"values":[["'$(date +%s)000000000'","hello from LSMP test"]]}]}'
```

**Expected result:** HTTP 204 (No Content) — the log was accepted.

**Verify in Grafana:**
1. Open `http://localhost:3000` → Explore → Select Loki datasource
2. Query: `{job="test"}`
3. **Expected:** Shows "hello from LSMP test" log entry.

---

## 🛑 Teardown & Maintenance

Stop and preserve data:
```bash
docker compose down
```

Stop and wipe all persistent storage:
```bash
docker compose down -v
```

---

## ⚠️ Impact and Risks

| Change | Impact | Risk |
|---|---|---|
| GRAF-01: Viewer role | Anonymous users can view dashboards but cannot modify anything | Users needing admin must log in with credentials |
| GRAF-02: Internal ports hidden | Prometheus (9090), Node-Exporter (9100), MinIO (9000) no longer on host | External tools accessing these ports directly will break — use Grafana or Docker network instead |
| GRAF-03: External config files | Config changes no longer require modifying docker-compose.yaml | None — improves maintainability |
| GRAF-04: Restart policies | All services auto-restart after Docker daemon restart | None — best practice |

---

## 📋 Known Issues / Not Fixed

No findings were rejected. All 4 findings were implemented.
