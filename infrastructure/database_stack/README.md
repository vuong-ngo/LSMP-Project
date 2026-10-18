# LSMP Database Stack

This directory contains the infrastructure configurations, database schema definitions, and security scripts for the PostgreSQL and TimescaleDB database layer of the LSMP project.

---

## 📂 Directory Structure

```text
infrastructure/database_stack/
├── docker-compose.yml             # Docker Compose service definition
├── .env.example                   # Environment variables template
├── schema.sql                     # SQL script for database initialization
├── grant_least_privilege.sql      # Security hardening: creates restricted wazuh_writer user
└── README.md                      # This documentation file
```

---

## 🏛 Component Architecture

| Component | Container Name | Default Ports | Description |
|---|---|---|---|
| **TimescaleDB** | `lsmp-postgres` | `5432/tcp` | PostgreSQL database with TimescaleDB extension for time-series logs and anomaly results storage. |

---

## 🏛 Database Schema Architecture

The database consists of **6 main tables** optimized for high-volume time-series security events and anomaly analysis.

### Hypertables (TimescaleDB Optimized)

* **`log_event`** — Raw security alert logs. Partitioned by day, compressed after 7 days, retained 90 days.
* **`feature_vectors`** — 14 computed security features per IP per window. Partitioned by day, compressed after 14 days, retained 180 days.
* **`anomaly_result`** — AI anomaly inference scores. Partitioned by week, compressed after 30 days, retained indefinitely for retraining.

### Regular Tables

* **`risk_score`** — Final aggregated risk priority scores (1-to-1 with anomaly_result).
* **`attack_scenarios`** — Metadata for attack simulation runs (ground-truth labeling).
* **`evaluation_metrics`** — AI model validation benchmarks (Precision, Recall, F1, latency).

---

## 🔧 What Was Changed in This Branch (`database_stack_fix`)

| Finding ID | File | Problem | Fix | Commit |
|---|---|---|---|---|
| DB-01 | `docker-compose.yml`, `.env.example` | Default `postgres:postgres` credentials used as fallback | Replaced with `${VAR:?error}` to force explicit config | `fix(database_stack): remove default credentials...` |
| DB-02 | `grant_least_privilege.sql` | `CREATE USER` inside DO block causes syntax error | Used `EXECUTE format()` for dynamic SQL | `fix(database_stack): fix SQL syntax error...` |
| DB-03 | `grant_least_privilege.sql` | Password hardcoded in SQL file | Password now from `current_setting()` with safe fallback | (included in DB-02 commit) |
| DB-04 | `docker-compose.yml` | `grant_least_privilege.sql` never auto-executed | Mounted as `02_grant_least_privilege.sql` in init dir | `fix(database_stack): remove default credentials...` |
| DB-05 | `docker-compose.yml` | No Docker resource limits | Added `deploy.resources.limits` (2 CPU, 2G RAM) | (included in DB-01 commit) |

---

## 🚀 Step-by-Step Deployment Guide

### Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- Minimum 2 GB RAM available for PostgreSQL

### Step 1: Create the shared Docker network

```bash
docker network create lsmp_backend
```

**Expected result:**
```
a1b2c3d4e5f6... (network ID hash)
```
If the network already exists, you'll see `Error: network with name lsmp_backend already exists` — this is fine.

---

### Step 2: Configure environment variables

```bash
cd infrastructure/database_stack
cp .env.example .env
```

Edit `.env` and set strong credentials:
```env
POSTGRES_USER=lsmp_admin
POSTGRES_PASSWORD=<your-strong-random-password>
POSTGRES_DB=lsmp_db
```

> ⚠️ **The container will REFUSE to start if `POSTGRES_USER` or `POSTGRES_PASSWORD` are not set.** This is intentional — there are no fallback defaults.

---

### Step 3: Start the database

```bash
docker compose up -d
```

**Expected result:**
```
[+] Running 2/2
 ✔ Volume "database_stack_postgresql_data"  Created
 ✔ Container lsmp-postgres                  Started
```

**Wait ~10-15 seconds** for initialization on first run. Check logs:
```bash
docker compose logs -f lsmp-postgres 2>&1 | head -30
```
**Expected output includes:**
```
LOG:  database system is ready to accept connections
NOTICE:  TimescaleDB hypertables, compression, and retention policies successfully initialized.
NOTICE:  Successfully applied Principle of Least Privilege: User wazuh_writer has INSERT-ONLY access.
```

---

### Step 4: Verify the database is healthy

```bash
docker compose ps
```

**Expected output:**
```
NAME            SERVICE        STATUS          PORTS
lsmp-postgres   lsmp-postgres   Up (healthy)   0.0.0.0:5432->5432/tcp
```

---

### Step 5: Verify schema was created

```bash
docker exec lsmp-postgres psql -U lsmp_admin -d lsmp_db -c "\dt"
```

**Expected output:**
```
               List of relations
 Schema |        Name         | Type  |   Owner
--------+---------------------+-------+------------
 public | anomaly_result      | table | lsmp_admin
 public | attack_scenarios    | table | lsmp_admin
 public | evaluation_metrics  | table | lsmp_admin
 public | feature_vectors     | table | lsmp_admin
 public | log_event           | table | lsmp_admin
 public | risk_score          | table | lsmp_admin
(6 rows)
```

---

### Step 6: Verify wazuh_writer user was created

```bash
docker exec lsmp-postgres psql -U lsmp_admin -d lsmp_db -c "SELECT rolname FROM pg_roles WHERE rolname = 'wazuh_writer';"
```

**Expected output:**
```
   rolname
--------------
 wazuh_writer
(1 row)
```

---

### Step 7: Verify wazuh_writer has INSERT-ONLY access

```bash
docker exec lsmp-postgres psql -U lsmp_admin -d lsmp_db -c "SELECT privilege_type FROM information_schema.table_privileges WHERE grantee = 'wazuh_writer' AND table_name = 'log_event';"
```

**Expected output:**
```
 privilege_type
----------------
 INSERT
 SELECT
(2 rows)
```

---

### Step 8: Verify resource limits

```bash
docker stats --no-stream lsmp-postgres
```

**Expected output:**
```
CONTAINER ID   NAME            CPU %   MEM USAGE / LIMIT   ...
abc123...      lsmp-postgres   0.50%   128MiB / 2GiB       ...
```

MEM LIMIT should show `2GiB`.

---

## 🛑 Teardown & Maintenance

Stop and preserve data:
```bash
docker compose down
```

Stop and wipe all data:
```bash
docker compose down -v
```

---

## ⚠️ Impact and Risks

| Change | Impact | Risk |
|---|---|---|
| DB-01: No default credentials | Container won't start without `.env` | Intentional — prevents accidental weak-credential deployments |
| DB-02: Dynamic SQL for user creation | `grant_least_privilege.sql` now executes correctly | Low — fixes a breaking bug |
| DB-04: Auto-execute privilege script | `wazuh_writer` user is created automatically on first init | Only runs on fresh database (docker-entrypoint-initdb.d behavior) |
| DB-05: Resource limits | PostgreSQL constrained to 2 CPU / 2G RAM | Must align with PostgreSQL memory settings (shared_buffers=512MB fits within 2G) |

---

## 📋 Known Issues / Not Fixed

No findings were rejected. All 5 findings were implemented.
