# LSMP Grafana & Loki Stack

This directory contains the Docker Compose configuration, Grafana dashboards provisioning, and Loki service configuration for the log storage and visualization layer of the LSMP project.

---

## 📂 Directory Structure

```text
infrastructure/grafana_stack/
├── docker-compose.yaml       # Docker Compose service definition
├── .env.example              # Environment variables template
└── config/                   # Configuration directory
    └── loki-config.yaml      # Grafana Loki distributed service configuration
```

---

## 🏛 Distributed Log Architecture

The log ingestion and querying system is built on a distributed **Grafana Loki** setup behind an Nginx reverse proxy gateway, backed by a **MinIO** object storage cluster.

### 1. Core Services

*   **`gateway` (Nginx Ingress)**
    *   **Description**: Acts as the reverse proxy entrypoint on host port `3100`.
    *   **Routing Logic**:
        *   Ingestion requests (`/loki/api/v1/push`) are routed to the **`write`** service.
        *   Query and tailing requests (`/loki/api/v1/tail`, `/loki/api/v1/query`) are routed to the **`read`** service.
*   **`write` (Ingester & Indexing)**
    *   **Description**: Validates, indexes, and batches incoming log lines, then flushes them to the object storage.
*   **`read` (Query Frontend)**
    *   **Description**: Executes LogQL queries, handles log chunk lookup, and aggregates query results.
*   **`backend` (Compactor & Index Store)**
    *   **Description**: Manages backend processes such as indexing storage and compaction of log chunks.
*   **`minio` (Object Storage)**
    *   **Description**: S3-compatible backend storage containing buckets `loki-data` and `loki-ruler` for storing log chunks and index schemas.

### 2. Visualization & Testing

*   **`grafana` (Visualization Dashboard)**
    *   **Description**: Provides the analytical UI. Automatically provisions Loki (`http://gateway:3100`) as a default datasource.
*   **`flog` (Log Generator)**
    *   **Description**: A testing utility that streams mock JSON log streams into the Loki environment to verify pipeline throughput and query correctness.

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Docker and Docker Compose (v2+) installed on your machine.

### 2. Configuration
Copy the environment variables template and configure the storage credentials:
```bash
cp .env.example .env
```

Open the `.env` file and set the MinIO root credentials:
```env
# MinIO root access configurations
MINIO_ROOT_USER=loki
MINIO_ROOT_PASSWORD=supersecret
```

### 3. Startup & Operations

#### A. Start the Stack
To launch all services in detached mode:
```bash
docker compose up -d
```
*Docker Compose will initialize the networks, start MinIO first, health-check it, and spin up Loki read/write targets, Nginx gateway, and Grafana.*

#### B. Accessing the Services
Once all services are healthy, you can access the following endpoints:
*   **Grafana Dashboard**: `http://localhost:3000` (Pre-configured with Loki datasource, bypasses login as Admin by default).
*   **Loki Gateway API**: `http://localhost:3100` (Endpoint for shippers such as Fluent-bit to push logs).
*   **Loki Read Target**: `http://localhost:3101`
*   **Loki Write Target**: `http://localhost:3102`

#### C. Stop the Stack
To stop the services and retain data in MinIO volumes:
```bash
docker compose down
```

To stop the services and wipe the persistent storage:
```bash
docker compose down -v
```
