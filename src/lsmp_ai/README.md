# 🛡️ LSMP AI Anomaly Detection & Risk Scoring Engine (`src/lsmp_ai`)

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pytest Status](https://img.shields.io/badge/pytest-61%20passed-brightgreen.svg)]()

`lsmp_ai` is the core Artificial Intelligence, Real-Time Risk Scoring, and Security Operations package of the **Log Security Monitoring Platform (LSMP)**. It provides a modular, high-throughput engine that ingests security log events (e.g., Wazuh alerts or system logs), extracts 14 security-focused feature vectors, performs two-stage cascade anomaly detection (Isolation Forest $\rightarrow$ One-Class SVM), calculates real-time composite risk scores, and persists threat predictions to PostgreSQL / TimescaleDB.

---

## 📌 Table of Contents

- [📐 Package Architecture & Submodule Breakdown](#-package-architecture--submodule-breakdown)
- [🛠️ 14 Security Feature Vector Specification](#️-14-security-feature-vector-specification)
- [🧠 Two-Stage Cascade Model & Risk Calculation](#-two-stage-cascade-model--risk-calculation)
- [💻 CLI Commands Reference](#-cli-commands-reference)
- [⚙️ Serving Engine & Background Daemons](#️-serving-engine--background-daemons)
- [🔒 Security & Cryptographic Verifications](#-security--cryptographic-verifications)
- [🔬 Verification & Unit Testing](#-verification--unit-testing)

---

## 📐 Package Architecture & Submodule Breakdown

The `lsmp_ai` package is organized into modular components:

```text
src/lsmp_ai/
├── cli.py               # Global CLI command entrypoint (`lsmp-ai`)
├── version.py           # Engine version metadata
├── common/              # System utilities, YAML config loaders, logging, exceptions, security, constants
├── io/                  # Data access layer: DBClient (PostgreSQL/TimescaleDB), DataLoader, ResultWriter
├── feature_engineering/ # 14 security-oriented time-series feature extractors & pipeline
├── models/              # IsolationForest, OCSVM, CascadeModel, ModelRegistry, GridSearch
├── risk_scoring/        # Composite Risk Scoring Engine (AI Score + Wazuh Severity) & Classifier
├── evaluation/          # Ablation studies, classification metrics, significance testing, benchmark runner
├── serving/             # Real-time inference daemon, FastAPI async writer engine, polling scheduler
└── scripts/             # Internal executable sub-routines (train, serve, evaluate, status)
```


### Key Technical Features

1. **Two-Stage Cascade AI Model (`CascadeModel`)**:
   - **Stage 1 (Isolation Forest)**: Rapidly filters obvious normal and obvious anomalous events using learned percentile routing thresholds.
   - **Stage 2 (One-Class SVM)**: Evaluates samples in the *Uncertainty Zone* passed from Stage 1, significantly lowering false positive rates while maintaining high execution speed.

2. **Composite Risk Scoring Formula**:
   - Combines unsupervised machine learning anomaly probability with rule-based severity from SIEM alerts:
     $$\text{Risk Score} = 100 \times \left( \alpha \times \text{Anomaly Score} + \beta \times \frac{\min(\max(\text{Severity}, 0), 15)}{15} \right)$$
   - Where default weights are $\alpha = 0.6$ (60% AI weight) and $\beta = 0.4$ (40% Rule weight). Categorized into **Low** ($<30$), **Medium** ($30-60$), **High** ($60-85$), and **Critical** ($85-100$).

3. **Relational Data Integrity & Foreign Key Linking**:
   - Preserves UUID identifiers across storage tables: `log_event` $\rightarrow$ `feature_vectors(id)` $\rightarrow$ `anomaly_result(feature_vector_id)` $\rightarrow$ `risk_score(anomaly_result_id)`.

4. **Non-Blocking Async Serving Engine**:
   - FastAPI server offloads time-series database batch inference to worker thread pools (`asyncio.to_thread`), ensuring HTTP health checks (`/health`) and management endpoints (`/process`, `/metadata`) remain responsive with under 5ms latency.

---

## 🛠️ 14 Security Feature Vector Specification

The feature extraction module (`extract_features_from_logs` / `FeaturePipeline`) generates 14 time-window features per source IP address (`src_ip`):

| # | Feature Name | Analytical Focus | Description |
|---|---|---|---|
| 1 | `auth_fail_count` | Auth Domain | Number of failed authentication attempts in time window |
| 2 | `auth_success_count` | Auth Domain | Number of successful authentication attempts in time window |
| 3 | `auth_fail_ratio` | Auth Domain | Ratio of failed logins: $F / (F + S)$ bounded in $[0, 1]$ |
| 4 | `distinct_username` | Auth Domain | Number of distinct usernames targeted |
| 5 | `fail_interarrival_mean` | Auth Domain | Mean seconds between consecutive auth failure events |
| 6 | `fail_interarrival_std` | Auth Domain | Standard deviation of seconds between auth failure events |
| 7 | `http_req_rate` | HTTP Domain | Average HTTP/Web request rate per second ($N / \Delta t$) |
| 8 | `http_4xx_ratio` | HTTP Domain | Ratio of HTTP 4xx client errors (directory fuzzing/scanning) |
| 9 | `http_5xx_ratio` | HTTP Domain | Ratio of HTTP 5xx server errors (exploitation/crash) |
| 10 | `http_post_ratio` | HTTP Domain | Ratio of HTTP POST requests (credential stuffing/form brute-force) |
| 11 | `distinct_user_agent` | HTTP Domain | Number of unique User-Agent strings observed |
| 12 | `bytes_sent_mean` | HTTP Domain | Mean response bytes sent across requests |
| 13 | `global_active_ips` | Context Domain | Count of unique active source IPs across monitored network window |
| 14 | `burst_rate` | Context Domain | Ratio of max 1-second burst count to average count per second |

---

## 🧠 Two-Stage Cascade Model & Risk Calculation

### Routing Protocol Architecture

```text
               ┌────────────────────────┐
               │    14-Feature Input    │
               └───────────┬────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ Stage 1: Isolation Forest│
              └────────────┬─────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │ (Score < Safe)  │ (Uncertain Zone)│ (Score > Danger)
         ▼                 ▼                 ▼
   ┌───────────┐   ┌───────────────┐   ┌───────────┐
   │  NORMAL   │   │ Stage 2: OCSVM│   │  ANOMALY  │
   └───────────┘   ┌───────┬───────┘   └───────────┘
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
            ┌───────────┐     ┌───────────┐
            │  NORMAL   │     │  ANOMALY  │
            └───────────┘     └───────────┘
```

The model loads hyperparameters from `configs/model_config.yaml` or `.env`. Trained artifacts are serialized with joblib metadata into `models_store/` and tracked in `models_store/catalog.json`.

---

## 💻 CLI Commands Reference

The `lsmp_ai` package provides the `lsmp-ai` command-line suite:

### Available Subcommands

```bash
# 1. Inspect status, thresholds, and DB connectivity
lsmp-ai status

# 2. Train Two-Stage Cascade AI model with optional Grid Search
lsmp-ai train --test-size 0.3 --model-version cascade-v1.0 --grid-search

# 3. Manage real-time continuous serving daemon
lsmp-ai serve start --interval 10 --lookback 60
lsmp-ai serve status
lsmp-ai serve stop

# 4. List registered AI models in models_store catalog
lsmp-ai models

# 5. Show live Device Risk Index (DRI) report across monitored hosts
lsmp-ai threat-summary

# 6. Execute model ablation evaluation benchmark & statistical significance test
lsmp-ai evaluate --runs 5 --full-ablation --output reports/ablation_study.csv

# 7. Synchronize model catalog and metrics to PostgreSQL / TimescaleDB
lsmp-ai export-db

# 8. Display package specifications
lsmp-ai version
```

---

## ⚙️ Serving Engine & Background Daemons

The package supports two modes of operational serving:

### Mode 1: CLI Background Daemon (`lsmp-ai serve`)
Runs a lightweight, continuous polling loop in the background:
- Verifies database connectivity and table schemas before launching.
- Records PID into `logs/service.pid` (enforced `0o600` permissions).
- Polls new log batches every `interval` seconds, computes 14-D features, executes cascade classification, and writes predictions directly to database.
- Verifies process identity via cmdline before executing graceful `stop`.

### Mode 2: FastAPI Writer Service (`lsmp_writer_service`)
High-concurrency ASGI REST server (`uvicorn`):
- **`/health`**: Minimal unauthenticated health check probe for container orchestrators.
- **`/metadata`**: Authenticated inspection of model version, hyper-parameters, and thresholds.
- **`/process`**: Authenticated trigger for ad-hoc batch processing runs over specified time windows.
- **Authentication**: Fail-closed API key verification (`X-API-Key` header).
- **Rate Limiting**: Sliding window rate limiter with LRU memory eviction and optional reverse proxy header parsing (`X-Forwarded-For`).

---

## 🔒 Security & Cryptographic Verifications

- **Cryptographic Artifact Integrity (S2)**: Streaming SHA-256 validation of `.joblib` model binaries against recorded digests in `manifest.json` prior to `joblib.load()` to prevent Remote Code Execution (RCE).
- **Fail-Closed API Authentication (S1)**: Insecure defaults trigger HTTP 500 configuration errors rather than opening public access.
- **Safe Database Interaction (S3, S6, S7, S8)**:
  - Whitelist-only SQL table name validation.
  - Parameterized queries for values.
  - Sanitization of connection strings and passwords in logs and exception messages.
  - Elimination of silent network auto-discovery probing.
- **Log Rotation & Permissions (S9, S10)**:
  - Bounded log file rotation (`RotatingFileHandler`).
  - Restricted file permissions (`0o640` for logs/artifacts, `0o600` for PID, `0o750` for directories).

---

## 🔬 Verification & Unit Testing

The `lsmp_ai` package is verified by an extensive automated test suite covering features, cascade models, risk scoring, serving logic, CLI subcommands, cryptographic integrity, and database clients.

Run unit tests:

```bash
pytest -v
```

**Status**: **61 PASSED**, 0 failed, 0 errors.

