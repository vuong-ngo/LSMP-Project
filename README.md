# 🛡️ LSMP: Log Security Monitoring & Threat Detection Platform

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.140-009688.svg)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/TimescaleDB-PostgreSQL%2015-336791.svg)](https://www.timescale.com/)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.x-0052CC.svg)](https://wazuh.com/)
[![Pytest Status](https://img.shields.io/badge/pytest-73%20passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **LSMP (Log Security Monitoring Platform)** is an enterprise-grade AI-powered Cyber Security Monitoring and Intrusion Detection Platform. It bridges traditional static SIEM rule enforcement (**Wazuh**) with a high-performance **Two-Stage Cascade Machine Learning Engine (Isolation Forest $\rightarrow$ One-Class SVM)** to deliver real-time anomaly detection, dynamic threat classification, and composite risk scoring across monitored infrastructure.

---

## 📌 Table of Contents

- [🌟 Key Features](#-key-features)
- [🧠 AI Engine & Two-Stage Cascade Model](#-ai-engine--two-stage-cascade-model)
- [🧮 Composite Risk Scoring Model](#-composite-risk-scoring-model)
- [📊 Dataset Preparation & Production Log Pipelines](#-dataset-preparation--production-log-pipelines)
- [🛠️ Tech Stack & Infrastructure](#️-tech-stack--infrastructure)
- [📁 Directory & Project Structure](#-directory--project-structure)
- [🚀 Installation & Setup Guide](#-installation--setup-guide)
- [💻 Command-Line Interface (CLI) Usage](#-command-line-interface-cli-usage)
- [⚙️ Service Management & Background Daemons](#️-service-management--background-daemons)
- [🧪 Attack Simulation & Verification Tools](#-attack-simulation--verification-tools)
- [🔬 Testing & Quality Assurance](#-testing--quality-assurance)
- [📄 License](#-license)

---

## 🌟 Key Features

- **Real-Time Dual Log Ingestion**: High-throughput log collection from host agents (Wazuh & Fluent-Bit) streaming directly into Redis Stream queues and TimescaleDB hypertables.
- **14-Dimensional Security Feature Extraction**: Dynamic aggregation of host authentication (SSH/Auth), Web HTTP traffic, and behavioral pattern metrics across sliding time windows per source IP.
- **Two-Stage Cascade Anomaly Detection (iForest $\rightarrow$ OCSVM)**:
  - **Stage 1 (Isolation Forest)**: Rapidly classifies obvious normal traffic and severe anomaly spikes.
  - **Stage 2 (One-Class SVM)**: Focuses on the *Uncertainty Zone* (borderline boundary samples) to eliminate false positives and catch zero-day intrusions.
- **Composite Risk Scoring Engine**: Calculates real-time threat scores ($0-100$) combining AI anomaly confidence ($60\%$) with Wazuh SIEM rule severity ($40\%$), categorized into 4 risk tiers (**Low**, **Medium**, **High**, **Critical**).
- **Production CLI (`lsmp-ai`)**: Global CLI interface for model training, serving daemon controls, catalog inspection, healthcheck, and research benchmarks.
- **Auto-Retraining & Model Versioning**: Automated background daemons for periodic model updates and persistent catalog registry in `models_store/`.
- **Time-Series Optimization**: Hypertable partitioning, metric compression policies, and automated retention management powered by TimescaleDB / PostgreSQL.
- **Integrated Security Attack Simulators**: Built-in scripts for testing SSH brute-force attacks and generating synthetic Wazuh SIEM alerts.

---

## 🧠 AI Engine & Two-Stage Cascade Model

The LSMP AI core ([`src/lsmp_ai`](file:///home/ngoducvuong/Documents/Projects/up/LSMP-Project/src/lsmp_ai)) extracts 14 dynamic security features grouped into 3 analytical domains (Auth, HTTP, and Context):

| Analytical Domain | Feature Name | Description |
| :--- | :--- | :--- |
| 🔑 **Auth Domain** | `auth_fail_count`<br/>`auth_success_count`<br/>`auth_fail_ratio`<br/>`distinct_username`<br/>`fail_interarrival_mean`<br/>`fail_interarrival_std` | Tracks authentication failures, successful logins, failure-to-total ratio, targeted distinct usernames, and temporal interarrival statistics. |
| 🌐 **HTTP Domain** | `http_req_rate`<br/>`http_4xx_ratio`<br/>`http_5xx_ratio`<br/>`http_post_ratio`<br/>`distinct_user_agent`<br/>`bytes_sent_mean` | Monitors Web/Nginx request velocity, client error ratio (fuzzing/probing), server error ratio, POST payload ratio, unique User-Agents, and outbound payload sizes. |
| 📊 **Context Domain** | `global_active_ips`<br/>`burst_rate` | Global concurrency context across monitored network and localized short-term event burst intensity. |

### Two-Stage Cascade Routing Protocol

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

1. **Stage 1 (Isolation Forest)**: Quickly screens input features. Clear normal traffic (below safe threshold) and severe anomaly spikes (above danger threshold) are resolved instantly.
2. **Stage 2 (One-Class SVM)**: Takes borderline samples falling into the *Uncertainty Zone* between thresholds and evaluates them against fine-grained boundary hyperplanes to eliminate false alarms.

---

## 🧮 Composite Risk Scoring Model

The overall threat risk score ($\text{RiskScore} \in [0, 100]$) combines machine learning anomaly probabilities with static Wazuh SIEM rule severity levels ($0-15$):

$$
\text{RiskScore} = 100 \times \left( 0.6 \times \text{AIScore} + 0.4 \times \frac{\min(\max(\text{WazuhSeverity}, 0), 15)}{15} \right)
$$

### Threat Level Classification Matrix

| Risk Score Range | Severity Level | Operational Impact & System Action |
| :---: | :---: | :--- |
| $0 \le \text{Score} < 25$ | 🟢 **LOW** | Normal activity. Logged for standard audit trails. |
| $25 \le \text{Score} < 50$ | 🟡 **MEDIUM** | Minor anomaly detected. Flagged for analyst review. |
| $50 \le \text{Score} < 80$ | 🟠 **HIGH** | Significant security threat. High-priority alert triggered. |
| $80 \le \text{Score} \le 100$ | 🔴 **CRITICAL** | Urgent intrusion alert. Active defense / mitigation recommended. |

---

## 🛠️ Tech Stack & Infrastructure

- **Programming Language**: Python 3.12+
- **Machine Learning & Analytics**: Scikit-Learn 1.3+, Pandas, NumPy, Joblib
- **API & Web Framework**: FastAPI, Uvicorn (ASGI), Pydantic v2
- **CLI Framework**: Python Argparse with ANSI terminal styling
- **Databases & Queues**: PostgreSQL 15, TimescaleDB, Redis 7 (Stream Queue)
- **SIEM & Forwarding**: Wazuh 4.x (Manager & Host Agent), Fluent-Bit
- **Containerization**: Docker & Docker Compose

---

## 📁 Directory & Project Structure

```text
LSMP-Project/
├── .env.example             # Template configuration file for environment variables
├── Dockerfile               # Production Docker container definition for LSMP AI Engine
├── docker-compose.yml       # Docker Compose service stack definition
├── install.sh               # Standalone 1-click automated installer script
├── pyproject.toml           # Package build configuration & dependencies
├── requirements.txt         # Pip dependency requirements
│
├── configs/                 # System YAML configurations (model & engine specs)
├── data/                    # Datasets (raw, interim, and processed CSV files)
├── infrastructure/          # Stacks for Database, Redis, Wazuh, and Grafana
├── models_store/            # Versioned trained AI model registry & catalog.json
├── reports/                 # Evaluation reports & benchmark CSV outputs
├── scripts/                 # Multi-source dataset preparation (prepare_data.py)
├── src/
│   └── lsmp_ai/             # Core LSMP AI Detection Engine Package
│       ├── cli.py           # Global Typer CLI entrypoint (`lsmp-ai`)
│       ├── common/          # Utilities, config loaders, loggers, and constants
│       ├── evaluation/      # Model benchmarks, metrics, and ablation logic
│       ├── feature_engineering/ # 14-dimensional security feature extraction
│       ├── io/              # Database client, data loaders, and result writers
│       ├── models/          # Isolation Forest, OCSVM & Cascade model classes
│       ├── risk_scoring/    # Composite risk calculation & threat classification
│       ├── serving/         # Serving daemon, FastAPI async writer & batch inference
│       └── scripts/         # Core execution subroutines (train, evaluate, serve, status)
├── tests/                   # Pytest automated test suite
└── tools/                   # Security simulators (SSH brute-force & log generators)
```

---

## 🚀 Installation & Setup Guide

### Method 1: Standalone Automated Setup (Recommended)

Run the automated installer script to prepare virtual environments, dependencies, system configurations, and symlink binary executables (`lsmp-ai`):

```bash
chmod +x install.sh
./install.sh
```

### Method 2: Manual Installation

```bash
# 1. Clone the repository
git clone https://github.com/vuong-ngo/LSMP-Project.git
cd LSMP-Project

# 2. Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install project dependencies in editable mode
pip install -e ".[all]"

# 4. Initialize environment configuration
cp .env.example .env
```

### Method 3: Containerized Docker Deployment

To launch the containerized LSMP engine alongside database and Redis infrastructure:

```bash
docker compose up -d --build
```

---

---

## 💻 Command-Line Interface (CLI) Usage

LSMP features a unified, production-ready CLI (`lsmp-ai`) with standard POSIX arguments, ANSI color formatting, and subcommands for the complete AI lifecycle.

### Global CLI Subcommands Overview

| Command | Action | Key Arguments |
| :--- | :--- | :--- |
| `lsmp-ai status` | Inspect model parameters, thresholds, DB tables, and daemon state | None (alias: `healthcheck`) |
| `lsmp-ai train` | Train the Two-Stage Cascade model (iForest + OCSVM) | `--dataset`, `--model-version`, `--test-size`, `--grid-search` |
| `lsmp-ai serve` | Manage real-time continuous AI detection daemon | `start`, `stop`, `status`, `--interval`, `--lookback` |
| `lsmp-ai evaluate` | Execute ablation study, compute metrics & benchmark inference | `--dataset`, `--output`, `--runs`, `--full-ablation`, `--rule` |
| `lsmp-ai models` | Inspect all registered model versions in `models_store/` | None |
| `lsmp-ai threat-summary` | Display live Device Risk Index (DRI) report from database | None |
| `lsmp-ai export-db` | Synchronize model catalog and evaluation metrics to PostgreSQL | `--db-url` |
| `lsmp-ai version` | Display engine specifications, model architecture & features | None |

### Practical CLI Workflows

```bash
# 1. Inspect overall engine health, model thresholds & database table status
lsmp-ai status

# 2. Train a new cascade model with Grid Search tuning
lsmp-ai train --model-version cascade-v1.1 --test-size 0.25 --grid-search

# 3. Inspect registered versions in the model registry
lsmp-ai models

# 4. Run model ablation study comparing AI vs Rule-only baselines
lsmp-ai evaluate --runs 5 --full-ablation --output reports/ablation_study.csv

# 5. Export model metrics and active thresholds to TimescaleDB
lsmp-ai export-db

# 6. Start real-time background serving daemon (polls every 10s with 60m lookback)
lsmp-ai serve start --interval 10 --lookback 60

# 7. Check serving daemon status and last processed watermark
lsmp-ai serve status

# 8. View live high-risk threats detected across monitored hosts
lsmp-ai threat-summary

# 9. Stop the background serving daemon gracefully
lsmp-ai serve stop
```

---

## 🌐 FastAPI Writer Service & REST API Reference

In addition to CLI daemon mode, LSMP provides a high-performance **FastAPI REST API Service** (`lsmp_writer_service`) for HTTP-based inference triggers, container health probes, and SIEM integrations.

### API Security & Authentication Policy (Fail-Closed)

All management endpoints (`/metadata`, `/process`) enforce **strict, fail-closed API Key authentication**:
* Requests must supply the secret key in the `X-API-Key` HTTP header.
* If `LSMP_API_KEY` is not configured in `.env`, protected endpoints fail closed with **HTTP 500** (misconfiguration protection).
* In local test environments without keys, authentication can be bypassed by setting `LSMP_ALLOW_INSECURE_DEV=1`.
* Per-client sliding window rate limiting is enforced (default 30 requests/minute with LRU memory eviction).

### Endpoints Reference

#### 1. Public Health Check: `GET /health`
Minimal unauthenticated probe for container orchestration (Docker Compose / Kubernetes). Omits sensitive version/database details to prevent reconnaissance (S5 defense).
```bash
curl -s http://localhost:8000/health
```
```json
{
  "status": "healthy",
  "timestamp": "2026-10-16T16:51:26.123456+00:00"
}
```

#### 2. Active Model Metadata: `GET /metadata` (Authenticated)
Retrieves active model version, detection thresholds, and hyperparameters.
```bash
curl -s -H "X-API-Key: ChangeMeInProduction_LsmpApiKeySecret123!" \
  http://localhost:8000/metadata
```
```json
{
  "model_version": "cascade-v1.0",
  "anomaly_threshold": -0.1185,
  "normal_threshold": -0.1713,
  "parameters": {
    "gate_rate": 0.2,
    "uncertainty_margin": 0.05
  }
}
```

#### 3. Trigger Serving Pipeline: `POST /process` (Authenticated)
Manually dispatches an asynchronous time-window inference run into background thread pools.
```bash
curl -s -X POST http://localhost:8000/process \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ChangeMeInProduction_LsmpApiKeySecret123!" \
  -d '{"start_time": "2026-10-16T15:00:00", "end_time": "2026-10-16T15:10:00"}'
```
```json
{
  "status": "queued",
  "message": "Serving pipeline triggered for window 2026-10-16T15:00:00 to 2026-10-16T15:10:00."
}
```

---

## 🔒 Security Hardening & Environment Variables

LSMP incorporates defense-in-depth protections across all layers:

| Vulnerability Vector | Defense Mechanism | Configuration / Setting |
| :--- | :--- | :--- |
| **API Bypass (S1)** | Fail-Closed authentication policy with constant-time token comparison | `LSMP_API_KEY`, `LSMP_ALLOW_INSECURE_DEV=0` |
| **Pickle RCE (S2)** | Cryptographic SHA-256 digest validation of model binaries before `joblib.load()` | Automatic via `manifest.json` & `security.py` |
| **DB Probing Leak (S3)** | Disabled silent auto-discovery probing; strict URL resolution | `DATABASE_URL`, `POSTGRES_HOST` |
| **Rate Limiter DoS (S4)** | LRU memory eviction with configurable maximum tracked IPs | `LSMP_RATE_LIMIT_MAX_IPS=10000`, `LSMP_TRUST_PROXY_HEADERS=0` |
| **Reconnaissance Leak (S5)** | Stripped metadata from public `/health` endpoint | Handled in `lsmp_writer_service.py` |
| **SQL Injection (S6/S7)** | Strict whitelist table validation (`VALID_TABLE_NAMES`) + parameterized queries | Whitelist in `db_client.py` |
| **Credential Log Leak (S8)** | URL credentials and passwords masked in logs and exception messages | `sanitize_db_url()`, `sanitize_error_msg()` |
| **Log File Flooding (S9)** | Rotating file handler with bounded byte size and backup retention | `LSMP_LOG_MAX_BYTES=10485760`, `LSMP_LOG_BACKUP_COUNT=5` |
| **PID Hijacking (S10)** | Process cmdline verification before signaling `os.kill` + `0o600` permissions | Handled in `serve.py` |

---

## 🧪 Attack Simulation & Verification Tools

Test and verify the detection capabilities of the LSMP engine using built-in security simulators:

### 1. SSH Brute-Force Attack Simulator

Simulate synthetic SSH authentication failures against a host to trigger Wazuh SIEM rule alerts (Rules 5710, 5716, 5720) and evaluate AI risk scoring:

```bash
# Simulate 20 SSH brute-force attempts against a target IP
python tools/simulate_ssh_bruteforce.py --target 127.0.0.1 --port 22 --count 20 --delay 0.3
```

### 2. Synthetic Wazuh Log Generator

Generate synthetic Wazuh security alert logs for local testing:

```bash
# Generate synthetic log events
python tools/generate_random_wazuh_logs.py --count 100
```

After running simulations, run `lsmp-ai threat-summary` to view generated risk scores in real-time.

---

## 🔬 Testing & Quality Assurance

LSMP comes with an automated unit and integration test suite covering feature engineering, model training, risk scoring, serving logic, CLI commands, cryptographic artifact verification, and database clients.

Run the test suite:

```bash
pytest -v
```

**Status**: **61 PASSED**, 0 failed, 0 errors.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

