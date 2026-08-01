# 🛡️ LSMP AI Anomaly Detection & Risk Scoring Engine (`src/lsmp_ai`)

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pytest Status](https://img.shields.io/badge/pytest-39%20passed%2C%200%20failed-brightgreen.svg)]()

`lsmp_ai` is the core Artificial Intelligence, Real-Time Risk Scoring, and Security Operations package of the **Log Security Monitoring Platform (LSMP)**. It provides a modular, high-throughput engine that ingests security log events (e.g., Wazuh alerts or system logs), extracts 14 security-focused feature vectors, performs two-stage cascade anomaly detection (Isolation Forest $\rightarrow$ One-Class SVM), calculates real-time composite risk scores, and persists threat predictions to PostgreSQL / TimescaleDB.

---

## 📌 Table of Contents

- [📐 Package Architecture & Submodule Breakdown](#-package-architecture--submodule-breakdown)
- [🛠️ 14 Security Feature Vector Specification](#️-14-security-feature-vector-specification)
- [🧠 Two-Stage Cascade Model & Risk Calculation](#-two-stage-cascade-model--risk-calculation)
- [💻 CLI & Interactive TUI Commands](#-cli--interactive-tui-commands)
- [⚙️ Serving Engine & Background Daemons](#️-serving-engine--background-daemons)
- [🔬 Verification & Unit Testing](#-verification--unit-testing)

---

## 📐 Package Architecture & Submodule Breakdown

The `lsmp_ai` package is organized into modular components:

```text
src/lsmp_ai/
├── cli.py               # Global Typer CLI command entrypoint (`lsmp-ai`)
├── version.py           # Engine version metadata
├── common/              # System utilities, YAML config loaders, logging, exceptions, constants
├── io/                  # Data access layer: DBClient (PostgreSQL/TimescaleDB), DataLoader, ResultWriter
├── feature_engineering/ # 14 security-oriented time-series feature extractors
├── models/              # IsolationForest, OCSVM, CascadeModel, ModelRegistry, GridSearch
├── risk_scoring/        # Composite Risk Scoring Engine (AI Score + Wazuh Severity) & Classifier
├── evaluation/          # Ablation studies, classification metrics, significance testing, benchmark runner
├── serving/             # Real-time inference daemon, FastAPI async writer engine, polling scheduler
├── ui/                  # Interactive Terminal UI (TUI) Dashboard logic
└── scripts/             # Internal executable sub-routines (train, serve, autotrain, evaluate, status)
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

The feature extraction module (`extract_features_from_logs`) generates 14 time-window features per source IP address (`src_ip`):

| # | Feature Name | Analytical Focus | Description |
|---|---|---|---|
| 1 | `login_fail_count` | Auth Domain | Number of failed authentication attempts in time window |
| 2 | `unique_failed_ip_count` | Auth Domain | Distinct target IPs targeted by failed logins |
| 3 | `fail_success_ratio` | Auth Domain | Ratio of failed logins to successful logins |
| 4 | `ip_entropy` | Auth Domain | Shannon entropy of IP distributions |
| 5 | `hour_of_day` | Behavior Domain | Cyclic hour of event timestamp (0–23) |
| 6 | `request_rate` | HTTP Domain | Average HTTP/Web request rate per second |
| 7 | `status_4xx_rate` | HTTP Domain | Ratio of HTTP 4xx client error responses (fuzzing indicator) |
| 8 | `url_frequency` | HTTP Domain | Frequency of requested URI paths |
| 9 | `user_agent_entropy` | HTTP Domain | Entropy of HTTP User-Agent strings |
| 10 | `method_distribution` | HTTP Domain | Distribution ratio of non-GET/POST HTTP methods |
| 11 | `time_window_count` | Behavior Domain | Total event count within fixed time window |
| 12 | `burst_rate` | Behavior Domain | Peak event frequency per second within window |
| 13 | `sliding_window_count` | Behavior Domain | Aggregated count across sliding temporal window |
| 14 | `ip_switch_frequency` | Behavior Domain | Frequency of IP address origin shifts per session |

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

## 💻 CLI & Interactive TUI Commands

The `lsmp_ai` package includes the `lsmp-ai` Typer command suite and `lsmp-tui` interactive dashboard.

### 1. Interactive TUI Dashboard (`lsmp-tui`)

Launch the Terminal UI dashboard:

```bash
lsmp-tui
```

### 2. Primary CLI Commands (`lsmp-ai`)

```bash
# Check status and health of model & database connections
lsmp-ai status

# Train Two-Stage Cascade AI model on baseline feature data
lsmp-ai train --test-size 0.3 --model-version cascade-v1.0

# Manage real-time serving daemon
lsmp-ai serve start --interval 10 --lookback 60
lsmp-ai serve stop
lsmp-ai serve status

# Manage auto-retraining background daemon
lsmp-ai autotrain start --interval-hours 24
lsmp-ai autotrain stop

# List registered AI models in models_store catalog
lsmp-ai models

# Show active threat summary report across monitored hosts
lsmp-ai threat-summary

# Clean raw log events & generate 14-feature vector CSV
lsmp-ai prepare-data --max-samples 100000

# Execute model ablation evaluation benchmark
lsmp-ai evaluate --runs 5 --output reports/ablation_study.csv

# Export model catalog and metrics to PostgreSQL
lsmp-ai export-db
```

---

## ⚙️ Serving Engine & Background Daemons

The package supports running as a background daemon or via FastAPI HTTP endpoint:

### Service Startup via Scripts

```bash
# Launch background daemon
./scripts/start_service.sh

# Check API health endpoint
curl http://localhost:8000/health

# Stop background daemon
./scripts/stop_service.sh
```

---

## 🔬 Verification & Unit Testing

The `lsmp_ai` package is verified by a test suite testing features, models, risk scoring, FastAPI endpoints, CLI functions, and database layers.

Run unit tests:

```bash
PYTHONPATH=src .venv/bin/pytest tests/ -v
```

**Status**: **39 PASSED**, 0 errors.
