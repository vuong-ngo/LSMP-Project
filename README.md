# 🛡️ LSMP: Log Security Monitoring & Threat Detection Platform

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.140-009688.svg)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/TimescaleDB-PostgreSQL%2015-336791.svg)](https://www.timescale.com/)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.x-0052CC.svg)](https://wazuh.com/)
[![Pytest Status](https://img.shields.io/badge/pytest-39%20passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **LSMP (Log Security Monitoring Platform)** is an enterprise-grade AI-powered Cyber Security Monitoring and Intrusion Detection Platform. It bridges traditional static SIEM rule enforcement (**Wazuh**) with a high-performance **Two-Stage Cascade Machine Learning Engine (Isolation Forest $\rightarrow$ One-Class SVM)** to deliver real-time anomaly detection, dynamic threat classification, and composite risk scoring across monitored infrastructure.

---

## 📌 Table of Contents

- [🌟 Key Features](#-key-features)
- [🧠 AI Engine & Two-Stage Cascade Model](#-ai-engine--two-stage-cascade-model)
- [🧮 Composite Risk Scoring Model](#-composite-risk-scoring-model)
- [🛠️ Tech Stack & Infrastructure](#️-tech-stack--infrastructure)
- [📁 Directory & Project Structure](#-directory--project-structure)
- [🚀 Installation & Setup Guide](#-installation--setup-guide)
- [🖥️ Interactive Terminal UI (TUI) & CLI Usage](#️-interactive-terminal-ui-tui--cli-usage)
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
- **Interactive Terminal UI (TUI)**: Rich, real-time command-line dashboard (`lsmp-tui`) for security operations, system health audits, live risk scoring, and threat tracking.
- **Production CLI (`lsmp-ai`)**: Global Typer CLI interface for model training, serving daemon controls, automatic retraining, catalog inspection, and research benchmarks.
- **Auto-Retraining & Model Versioning**: Automated background daemons for periodic model updates and persistent catalog registry in `models_store/`.
- **Time-Series Optimization**: Hypertable partitioning, metric compression policies, and automated retention management powered by TimescaleDB / PostgreSQL.
- **Integrated Security Attack Simulators**: Built-in scripts for testing SSH brute-force attacks and generating synthetic Wazuh SIEM alerts.

---

## 🧠 AI Engine & Two-Stage Cascade Model

The LSMP AI core ([`src/lsmp_ai`](file:///home/ngoducvuong/Documents/Projects/up/LSMP-Project/src/lsmp_ai)) extracts 14 dynamic security features grouped into 3 analytical domains:

| Analytical Domain | Feature Name | Description |
| :--- | :--- | :--- |
| 🔑 **Auth Domain** | `login_fail_count`<br/>`unique_failed_ip_count`<br/>`fail_success_ratio`<br/>`targeted_dest_ips` | Tracks authentication failure rates, unique target IPs, login ratios, and multi-IP brute-force activity. |
| 🌐 **HTTP Domain** | `request_rate`<br/>`status_4xx_rate`<br/>`status_5xx_rate`<br/>`url_frequency`<br/>`user_agent_entropy`<br/>`unusual_method_ratio` | Detects web scanning, directory fuzzing, malicious payload patterns, anomalous User-Agents, and non-standard HTTP methods. |
| 📊 **Behavior Domain** | `time_window_count`<br/>`ip_switch_frequency`<br/>`burst_rate`<br/>`sliding_window_count` | Monitors total event density, IP switching frequency, peak event bursts, and temporal window trends. |

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
| $0 \le \text{Score} < 30$ | 🟢 **LOW** | Normal activity. Logged for standard audit trails. |
| $30 \le \text{Score} < 50$ | 🟡 **MEDIUM** | Minor anomaly detected. Flagged for analyst review. |
| $50 \le \text{Score} < 85$ | 🟠 **HIGH** | Significant security threat. High-priority alert triggered. |
| $85 \le \text{Score} \le 100$ | 🔴 **CRITICAL** | Urgent intrusion alert. Active defense / mitigation recommended. |

---

## 🛠️ Tech Stack & Infrastructure

- **Programming Language**: Python 3.12+
- **Machine Learning & Analytics**: Scikit-Learn 1.3+, Pandas, NumPy, Joblib
- **API & Web Framework**: FastAPI, Uvicorn (ASGI), Pydantic v2, Typer CLI
- **Terminal UI Engine**: Textual / Rich Framework
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
├── scripts/                 # Service control scripts (start_service.sh, stop_service.sh)
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
│       └── ui/              # Interactive Terminal UI (TUI) Dashboard
├── tests/                   # Pytest automated test suite
└── tools/                   # Security simulators (SSH brute-force & log generators)
```

---

## 🚀 Installation & Setup Guide

### Method 1: Standalone Automated Setup (Recommended)

Run the automated installer script to prepare virtual environments, dependencies, system configurations, and symlink binary executables (`lsmp-ai`, `lsmp-tui`):

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

## 🖥️ Interactive Terminal UI (TUI) & CLI Usage

LSMP provides both an interactive Terminal UI and a global CLI command suite.

### 1. Interactive Terminal UI (`lsmp-tui`)

Launch the real-time Security Operations TUI dashboard to view live risk scores, model status, host indices, and threat distribution:

```bash
# Launch interactive TUI
lsmp-tui

# Alternative command via CLI
lsmp-ai dashboard
```

### 2. Global CLI Reference (`lsmp-ai`)

```bash
# View all available CLI commands
lsmp-ai --help

# Inspect system health, model status, and DB connectivity
lsmp-ai status

# Train the Two-Stage Cascade Model (iForest + OCSVM)
lsmp-ai train --test-size 0.3 --model-version cascade-v1.0

# Start or stop the real-time background serving daemon
lsmp-ai serve start --interval 10 --lookback 60
lsmp-ai serve stop
lsmp-ai serve status

# Start or stop the automated periodic model re-training daemon
lsmp-ai autotrain start --interval-hours 24
lsmp-ai autotrain stop

# Inspect all registered AI model versions in the catalog
lsmp-ai models

# Display live Device Risk Index (DRI) summary report from database
lsmp-ai threat-summary

# Clean raw log data and extract 14 feature vectors
lsmp-ai prepare-data --max-samples 100000

# Run evaluation benchmarks and export CSV report
lsmp-ai evaluate --runs 5 --output reports/ablation_study.csv

# Export registered model metadata and metrics to PostgreSQL
lsmp-ai export-db
```

---

## ⚙️ Service Management & Background Daemons

LSMP provides control scripts to start and stop background serving services cleanly:

```bash
# Start background AI serving daemon
./scripts/start_service.sh

# Verify API health status endpoint
curl http://localhost:8000/health

# Stop background AI serving daemon
./scripts/stop_service.sh
```

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

After running simulations, launch `lsmp-tui` or run `lsmp-ai threat-summary` to view generated risk scores in real-time.

---

## 🔬 Testing & Quality Assurance

LSMP comes with an automated unit and integration test suite covering feature engineering, model training, risk scoring, serving logic, CLI commands, and database clients.

Run the test suite:

```bash
PYTHONPATH=src .venv/bin/pytest tests/ -v
```

**Status**: **39 PASSED**, 0 errors.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
