# LSMP AI Anomaly Detection & Risk Scoring Engine (`src/lsmp_ai`)

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pytest Status](https://img.shields.io/badge/pytest-39%20passed%2C%200%20failed-brightgreen.svg)]()

`lsmp_ai` is the core Artificial Intelligence and Real-Time Risk Scoring package of the **Log Security Monitoring Platform (LSMP)**. It provides an automated, high-throughput pipeline that ingests security log events (e.g., from Wazuh alerts or system logs), extracts 14 security-focused features, performs two-stage cascade anomaly detection (Isolation Forest $\rightarrow$ One-Class SVM), calculates real-time composite risk scores, and persists predictions to PostgreSQL / TimescaleDB.

---

## 📐 Architecture & Module Breakdown

The `lsmp_ai` package is organized into modular, single-responsibility components:

```text
src/lsmp_ai/
├── common/             # System utilities, YAML config loaders, logging, custom exceptions, constants
├── io/                 # Data access layer: DBClient (PostgreSQL), DataLoader, ResultWriter
├── feature_engineering/# 14 security-oriented time-series feature extractors & FeaturePipeline
├── models/             # ML Models: IsolationForest, OCSVM, CascadeModel, ModelRegistry, GridSearch
├── risk_scoring/       # Composite Risk Scoring Engine (AI Score + Wazuh Severity) & Risk Classifier
├── evaluation/         # Ablation studies, classification metrics, significance testing, benchmark runner
├── serving/            # Real-time inference service, FastAPI async writer engine, polling scheduler
└── pipeline/           # End-to-end workflows: TrainPipeline, ServePipeline, EvaluatePipeline
```

### Key Technical Innovations & Resolved Edge Cases

1. **Two-Stage Cascade ML Model (`CascadeModel`)**:
   - **Stage 1 (Isolation Forest)**: Rapidly filters obvious normal and obvious anomalous events using learned percentile routing thresholds.
   - **Stage 2 (One-Class SVM)**: Focuses exclusively on the "uncertain region" (boundary samples) passed from Stage 1, significantly lowering false positive rates while maintaining high execution speed.

2. **Composite Risk Scoring Formula**:
   - Combines unsupervised machine learning anomaly probability with rule-based severity from SIEM alerts:
     $$\text{Risk Score} = 100 \times \left( \alpha \times \text{Anomaly Score} + \beta \times \frac{\min(\max(\text{Severity}, 0), 15)}{15} \right)$$
   - Where default weights are $\alpha = 0.6$ (60% AI weight) and $\beta = 0.4$ (40% Rule weight). Categorized into **Low** ($<25$), **Medium** ($25-50$), **High** (-$80$), and **Critical** ($>80$).

3. **Standardized Resource Measurement**:
   - Resolved database `<null>` metrics in evaluation tables by implementing standard OS/Posix measurements (`resource.getrusage` for RAM RSS MB and `os.times()` for CPU usage percentage), avoiding third-party dependency crashes.

4. **Relational Data Integrity & Foreign Key Linking**:
   - Preserves UUID identifiers across stages: `log_event` $\rightarrow$ `feature_vectors(id)` $\rightarrow$ `anomaly_result(feature_vector_id)` $\rightarrow$ `risk_score(anomaly_result_id)`.

5. **Non-Blocking Async Serving Engine**:
   - FastAPI server (`lsmp_writer_service.py`) offloads heavy time-series database batch inference to worker thread pools (`asyncio.to_thread`), ensuring HTTP health checks (`/health`) and management endpoints (`/process`, `/metadata`) remain responsive at under 5ms latency.

---

## 🛠️ 14 Security Feature Vector Specification

The feature engineering module (`extract_features_from_logs`) extracts 14 time-window features per source IP address (`src_ip`):

| # | Feature Name | Description |
|---|---|---|
| 1 | `login_fail_count` | Number of failed authentication attempts in the time window |
| 2 | `unique_failed_ip_count` | Distinct target IPs targeted by failed logins |
| 3 | `fail_success_ratio` | Ratio of failed logins to successful logins |
| 4 | `ip_entropy` | Shannon entropy of IP distributions in window |
| 5 | `hour_of_day` | Cyclic hour of event timestamp (0–23) |
| 6 | `request_rate` | Average HTTP/Web request rate per second |
| 7 | `status_4xx_rate` | Ratio of HTTP 4xx client error responses (fuzzing/scanning indicator) |
| 8 | `url_frequency` | Frequency of requested URI paths |
| 9 | `user_agent_entropy` | Entropy of HTTP User-Agent strings |
| 10 | `method_distribution` | Distribution ratio of non-GET/POST HTTP methods |
| 11 | `time_window_count` | Total event count within fixed time window |
| 12 | `burst_rate` | Peak event frequency per second within window |
| 13 | `sliding_window_count` | Aggregated count across sliding temporal window |
| 14 | `ip_switch_frequency` | Frequency of IP address origin shifts per session |

---

## 🚀 Standalone Installation & Usage

### 1-Click Automated Installer
Run the installer script:
```bash
./install.sh
```

### Global CLI Commands (`lsmp-ai`)
After installation, the `lsmp-ai` executable is symlinked into `~/.local/bin/lsmp-ai`:

```bash
# Display CLI help menu
lsmp-ai --help

# Train Cascade Model & register version in model store
lsmp-ai train --test-size 0.3 --model-version cascade-v1.0

# Run batch inference on recent database logs
lsmp-ai serve --limit 100

# Evaluate model with ablation study and export CSV report
lsmp-ai evaluate --output reports/results/bang_3_1_so_sanh_baseline.csv

# Run detailed performance comparison between iForest, OCSVM, and Cascade
lsmp-ai compare
```

### Service Controls
To start or stop the local background FastAPI server and time-series daemon:
```bash
# Start background service (Port 8000)
./scripts/start_service.sh

# Stop background service
./scripts/stop_service.sh
```

### Docker Container Deployment (Model Only)
To package and run the AI Model container connected to your infrastructure database:
```bash
docker compose up -d --build
```

### Continuous Resource & Database Metric Verification Scripts
For continuous CPU/RAM monitoring and PostgreSQL schema verification:
```bash
# 1. Run continuous CPU, RAM, Latency & Throughput benchmark
./.venv/bin/python scripts/measure_model_throughput_resources.py --num-samples 1000 --iterations 50

# 2. Verify complete DB schema metrics ingestion (16 columns)
./.venv/bin/python scripts/verify_db_metrics_ingestion.py
```
For detailed documentation, see [docs/METRICS_AND_BENCHMARK_GUIDE.md](../../docs/METRICS_AND_BENCHMARK_GUIDE.md).

---

## 🧪 Verification & Unit Testing

The test suite consists of 40 comprehensive unit tests verifying data pipeline execution, feature calculation, model training, registry persistence, risk scoring, FastAPI endpoints, and database interactions.

Run full test suite:
```bash
PYTHONPATH=src .venv/bin/pytest tests/
```

**Status**: **39 PASSED**, 2 skipped (optional real DB integration test), **0 ERRORS**.
