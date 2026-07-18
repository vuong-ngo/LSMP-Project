-- ============================================================================
-- file: schema.sql
-- LSMP Database Schema Initialization Script
-- Target Database: PostgreSQL with TimescaleDB Extension
-- ============================================================================

-- ============================================================================
-- 1. LOG_EVENT
-- ============================================================================
CREATE TABLE log_event (
    event_id        UUID DEFAULT gen_random_uuid(),
    "timestamp"     TIMESTAMPTZ NOT NULL,
    source_ip       VARCHAR(45),
    username        VARCHAR(100),
    event_type      VARCHAR(20) NOT NULL CHECK (event_type IN ('auth', 'nginx')),
    severity        INT NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 16),
    raw_log         TEXT NOT NULL,
    parsed_json     JSONB,
    agent_id        VARCHAR(50),
    PRIMARY KEY (event_id, "timestamp")   -- composite PK required for hypertable
);

CREATE INDEX idx_log_event_srcip_time ON log_event (source_ip, "timestamp" DESC);
CREATE INDEX idx_log_event_agent      ON log_event (agent_id, "timestamp" DESC);


-- ============================================================================
-- 2. ANOMALY_RESULT
-- ============================================================================
CREATE TABLE anomaly_result (
    id                  UUID DEFAULT gen_random_uuid(),
    window_start        TIMESTAMPTZ NOT NULL,             -- start of 60-second sliding window
    src_ip              VARCHAR(45) NOT NULL,
    event_id            UUID,                             -- logical FK -> log_event(event_id)
    feature_snapshot    JSONB NOT NULL,                   -- 14 AI features, used for retraining
    anomaly_score       FLOAT NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),
    model_version       VARCHAR(50) NOT NULL,
    predicted_label     VARCHAR(10) NOT NULL CHECK (predicted_label IN ('Normal','Anomaly')),
    ground_truth_label  VARCHAR(10) CHECK (ground_truth_label IN ('Normal','Anomaly')),
    label_source        VARCHAR(30),                      -- 'lab_scenario' / 'analyst_confirmed'
    PRIMARY KEY (id, window_start),
    UNIQUE (window_start, src_ip, model_version)
);

CREATE INDEX idx_anomaly_srcip_time ON anomaly_result (src_ip, window_start DESC);
CREATE INDEX idx_anomaly_label      ON anomaly_result (ground_truth_label) WHERE ground_truth_label IS NOT NULL;


-- ============================================================================
-- 3. RISK_SCORE
-- ============================================================================
CREATE TABLE risk_score (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    src_ip              VARCHAR(45) NOT NULL,
    asset_id            VARCHAR(50),
    anomaly_result_id   UUID,                             -- logical FK -> anomaly_result(id)
    ai_component        FLOAT,
    rule_component       FLOAT,
    score                FLOAT NOT NULL CHECK (score BETWEEN 0 AND 100),
    risk_class           VARCHAR(10) CHECK (risk_class IN ('Low','Medium','High','Critical')),
    "timestamp"          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (anomaly_result_id)                            -- enforces 1-to-1 relationship with anomaly_result
);

CREATE INDEX idx_risk_srcip_time ON risk_score (src_ip, "timestamp" DESC);
CREATE INDEX idx_risk_class      ON risk_score (risk_class, "timestamp" DESC);
-- Note: UNIQUE (anomaly_result_id) automatically creates an index on this column.


-- ============================================================================
-- 4. ATTACK_SCENARIOS
-- ============================================================================
CREATE TABLE attack_scenarios (
    id              SERIAL PRIMARY KEY,
    scenario_name   VARCHAR(100) NOT NULL,
    attack_type     VARCHAR(50) NOT NULL CHECK (attack_type IN ('ssh_bruteforce', 'web_bruteforce')),
    start_time      TIMESTAMPTZ NOT NULL,
    end_time        TIMESTAMPTZ NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    CHECK (end_time > start_time)
);

CREATE INDEX idx_attack_scenarios_time ON attack_scenarios (start_time, end_time);
CREATE INDEX idx_attack_scenarios_ip   ON attack_scenarios (attacker_ip);


-- ============================================================================
-- 5. EVALUATION_METRICS
-- ============================================================================
CREATE TABLE evaluation_metrics (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id                      VARCHAR(100) NOT NULL,      -- groups multiple rows from the same evaluation run
    model_config                VARCHAR(30) NOT NULL CHECK (
        model_config IN ('wazuh_rule_only', 'iforest_only', 'ocsvm_only', 'cascade_iforest_ocsvm')
    ),
    model_version               VARCHAR(50),                -- matches anomaly_result.model_version if applicable
    dataset_split                VARCHAR(50) NOT NULL,       -- e.g. 'test', 'lab_ssh', 'lab_web', 'cicids2017'
    precision_score              FLOAT CHECK (precision_score BETWEEN 0 AND 1),
    recall_score                 FLOAT CHECK (recall_score BETWEEN 0 AND 1),
    f1_score                     FLOAT CHECK (f1_score BETWEEN 0 AND 1),
    false_positive_rate          FLOAT CHECK (false_positive_rate BETWEEN 0 AND 1),
    roc_auc                      FLOAT CHECK (roc_auc BETWEEN 0 AND 1),
    latency_ms_avg                FLOAT,
    latency_ms_p95                FLOAT,
    throughput_events_per_sec     FLOAT,
    cpu_usage_percent              FLOAT,
    ram_usage_mb                    FLOAT,
    hyperparameters                 JSONB,                  -- params used for this run (n_estimators, nu, gamma...)
    evaluated_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, model_config, dataset_split)
);

CREATE INDEX idx_eval_metrics_run    ON evaluation_metrics (run_id);
CREATE INDEX idx_eval_metrics_config ON evaluation_metrics (model_config, evaluated_at DESC);


-- ============================================================================
-- TIMESCALEDB HYPERTABLES CONFIGURATION (log_event and anomaly_result only)
-- ============================================================================

DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
    EXCEPTION WHEN others THEN
        RAISE NOTICE 'TimescaleDB extension library not active. Running on standard PostgreSQL.';
    END;

    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- log_event: partition by day, compress after 7 days, retain for 90 days
        PERFORM create_hypertable('log_event', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
        ALTER TABLE log_event SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'event_type, source_ip',
            timescaledb.compress_orderby = 'timestamp DESC'
        );
        PERFORM add_compression_policy('log_event', INTERVAL '7 days', if_not_exists => TRUE);
        PERFORM add_retention_policy('log_event', INTERVAL '90 days', if_not_exists => TRUE);

        -- anomaly_result: partition by week, compress after 30 days, NO retention
        -- (kept long-term as training data for AI model retraining)
        PERFORM create_hypertable('anomaly_result', 'window_start', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
        ALTER TABLE anomaly_result SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'src_ip, model_version',
            timescaledb.compress_orderby = 'window_start DESC'
        );
        PERFORM add_compression_policy('anomaly_result', INTERVAL '30 days', if_not_exists => TRUE);

        -- risk_score, attack_scenarios, evaluation_metrics: kept as regular tables
        -- (no hypertable) as per the 5-table classification.

        RAISE NOTICE 'TimescaleDB hypertables, compression, and retention policies successfully initialized.';
    ELSE
        RAISE NOTICE 'TimescaleDB extension not found. Running on standard PostgreSQL.';
    END IF;
END $$;