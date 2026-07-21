-- ============================================================================
-- file: schema.sql
-- description: LSMP Database Schema Initialization Script
-- ============================================================================

-- ============================================================================
-- 1. LOG_EVENT
-- ============================================================================
CREATE TABLE log_event (
    event_id        UUID DEFAULT gen_random_uuid(),
    "timestamp"     TIMESTAMPTZ NOT NULL,
    source_ip       VARCHAR(45),    -- IP that initiate the connection
    source_host     VARCHAR(100),   -- Hostname that initiate the connection
    username        VARCHAR(100),   -- Username that initiate the connection
    event_type      VARCHAR(20) NOT NULL CHECK (event_type IN ('auth', 'nginx')),   -- type of event
    severity        INT NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 16),   -- severity level
    rule_id         INT,            -- ID rulebase
    raw_log         TEXT NOT NULL,  -- raw log from Wazuh
    parsed_json     JSONB,          -- parsed log in JSON format
    agent_id        VARCHAR(50),    -- Agent ID
    PRIMARY KEY (event_id, "timestamp")   -- composite PK required for hypertable
);

CREATE INDEX idx_log_event_srcip_time  ON log_event (source_ip, "timestamp" DESC);
CREATE INDEX idx_log_event_agent       ON log_event (agent_id, "timestamp" DESC);
CREATE INDEX idx_log_event_source_host ON log_event (source_host, "timestamp" DESC);
CREATE INDEX idx_log_event_parsed_json ON log_event USING GIN (parsed_json);

-- ============================================================================
-- 2. FEATURE_VECTORS
-- ============================================================================
CREATE TABLE feature_vectors (
    id                      UUID DEFAULT gen_random_uuid(),
    window_start            TIMESTAMPTZ NOT NULL,
    src_ip                  VARCHAR(45) NOT NULL,
    -- LOCAL features (per src_ip)
    login_fail_count        FLOAT NOT NULL DEFAULT 0,
    fail_success_ratio      FLOAT NOT NULL DEFAULT 0,
    hour_of_day             INT NOT NULL DEFAULT 0,
    request_rate            FLOAT NOT NULL DEFAULT 0,
    status_4xx_rate         FLOAT NOT NULL DEFAULT 0,
    url_frequency           FLOAT NOT NULL DEFAULT 0,
    user_agent_entropy      FLOAT NOT NULL DEFAULT 0,
    method_distribution     FLOAT NOT NULL DEFAULT 0,
    time_window_count       FLOAT NOT NULL DEFAULT 0,
    burst_rate              FLOAT NOT NULL DEFAULT 0,
    sliding_window_count    FLOAT NOT NULL DEFAULT 0,
    -- GLOBAL features (per window, computed across ALL traffic, same value
    -- broadcast to every src_ip row within that window)
    unique_failed_ip_count  FLOAT NOT NULL DEFAULT 0,
    ip_entropy              FLOAT NOT NULL DEFAULT 0,
    ip_switch_frequency     FLOAT NOT NULL DEFAULT 0,
    feature_version         VARCHAR(20) NOT NULL DEFAULT 'v1',
    computed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, window_start),
    UNIQUE (window_start, src_ip, feature_version)
);

CREATE INDEX idx_fv_srcip_time ON feature_vectors (src_ip, window_start DESC);
CREATE INDEX idx_fv_version    ON feature_vectors (feature_version, window_start DESC);


-- ============================================================================
-- 3. ANOMALY_RESULT
-- ============================================================================
CREATE TABLE anomaly_result (
    id                  UUID DEFAULT gen_random_uuid(),   -- Primary key
    window_start        TIMESTAMPTZ NOT NULL,             -- start of 60-second sliding window
    src_ip              VARCHAR(45) NOT NULL,             -- source IP
    event_id            UUID,                             -- logical FK -> log_event(event_id)
    feature_vector_id   UUID,                             -- logical FK -> feature_vectors(id)
    feature_snapshot    JSONB NOT NULL,                   -- 14 AI features, used for retraining
    anomaly_score       FLOAT NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),   -- anomaly score
    model_version       VARCHAR(50) NOT NULL,             -- AI model version
    predicted_label     VARCHAR(10) NOT NULL CHECK (predicted_label IN ('Normal','Anomaly')),   -- predicted label
    ground_truth_label  VARCHAR(10) CHECK (ground_truth_label IN ('Normal','Anomaly')),   -- ground truth label
    label_source        VARCHAR(30),                      -- 'lab_scenario' / 'analyst_confirmed'
    PRIMARY KEY (id, window_start),
    UNIQUE (window_start, src_ip, model_version)
);

CREATE INDEX idx_anomaly_srcip_time  ON anomaly_result (src_ip, window_start DESC);
CREATE INDEX idx_anomaly_label       ON anomaly_result (ground_truth_label) WHERE ground_truth_label IS NOT NULL;
CREATE INDEX idx_anomaly_model_ver   ON anomaly_result (model_version, window_start DESC);
CREATE INDEX idx_anomaly_fv_id       ON anomaly_result (feature_vector_id);


-- ============================================================================
-- 4. RISK_SCORE
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
-- 5. ATTACK_SCENARIOS
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
-- 6. EVALUATION_METRICS
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
-- TIMESCALEDB HYPERTABLES CONFIGURATION (log_event, feature_vectors, and anomaly_result)
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
            -- source_host added to segmentby: with multiple collector
            -- machines, grouping compressed chunks by client as well as
            -- event_type/source_ip improves compression ratio and keeps
            -- per-client queries scanning fewer chunks.
            timescaledb.compress_segmentby = 'event_type, source_ip, source_host',
            timescaledb.compress_orderby = 'timestamp DESC'
        );
        PERFORM add_compression_policy('log_event', INTERVAL '7 days', if_not_exists => TRUE);
        PERFORM add_retention_policy('log_event', INTERVAL '90 days', if_not_exists => TRUE);

        -- feature_vectors: partition by day, compress after 14 days, retain for 180 days
        PERFORM create_hypertable('feature_vectors', 'window_start', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
        ALTER TABLE feature_vectors SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'src_ip, feature_version',
            timescaledb.compress_orderby = 'window_start DESC'
        );
        PERFORM add_compression_policy('feature_vectors', INTERVAL '14 days', if_not_exists => TRUE);
        PERFORM add_retention_policy('feature_vectors', INTERVAL '180 days', if_not_exists => TRUE);

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
        -- (no hypertable) as per the 6-table classification.

        RAISE NOTICE 'TimescaleDB hypertables, compression, and retention policies successfully initialized.';
    ELSE
        RAISE NOTICE 'TimescaleDB extension not found. Running on standard PostgreSQL.';
    END IF;
END $$;
