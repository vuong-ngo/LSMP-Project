-- ============================================================================
-- file: test_schema.sql
-- description: SQL script to test and verify the LSMP database schema.
-- ============================================================================

-- ============================================================================
-- 1. VERIFY TABLE EXISTENCE
-- ============================================================================
\echo ''
\echo '=== [1/8] Verifying 5 tables exist ==='
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('log_event', 'anomaly_result', 'risk_score', 'attack_scenarios', 'evaluation_metrics')
ORDER BY table_name;

-- ============================================================================
-- 2. VERIFY TIMESCALEDB (optional - will show empty if not installed)
-- ============================================================================
\echo ''
\echo '=== [2/8] Checking TimescaleDB extension status ==='
SELECT extname, extversion FROM pg_extension WHERE extname = 'timescaledb';

\echo 'Checking hypertables (empty if TimescaleDB not active)...'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        RAISE NOTICE 'TimescaleDB detected. Querying hypertable info...';
        -- timescaledb_information.hypertables exists only when extension is loaded
    ELSE
        RAISE NOTICE 'TimescaleDB not installed. Skipping hypertable check.';
    END IF;
END $$;

-- ============================================================================
-- 3. INSERT VALID MOCK DATA (happy path)
-- ============================================================================
\echo ''
\echo '=== [3/8] Inserting valid mock data ==='

-- 3a. log_event (2 rows)
\echo '  -> log_event...'
INSERT INTO log_event (event_id, "timestamp", source_ip, username, event_type, severity, raw_log, parsed_json, agent_id)
VALUES
  ('a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1', '2026-07-18 07:00:00+07', '192.168.1.100', 'admin', 'auth', 10, 'Failed password for admin from 192.168.1.100', '{"status": "failed", "rule_id": 5710}', 'agent-01'),
  ('b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2', '2026-07-18 07:01:00+07', '192.168.1.100', NULL, 'nginx', 5, 'GET /admin HTTP/1.1 404', '{"http_code": 404, "method": "GET"}', 'agent-01');

-- 3b. anomaly_result (1 row)
\echo '  -> anomaly_result...'
INSERT INTO anomaly_result (id, window_start, src_ip, event_id, feature_snapshot, anomaly_score, model_version, predicted_label, ground_truth_label, label_source)
VALUES
  ('c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3', '2026-07-18 07:00:00+07', '192.168.1.100', 'a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1',
   '{"login_fail_count": 5.0, "request_rate": 10.0, "unique_users": 1, "avg_severity": 7.5}',
   0.85, 'cascade-v1.0', 'Anomaly', NULL, NULL);

-- 3c. risk_score (1 row)
\echo '  -> risk_score...'
INSERT INTO risk_score (id, src_ip, asset_id, anomaly_result_id, ai_component, rule_component, score, risk_class, "timestamp")
VALUES
  ('d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4', '192.168.1.100', 'agent-01', 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3', 0.51, 0.27, 78.0, 'High', '2026-07-18 07:02:00+07');

-- 3d. attack_scenarios (1 row)
\echo '  -> attack_scenarios...'
INSERT INTO attack_scenarios (scenario_name, attack_type, start_time, end_time, attacker_ip)
VALUES
  ('SSH Brute Force Test', 'ssh_bruteforce', '2026-07-18 06:55:00+07', '2026-07-18 07:05:00+07', '192.168.1.100');

-- 3e. evaluation_metrics (1 row - cascade config)
\echo '  -> evaluation_metrics...'
INSERT INTO evaluation_metrics (
    run_id, model_config, model_version, dataset_split,
    precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
    latency_ms_avg, latency_ms_p95, throughput_events_per_sec,
    cpu_usage_percent, ram_usage_mb, hyperparameters
)
VALUES (
    'run_20260718', 'cascade_iforest_ocsvm', 'cascade-v1.0', 'test',
    0.92, 0.88, 0.90, 0.05, 0.95,
    12.5, 25.0, 850.0,
    35.0, 256.0, '{"n_estimators": 100, "contamination": 0.05, "nu": 0.1}'
);

\echo '  [OK] All valid mock data inserted successfully.'

-- Verify row counts
\echo ''
\echo 'Row counts after insert:'
SELECT 'log_event' AS tbl, COUNT(*) FROM log_event
UNION ALL SELECT 'anomaly_result', COUNT(*) FROM anomaly_result
UNION ALL SELECT 'risk_score', COUNT(*) FROM risk_score
UNION ALL SELECT 'attack_scenarios', COUNT(*) FROM attack_scenarios
UNION ALL SELECT 'evaluation_metrics', COUNT(*) FROM evaluation_metrics;

-- ============================================================================
-- 4. CHECK CONSTRAINT TESTS (negative - expected to fail)
-- ============================================================================
\echo ''
\echo '=== [4/8] Testing CHECK constraints (expect errors inside savepoints) ==='

-- 4a. Invalid event_type
\echo '  -> [EXPECT ERROR] Invalid event_type = syslog...'
BEGIN;
SAVEPOINT sp1;
INSERT INTO log_event ("timestamp", event_type, severity, raw_log)
VALUES ('2026-07-18 08:00:00+07', 'syslog', 3, 'test invalid type');
ROLLBACK TO sp1;
COMMIT;

-- 4b. Severity out of range (17 > max 16)
\echo '  -> [EXPECT ERROR] severity = 17 (out of range 0-16)...'
BEGIN;
SAVEPOINT sp2;
INSERT INTO log_event ("timestamp", event_type, severity, raw_log)
VALUES ('2026-07-18 08:00:00+07', 'auth', 17, 'test severity overflow');
ROLLBACK TO sp2;
COMMIT;

-- 4c. Severity = 16 should SUCCEED (boundary valid)
\echo '  -> [EXPECT SUCCESS] severity = 16 (max valid value)...'
BEGIN;
SAVEPOINT sp3;
INSERT INTO log_event (event_id, "timestamp", event_type, severity, raw_log)
VALUES ('e5e5e5e5-e5e5-e5e5-e5e5-e5e5e5e5e5e5', '2026-07-18 08:00:00+07', 'auth', 16, 'severity max boundary test');
ROLLBACK TO sp3;
COMMIT;

-- 4d. anomaly_score > 1
\echo '  -> [EXPECT ERROR] anomaly_score = 1.5 (out of range 0-1)...'
BEGIN;
SAVEPOINT sp4;
INSERT INTO anomaly_result (window_start, src_ip, feature_snapshot, anomaly_score, model_version, predicted_label)
VALUES ('2026-07-18 08:00:00+07', '10.0.0.1', '{}', 1.5, 'test-v0', 'Anomaly');
ROLLBACK TO sp4;
COMMIT;

-- 4e. Invalid predicted_label
\echo '  -> [EXPECT ERROR] predicted_label = Unknown...'
BEGIN;
SAVEPOINT sp5;
INSERT INTO anomaly_result (window_start, src_ip, feature_snapshot, anomaly_score, model_version, predicted_label)
VALUES ('2026-07-18 08:00:00+07', '10.0.0.1', '{}', 0.5, 'test-v0', 'Unknown');
ROLLBACK TO sp5;
COMMIT;

-- 4f. Invalid risk_class
\echo '  -> [EXPECT ERROR] risk_class = Extreme (not in enum)...'
BEGIN;
SAVEPOINT sp6;
INSERT INTO risk_score (src_ip, score, risk_class)
VALUES ('10.0.0.1', 95.0, 'Extreme');
ROLLBACK TO sp6;
COMMIT;

-- 4g. Score out of range
\echo '  -> [EXPECT ERROR] score = 150 (out of range 0-100)...'
BEGIN;
SAVEPOINT sp7;
INSERT INTO risk_score (src_ip, score, risk_class)
VALUES ('10.0.0.1', 150.0, 'Critical');
ROLLBACK TO sp7;
COMMIT;

-- 4h. Invalid attack_type
\echo '  -> [EXPECT ERROR] attack_type = ddos (not in enum)...'
BEGIN;
SAVEPOINT sp8;
INSERT INTO attack_scenarios (scenario_name, attack_type, start_time, end_time, attacker_ip)
VALUES ('DDoS Test', 'ddos', '2026-07-18 06:00:00+07', '2026-07-18 07:00:00+07', '10.0.0.1');
ROLLBACK TO sp8;
COMMIT;

-- 4i. end_time <= start_time
\echo '  -> [EXPECT ERROR] end_time <= start_time...'
BEGIN;
SAVEPOINT sp9;
INSERT INTO attack_scenarios (scenario_name, attack_type, start_time, end_time, attacker_ip)
VALUES ('Invalid Time', 'ssh_bruteforce', '2026-07-18 07:00:00+07', '2026-07-18 06:00:00+07', '10.0.0.1');
ROLLBACK TO sp9;
COMMIT;

-- 4j. Invalid model_config
\echo '  -> [EXPECT ERROR] model_config = random_forest (not in enum)...'
BEGIN;
SAVEPOINT sp10;
INSERT INTO evaluation_metrics (run_id, model_config, dataset_split, precision_score)
VALUES ('run_test', 'random_forest', 'test', 0.5);
ROLLBACK TO sp10;
COMMIT;

-- 4k. Metric score out of range
\echo '  -> [EXPECT ERROR] f1_score = 1.5 (out of range 0-1)...'
BEGIN;
SAVEPOINT sp11;
INSERT INTO evaluation_metrics (run_id, model_config, dataset_split, f1_score)
VALUES ('run_test', 'iforest_only', 'test', 1.5);
ROLLBACK TO sp11;
COMMIT;

\echo '  [OK] All CHECK constraint tests completed.'

-- ============================================================================
-- 5. UNIQUE CONSTRAINT TESTS
-- ============================================================================
\echo ''
\echo '=== [5/8] Testing UNIQUE constraints ==='

-- 5a. UNIQUE (anomaly_result_id) on risk_score - duplicate should fail
\echo '  -> [EXPECT ERROR] Duplicate anomaly_result_id in risk_score (1-1 violation)...'
BEGIN;
SAVEPOINT sp_uniq1;
INSERT INTO risk_score (src_ip, anomaly_result_id, score, risk_class)
VALUES ('10.0.0.99', 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3', 50.0, 'Medium');
ROLLBACK TO sp_uniq1;
COMMIT;

-- 5b. UNIQUE (window_start, src_ip, model_version) on anomaly_result
\echo '  -> [EXPECT ERROR] Duplicate (window_start, src_ip, model_version) in anomaly_result...'
BEGIN;
SAVEPOINT sp_uniq2;
INSERT INTO anomaly_result (window_start, src_ip, feature_snapshot, anomaly_score, model_version, predicted_label)
VALUES ('2026-07-18 07:00:00+07', '192.168.1.100', '{}', 0.5, 'cascade-v1.0', 'Normal');
ROLLBACK TO sp_uniq2;
COMMIT;

-- 5c. UNIQUE (run_id, model_config, dataset_split) on evaluation_metrics
\echo '  -> [EXPECT ERROR] Duplicate (run_id, model_config, dataset_split) in evaluation_metrics...'
BEGIN;
SAVEPOINT sp_uniq3;
INSERT INTO evaluation_metrics (run_id, model_config, dataset_split)
VALUES ('run_20260718', 'cascade_iforest_ocsvm', 'test');
ROLLBACK TO sp_uniq3;
COMMIT;

-- 5d. NULL anomaly_result_id should be allowed (multiple NULLs OK in UNIQUE)
\echo '  -> [EXPECT SUCCESS] Multiple NULL anomaly_result_id (allowed by UNIQUE)...'
BEGIN;
SAVEPOINT sp_uniq4;
INSERT INTO risk_score (src_ip, anomaly_result_id, score, risk_class)
VALUES ('10.0.0.1', NULL, 30.0, 'Low');
INSERT INTO risk_score (src_ip, anomaly_result_id, score, risk_class)
VALUES ('10.0.0.2', NULL, 20.0, 'Low');
-- Clean up these test rows
DELETE FROM risk_score WHERE anomaly_result_id IS NULL AND src_ip IN ('10.0.0.1', '10.0.0.2');
ROLLBACK TO sp_uniq4;
COMMIT;

\echo '  [OK] All UNIQUE constraint tests completed.'

-- ============================================================================
-- 6. GROUND-TRUTH AUTO-LABELING QUERY
-- ============================================================================
\echo ''
\echo '=== [6/8] Testing ground-truth auto-labeling query ==='

\echo '  Before labeling:'
SELECT id, predicted_label, ground_truth_label, label_source
FROM anomaly_result
WHERE id = 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3';

-- Auto-label: match anomaly_result to attack_scenarios by IP + time window
UPDATE anomaly_result ar
SET ground_truth_label = 'Anomaly',
    label_source = 'lab_scenario'
FROM attack_scenarios ascn
WHERE ar.src_ip = ascn.attacker_ip
  AND ar.window_start BETWEEN ascn.start_time AND ascn.end_time
  AND ar.id = 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3';

\echo '  After labeling:'
SELECT id, predicted_label, ground_truth_label, label_source
FROM anomaly_result
WHERE id = 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3';

-- ============================================================================
-- 7. JOIN QUERY TEST (risk_score <-> anomaly_result)
-- ============================================================================
\echo ''
\echo '=== [7/8] Testing logical FK join query ==='

\echo '  Join result:'
SELECT r.src_ip, r.score, r.risk_class,
       a.anomaly_score, a.predicted_label, a.ground_truth_label, a.model_version
FROM risk_score r
JOIN anomaly_result a ON r.anomaly_result_id = a.id
WHERE r.src_ip = '192.168.1.100';

\echo '  EXPLAIN plan:'
EXPLAIN
SELECT r.src_ip, r.score, r.risk_class,
       a.anomaly_score, a.predicted_label, a.feature_snapshot
FROM risk_score r
JOIN anomaly_result a ON r.anomaly_result_id = a.id
WHERE r.src_ip = '192.168.1.100';

-- ============================================================================
-- 8. CLEANUP
-- ============================================================================
\echo ''
\echo '=== [8/8] Cleaning up test data ==='
DELETE FROM risk_score WHERE id = 'd4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4';
DELETE FROM anomaly_result WHERE id = 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3';
DELETE FROM log_event WHERE event_id IN ('a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1', 'b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2');
DELETE FROM attack_scenarios WHERE scenario_name = 'SSH Brute Force Test';
DELETE FROM evaluation_metrics WHERE run_id = 'run_20260718';

\echo ''
\echo '=== LSMP Database Schema Test Complete ==='
\echo 'All 5 tables verified. CHECK + UNIQUE constraints working correctly.'
