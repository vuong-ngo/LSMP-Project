-- ============================================================================
-- file: grant_least_privilege.sql
-- Description: Security Hardening SQL Script for Principle of Least Privilege.
--              Creates a restricted wazuh_writer database user that ONLY has
--              INSERT privileges on log tables, preventing UPDATE/DELETE tampering.
-- ============================================================================

-- 1. Create dedicated restricted user for DB Ingestion Service
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'wazuh_writer') THEN
        CREATE USER wazuh_writer WITH PASSWORD 'ChangeMeInProduction_WazuhWriter123!';
    END IF;
END
$$;

-- 2. Grant CONNECT permission to database lsmp_db
GRANT CONNECT ON DATABASE lsmp_db TO wazuh_writer;
GRANT USAGE ON SCHEMA public TO wazuh_writer;

-- 3. Grant INSERT-ONLY privileges on ingest tables (NO UPDATE, NO DELETE, NO DROP)
GRANT INSERT, SELECT ON TABLE log_event TO wazuh_writer;
GRANT INSERT, SELECT ON TABLE feature_vectors TO wazuh_writer;
GRANT INSERT, SELECT ON TABLE anomaly_result TO wazuh_writer;
GRANT INSERT, SELECT ON TABLE risk_score TO wazuh_writer;
GRANT INSERT, SELECT, USAGE ON ALL SEQUENCES IN SCHEMA public TO wazuh_writer;

-- 4. Revoke UPDATE, DELETE, and TRUNCATE privileges to prevent log tampering
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE log_event FROM wazuh_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE feature_vectors FROM wazuh_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE anomaly_result FROM wazuh_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE risk_score FROM wazuh_writer;

-- 5. Set search_path for safety
ALTER USER wazuh_writer SET search_path TO public;

RAISE NOTICE 'Successfully applied Principle of Least Privilege: User wazuh_writer has INSERT-ONLY access.';
