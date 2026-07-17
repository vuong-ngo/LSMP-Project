-- ============================================================================
-- LSMP Database Schema Initialization Script
-- Target Database: PostgreSQL with TimescaleDB Extension
-- ============================================================================

-- Kích hoạt extension hỗ trợ sinh mã UUID ngẫu nhiên
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 9.1 LOG_EVENT (Bảng lưu trữ logs/alerts cấu trúc nhận từ Wazuh Manager)
-- ============================================================================
CREATE TABLE log_event (
    event_id        UUID DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMP NOT NULL,
    source_ip       VARCHAR(45),
    username        VARCHAR(100),
    event_type      VARCHAR(20) NOT NULL CHECK (event_type IN ('auth', 'nginx')),
    severity        INT NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 15),
    raw_log         TEXT NOT NULL,
    parsed_json     JSONB,
    agent_id        VARCHAR(50),
    PRIMARY KEY (event_id, timestamp)
);

-- Chỉ mục tối ưu hóa cho truy vấn theo IP và thời gian (vẽ biểu đồ dashboard)
CREATE INDEX idx_log_event_srcip_time ON log_event (source_ip, timestamp DESC);
-- Chỉ mục tối ưu hóa cho truy vấn theo thiết bị giám sát (Agent)
CREATE INDEX idx_log_event_agent ON log_event (agent_id, timestamp DESC);


-- ============================================================================
-- 9.2 ANOMALY_RESULT (Bảng lưu trữ kết quả phân tích AI & Đặc trưng hành vi)
-- ============================================================================
CREATE TABLE anomaly_result (
    id                  UUID DEFAULT uuid_generate_v4(),
    window_start        TIMESTAMP NOT NULL,               -- Mốc bắt đầu cửa sổ trượt 60 giây
    src_ip              VARCHAR(45) NOT NULL,
    event_id            UUID,                             -- Khóa ngoại logic trỏ tới log_event(event_id)
    feature_snapshot    JSONB NOT NULL,                   -- Snapshot chứa 14 đặc trưng AI phục vụ retrain
    anomaly_score       FLOAT NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),
    model_version       VARCHAR(50) NOT NULL,
    predicted_label     VARCHAR(10) NOT NULL CHECK (predicted_label IN ('Normal','Anomaly')),
    ground_truth_label  VARCHAR(10) CHECK (ground_truth_label IN ('Normal','Anomaly', NULL)),
    label_source        VARCHAR(30),                      -- 'lab_scenario' / 'analyst_confirmed' / NULL
    PRIMARY KEY (id, window_start),
    UNIQUE (window_start, src_ip, model_version)
);

-- Chỉ mục cho IP và thời gian đánh giá bất thường
CREATE INDEX idx_anomaly_srcip_time ON anomaly_result (src_ip, window_start DESC);
-- Chỉ mục lọc nhanh dữ liệu đã có nhãn kiểm định để huấn luyện lại AI
CREATE INDEX idx_anomaly_label ON anomaly_result (ground_truth_label) WHERE ground_truth_label IS NOT NULL;


-- ============================================================================
-- 9.3 RISK_SCORE (Bảng lưu trữ điểm rủi ro cuối cùng hiển thị trên Dashboard)
-- ============================================================================
CREATE TABLE risk_score (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    src_ip              VARCHAR(45) NOT NULL,             -- IP nguồn bị đánh giá rủi ro (đối tượng giám sát)
    asset_id            VARCHAR(50),                      -- Thiết bị/Host chịu ảnh hưởng
    anomaly_result_id   UUID,                             -- Khóa ngoại logic trỏ tới anomaly_result(id)
    ai_component        FLOAT,                            -- Thành phần đóng góp của AI (alpha * anomaly_score)
    rule_component       FLOAT,                            -- Thành phần đóng góp của Wazuh (beta * severity)
    score                FLOAT NOT NULL CHECK (score BETWEEN 0 AND 100),
    risk_class           VARCHAR(10) CHECK (risk_class IN ('Low','Medium','High','Critical')),
    timestamp            TIMESTAMP NOT NULL DEFAULT now()
);

-- Chỉ mục cho IP và thời gian đánh giá rủi ro
CREATE INDEX idx_risk_srcip_time ON risk_score (src_ip, timestamp DESC);
-- Chỉ mục lọc phân cấp độ nguy hiểm để Dashboard query nhanh
CREATE INDEX idx_risk_class ON risk_score (risk_class, timestamp DESC);


-- ============================================================================
-- 9.4 ATTACK_SCENARIOS (Bảng phụ trợ lưu mốc thời gian kịch bản chạy Lab)
-- ============================================================================
CREATE TABLE attack_scenarios (
    id              SERIAL PRIMARY KEY,
    scenario_name   VARCHAR(100) NOT NULL,
    attack_type     VARCHAR(50) NOT NULL,
    start_time      TIMESTAMP NOT NULL,
    end_time        TIMESTAMP NOT NULL,
    attacker_ip     VARCHAR(45) NOT NULL,
    CHECK (end_time > start_time)
);


-- ============================================================================
-- CẤU HÌNH TIMESCALEDB HYPERTABLES (Tối ưu hóa ghi logs chuỗi thời gian lớn)
-- ============================================================================
-- Lưu ý: Cần kích hoạt extension TimescaleDB trên database trước khi chạy lệnh này.
-- Nếu chạy trên Postgres thuần túy, vui lòng bỏ qua các câu lệnh dưới đây.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- Phân vùng bảng log_event theo ngày (1 day interval) để chống nghẽn ghi log thô
        PERFORM create_hypertable('log_event', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
        
        -- Phân vùng bảng anomaly_result theo tuần (7 days interval)
        PERFORM create_hypertable('anomaly_result', 'window_start', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
        
        RAISE NOTICE 'TimescaleDB hypertables successfully initialized.';
    ELSE
        RAISE NOTICE 'TimescaleDB extension not found. Running on standard PostgreSQL partitioning.';
    END IF;
END $$;
