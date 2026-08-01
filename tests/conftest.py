import pytest
import pandas as pd
from datetime import datetime, timedelta

@pytest.fixture
def sample_raw_logs():
    """Returns a mock DataFrame of raw web and authentication logs."""
    data = [
        # Normal web log
        {
            "src_ip": "192.168.1.100",
            "raw_message": '192.168.1.100 - - [15/Jul/2026:22:00:00 +0700] "GET /index.html HTTP/1.1" 200 4324',
            "parsed_json": {"status": "200", "url": "/index.html", "method": "GET", "user_agent": "Mozilla/5.0"}
        },
        # Nginx 404 scan log
        {
            "src_ip": "172.16.0.1",
            "raw_message": '172.16.0.1 - - [15/Jul/2026:22:00:01 +0700] "GET /admin/config.php HTTP/1.1" 404 120',
            "parsed_json": {"status": "404", "url": "/admin/config.php", "method": "GET", "user_agent": "Gobuster/v3.0"}
        },
        # SSH failed login log
        {
            "src_ip": "10.0.0.5",
            "raw_message": "sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 54322 ssh2",
            "parsed_json": {"user": "admin"}
        },
        # SSH success log
        {
            "src_ip": "10.0.0.5",
            "raw_message": "sshd[1234]: Accepted password for root from 10.0.0.5 port 54322 ssh2",
            "parsed_json": {"user": "root"}
        }
    ]
    return pd.DataFrame(data)

@pytest.fixture
def sample_features():
    """Returns a mock feature vectors DataFrame (14 features)."""
    base_time = datetime.now()
    data = []
    
    # 5 Normal vectors
    for i in range(5):
        data.append({
            "window_start": base_time - timedelta(minutes=i),
            "src_ip": f"192.168.1.{10 + i}",
            "login_fail_count": 0.0,
            "unique_failed_ip_count": 0.0,
            "fail_success_ratio": 0.0,
            "ip_entropy": 1.2,
            "hour_of_day": 12,
            "request_rate": 2.5,
            "status_4xx_rate": 0.02,
            "url_frequency": 0.3,
            "user_agent_entropy": 0.5,
            "method_distribution": 0.0,
            "time_window_count": 10.0,
            "burst_rate": 1.0,
            "sliding_window_count": 10.0,
            "ip_switch_frequency": 0.0,
            "label": "Normal",
            "label_source": "baseline_normal",
            "confidence": 1.0
        })
        
    # 2 Anomaly vectors (Brute force & Scanning profiles)
    data.append({
        "window_start": base_time,
        "src_ip": "172.16.0.99",
        "login_fail_count": 85.0, # high fail
        "unique_failed_ip_count": 2.0,
        "fail_success_ratio": 85.0,
        "ip_entropy": 0.1,
        "hour_of_day": 3,
        "request_rate": 0.0,
        "status_4xx_rate": 0.0,
        "url_frequency": 0.0,
        "user_agent_entropy": 0.0,
        "method_distribution": 0.0,
        "time_window_count": 85.0,
        "burst_rate": 15.0, # high burst
        "sliding_window_count": 85.0,
        "ip_switch_frequency": 3.0,
        "label": "Anomaly",
        "label_source": "lab_scenario",
        "confidence": 1.0
    })
    
    data.append({
        "window_start": base_time,
        "src_ip": "172.16.0.100",
        "login_fail_count": 0.0,
        "unique_failed_ip_count": 0.0,
        "fail_success_ratio": 0.0,
        "ip_entropy": 0.4,
        "hour_of_day": 15,
        "request_rate": 120.0, # high rate
        "status_4xx_rate": 0.9, # high errors
        "url_frequency": 0.95, # unique urls (scan)
        "user_agent_entropy": 0.05,
        "method_distribution": 0.4,
        "time_window_count": 7200.0,
        "burst_rate": 8.0,
        "sliding_window_count": 7200.0,
        "ip_switch_frequency": 0.0,
        "label": "Anomaly",
        "label_source": "lab_scenario",
        "confidence": 1.0
    })
    
    return pd.DataFrame(data)

@pytest.fixture
def sample_feature_df(sample_features):
    """Returns a mock feature vectors DataFrame (14 features)."""
    return sample_features

