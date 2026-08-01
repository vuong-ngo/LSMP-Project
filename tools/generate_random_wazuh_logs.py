#!/usr/bin/env python3
# ============================================================================
# file: scripts/generate_random_wazuh_logs.py
# Description: Generates realistic random Wazuh security alert logs and inserts
#              them into PostgreSQL (log_event table) or Redis stream.
# ============================================================================

import os
import sys
import uuid
import json
import random
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add project root directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from sqlalchemy import create_engine, text
except ImportError:
    print("❌ SQLAlchemy is not installed. Installing required dependencies...")
    os.system("pip install sqlalchemy psycopg2-binary redis pandas numpy rich")
    from sqlalchemy import create_engine, text

# Sample datasets for realistic log generation
NORMAL_IPS = ["192.168.1.50", "192.168.1.105", "10.0.1.15", "10.0.1.20", "192.168.1.220"]
ATTACK_IPS = ["173.234.31.186", "202.100.179.208", "10.0.4.15", "185.220.101.5", "45.33.32.156"]

HOSTNAMES = ["web-server-prod-01", "db-server-main", "auth-gateway-02", "workstation-hr-05", "api-server-01"]
USERNAMES = ["root", "admin", "postgres", "ubuntu", "webmaster", "deploy", "john_doe", "guest"]
AGENTS = ["001 (wazuh-manager)", "002 (web-server)", "003 (db-server)", "004 (dmz-proxy)"]

WAZUH_RULES = [
    {"id": 5710, "level": 5, "description": "sshd: Attempt to login using non-existent user", "group": "auth"},
    {"id": 5716, "level": 10, "description": "sshd: Authentication failed (possible brute force attack)", "group": "auth"},
    {"id": 5720, "level": 12, "description": "sshd: Multiple authentication failures from same IP", "group": "auth"},
    {"id": 5715, "level": 3, "description": "sshd: Successful authentication for user root", "group": "auth"},
    {"id": 31101, "level": 5, "description": "nginx: Accessing forbidden directory (403 Forbidden)", "group": "nginx"},
    {"id": 31108, "level": 14, "description": "nginx: SQL Injection attack detected in URI parameter", "group": "nginx"},
    {"id": 31151, "level": 15, "description": "nginx: Path traversal attempt detected (/etc/passwd)", "group": "nginx"},
    {"id": 31103, "level": 2, "description": "nginx: Normal HTTP GET request (200 OK)", "group": "nginx"},
]


def generate_wazuh_alert(is_attack: bool = False, timestamp: datetime = None) -> dict:
    """Generates a single, realistic Wazuh 4.x JSON alert data structure."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    
    source_ip = random.choice(ATTACK_IPS) if is_attack else random.choice(NORMAL_IPS)
    source_host = random.choice(HOSTNAMES)
    username = random.choice(USERNAMES)
    agent_info = random.choice(AGENTS)
    agent_id = agent_info.split()[0]

    # Select appropriate rule based on whether it's an attack or normal log
    if is_attack:
        rule = random.choice([r for r in WAZUH_RULES if r["level"] >= 10])
    else:
        rule = random.choice([r for r in WAZUH_RULES if r["level"] < 10])

    event_type = "auth" if rule["group"] == "auth" else "nginx"
    severity = rule["level"]

    # Construct raw syslog / web log string
    if event_type == "auth":
        if is_attack:
            raw_log = f"{timestamp.strftime('%b %d %H:%M:%S')} {source_host} sshd[{random.randint(10000, 30000)}]: Failed password for invalid user {username} from {source_ip} port {random.randint(30000, 65000)} ssh2"
        else:
            raw_log = f"{timestamp.strftime('%b %d %H:%M:%S')} {source_host} sshd[{random.randint(10000, 30000)}]: Accepted password for {username} from {source_ip} port {random.randint(30000, 65000)} ssh2"
    else:
        status_code = random.choice([403, 404, 500]) if is_attack else 200
        uri = "/admin/config.php?id=1' OR '1'='1" if is_attack else "/api/v1/health"
        raw_log = f'{source_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {uri} HTTP/1.1" {status_code} {random.randint(100, 5000)} "-" "Mozilla/5.0"'

    # Construct full parsed JSON matching Wazuh alert format
    parsed_json = {
        "timestamp": timestamp.isoformat(),
        "agent": {"id": agent_id, "name": source_host, "ip": "192.168.1.10"},
        "rule": {
            "id": str(rule["id"]),
            "level": rule["level"],
            "description": rule["description"],
            "groups": [rule["group"], "security"]
        },
        "data": {
            "srcip": source_ip,
            "srcuser": username,
            "system_name": source_host
        },
        "location": "/var/log/auth.log" if event_type == "auth" else "/var/log/nginx/access.log"
    }

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_host": source_host,
        "username": username,
        "event_type": event_type,
        "severity": severity,
        "rule_id": rule["id"],
        "raw_log": raw_log,
        "parsed_json": json.dumps(parsed_json),
        "agent_id": agent_id,
        "is_attack": is_attack
    }


def push_to_postgres(logs: list, db_url: str):
    """Inserts a batch of log_event records directly into PostgreSQL."""
    print(f"🔌 Connecting to PostgreSQL at: {db_url}...")
    engine = create_engine(db_url)

    insert_query = text("""
        INSERT INTO log_event (
            event_id, "timestamp", source_ip, source_host, username,
            event_type, severity, rule_id, raw_log, parsed_json, agent_id
        ) VALUES (
            :event_id, :timestamp, :source_ip, :source_host, :username,
            :event_type, :severity, :rule_id, :raw_log, :parsed_json, :agent_id
        )
    """)

    with engine.begin() as conn:
        for log in logs:
            conn.execute(insert_query, {
                "event_id": log["event_id"],
                "timestamp": log["timestamp"],
                "source_ip": log["source_ip"],
                "source_host": log["source_host"],
                "username": log["username"],
                "event_type": log["event_type"],
                "severity": log["severity"],
                "rule_id": log["rule_id"],
                "raw_log": log["raw_log"],
                "parsed_json": log["parsed_json"],
                "agent_id": log["agent_id"]
            })

    print(f"✅ Successfully inserted {len(logs)} log records into 'log_event' table in PostgreSQL!")


def main():
    parser = argparse.ArgumentParser(description="Generate batch of random Wazuh log alerts into PostgreSQL.")
    parser.add_argument("--count", type=int, default=50, help="Number of random log events to generate (default: 50)")
    parser.add_argument("--attack-ratio", type=float, default=0.3, help="Ratio of attack logs vs normal logs (0.0 to 1.0, default: 0.3)")
    parser.add_argument("--db-url", type=str, default=None, help="Database connection URL (defaults to DATABASE_URL in environment or localhost)")
    
    args = parser.parse_args()

    db_url = args.db_url or os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "postgresql://postgres:postgres@localhost:5432/lsmp_db"

    print("=" * 70)
    print("🚀 LSMP - RANDOM WAZUH LOG GENERATOR & DATABASE POPULATOR")
    print(f"📊 Total Records to Generate: {args.count}")
    print(f"⚠️ Attack Log Ratio         : {int(args.attack_ratio * 100)}%")
    print(f"💾 Target Database          : {db_url}")
    print("=" * 70)

    now = datetime.now(timezone.utc)
    logs = []

    num_attacks = 0
    for i in range(args.count):
        is_attack = random.random() < args.attack_ratio
        if is_attack:
            num_attacks += 1
        # Spread timestamps over the past 2 hours
        ts = now - timedelta(seconds=random.randint(0, 7200))
        log = generate_wazuh_alert(is_attack=is_attack, timestamp=ts)
        logs.append(log)

    print(f"📦 Generated {len(logs)} logs ({num_attacks} attack logs, {len(logs) - num_attacks} normal logs).")

    try:
        push_to_postgres(logs, db_url)
    except Exception as e:
        print(f"\n❌ Error inserting logs into database: {e}")
        print("💡 Hint: Make sure PostgreSQL container 'lsmp-postgres' is running and DATABASE_URL is correct.")
        sys.exit(1)


if __name__ == "__main__":
    main()
