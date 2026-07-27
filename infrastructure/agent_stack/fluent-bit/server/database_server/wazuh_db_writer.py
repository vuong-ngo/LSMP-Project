# ============================================================================
# file: wazuh_db_writer.py
# Description: Background Python service to consume Wazuh alerts from Redis
#              and batch insert them into PostgreSQL (log_event table).
# ============================================================================

import os
import sys
import json
import uuid
import time
import re
import logging
import redis
from datetime import datetime, timezone
from sqlalchemy import create_engine, text

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d]: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("wazuh-db-writer")

# Environment Configurations
REDIS_HOST = os.getenv("REDIS_HOST", "lsmp-redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@lsmp-postgres:5432/lsmp_db")

STREAM_KEY = "wazuh_stream"
CONSUMER_GROUP = "db_writers"
CONSUMER_NAME = os.getenv("HOSTNAME", "writer_1")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 500))
BATCH_TIMEOUT = float(os.getenv("BATCH_TIMEOUT", 2.0))

# IP validation regex for PostgreSQL INET type
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$')

def init_db_and_redis():
    """Initializes Redis stream consumer group and PostgreSQL database connection."""
    logger.info(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD)

    # Create consumer group if not exists
    try:
        r.xgroup_create(STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info(f"Created new Redis Stream consumer group '{CONSUMER_GROUP}' on key '{STREAM_KEY}'")
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.info(f"Consumer group '{CONSUMER_GROUP}' already exists on key '{STREAM_KEY}'")
        else:
            logger.error(f"Failed to create consumer group: {e}")
            raise e

    logger.info("Initializing PostgreSQL database client engine...")
    try:
        engine = create_engine(DATABASE_URL, pool_size=5, max_overflow=10)
        # Test connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Successfully connected to PostgreSQL database.")
    except Exception as e:
        logger.critical(f"Failed to connect to database: {e}")
        raise e

    return r, engine

def parse_wazuh_alert(raw_data: str) -> dict:
    """Parses raw Wazuh 4.x alert JSON and maps it to log_event schema fields accurately."""
    try:
        if isinstance(raw_data, bytes):
            raw_data = raw_data.decode("utf-8")
        alert = json.loads(raw_data) if isinstance(raw_data, str) else raw_data

        # 1. Extract and validate source_ip (INET / VARCHAR(45) constraint)
        src_ip = (
            alert.get("data", {}).get("srcip") or
            alert.get("data", {}).get("src_ip") or
            alert.get("data", {}).get("dstip") or
            alert.get("agent", {}).get("ip")
        )

        if src_ip in ["any", "127.0.0.1", "localhost", None] or not src_ip:
            # Fallback to agent IP if srcip is local/any
            agent_ip = alert.get("agent", {}).get("ip")
            if agent_ip and agent_ip != "127.0.0.1":
                src_ip = agent_ip
            else:
                src_ip = None
        else:
            src_ip = str(src_ip).strip()
            if not IP_PATTERN.match(src_ip):
                src_ip = None

        # 2. Extract username
        username = (
            alert.get("data", {}).get("dstuser") or
            alert.get("data", {}).get("srcuser") or
            alert.get("data", {}).get("systemuser") or
            alert.get("data", {}).get("user")
        )
        if username:
            username = str(username)[:100]

        # 3. Extract source_host
        source_host = (
            alert.get("agent", {}).get("name") or
            alert.get("agent", {}).get("hostname") or
            alert.get("data", {}).get("src_host") or
            alert.get("data", {}).get("hostname") or
            alert.get("predecoder", {}).get("hostname") or
            "wazuh-manager"
        )
        if source_host:
            source_host = str(source_host)[:100]

        # 4. Determine event_type (Strictly match schema.sql CHECK constraint: IN ('auth', 'nginx'))
        location = alert.get("location", "").lower()
        full_log_str = str(alert.get("full_log") or alert.get("log") or alert.get("message") or "").lower()

        if any(k in location or k in full_log_str for k in ["nginx", "apache", "web", "http"]):
            event_type = "nginx"
        else:
            event_type = "auth"  # Default to 'auth' to pass PostgreSQL CHECK (event_type IN ('auth', 'nginx'))

        # 5. Extract rule details & clamp severity (CHECK severity BETWEEN 0 AND 16)
        raw_sev = alert.get("rule", {}).get("level", 0)
        try:
            severity = int(raw_sev)
        except (ValueError, TypeError):
            severity = 0
        severity = min(max(severity, 0), 16)  # Clamp between 0 and 16

        rule_id = alert.get("rule", {}).get("id")
        try:
            rule_id = int(rule_id) if rule_id else None
        except (ValueError, TypeError):
            rule_id = None

        # 6. Extract timestamp
        timestamp_str = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

        # 7. Extract raw_log ensuring non-empty text
        raw_log = alert.get("full_log") or alert.get("log") or alert.get("message") or json.dumps(alert.get("data", {}))
        if not raw_log or raw_log == "{}":
            raw_log = json.dumps(alert)

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp_str,
            "source_ip": src_ip,
            "username": username,
            "event_type": event_type,
            "severity": severity,
            "rule_id": rule_id,
            "raw_log": str(raw_log),
            "parsed_json": json.dumps(alert),
            "agent_id": str(alert.get("agent", {}).get("id", "000"))[:50],
            "source_host": source_host
        }
    except Exception as e:
        logger.error(f"Error parsing raw Wazuh 4.x alert: {e}")
        return None

def write_to_postgres(engine, batch: list) -> bool:
    """Executes optimized batch inserts to PostgreSQL with row-by-row fallback."""
    if not batch:
        return True

    query = text("""
        INSERT INTO log_event (event_id, timestamp, source_ip, username, event_type, severity, rule_id, raw_log, parsed_json, agent_id, source_host)
        VALUES (:event_id, :timestamp, :source_ip, :username, :event_type, :severity, :rule_id, :raw_log, :parsed_json, :agent_id, :source_host)
    """)

    start_time = time.time()
    try:
        with engine.begin() as conn:
            conn.execute(query, batch)
        logger.info(f"Successfully wrote batch of {len(batch)} alerts to log_event in {time.time() - start_time:.4f}s")
        return True
    except Exception as e:
        logger.warning(f"Batch insert error ({e}). Retrying row-by-row to salvage valid critical alerts...")
        success_count = 0
        for item in batch:
            try:
                with engine.begin() as conn:
                    conn.execute(query, item)
                success_count += 1
            except Exception as single_err:
                logger.error(f"Single row insert failed for rule_id {item.get('rule_id')}: {single_err}")
        logger.info(f"Rescued {success_count}/{len(batch)} alerts row-by-row.")
        return success_count > 0

def main():
    try:
        r, engine = init_db_and_redis()
    except Exception as e:
        logger.critical(f"Initialization failed. Exiting... Error: {e}")
        sys.exit(1)

    logger.info("Wazuh Database Writer Service started successfully. Awaiting stream logs...")

    batch = []
    message_ids = []
    last_flush_time = time.time()

    # Recover any pending messages (PEL) left unacknowledged from previous crashes
    try:
        pending_streams = r.xreadgroup(CONSUMER_GROUP, CONSUMER_NAME, {STREAM_KEY: "0"}, count=BATCH_SIZE)
        if pending_streams:
            logger.info("Recovering pending unacknowledged messages from Redis PEL...")
            for stream, messages in pending_streams:
                for msg_id, payload in messages:
                    raw_data = payload.get(b"data") or list(payload.values())[0]
                    parsed = parse_wazuh_alert(raw_data.decode("utf-8"))
                    if parsed:
                        batch.append(parsed)
                    message_ids.append(msg_id)
            if batch:
                if write_to_postgres(engine, batch):
                    for msg_id in message_ids:
                        r.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)
                    logger.info(f"Recovered and acknowledged {len(message_ids)} pending messages.")
                    batch = []
                    message_ids = []
    except Exception as e:
        logger.warning(f"Pending message recovery check encounter exception: {e}")

    while True:
        try:
            # Read from group: '>' means only new messages that haven't been delivered to other consumers
            streams = r.xreadgroup(CONSUMER_GROUP, CONSUMER_NAME, {STREAM_KEY: ">"}, count=BATCH_SIZE, block=1000)

            if streams:
                for stream, messages in streams:
                    for msg_id, payload in messages:
                        # Extract payload
                        raw_data = payload.get(b"data") or list(payload.values())[0]
                        parsed = parse_wazuh_alert(raw_data.decode("utf-8"))

                        if parsed:
                            batch.append(parsed)
                        message_ids.append(msg_id)

            now = time.time()
            # Flush if batch limit is reached, or if timeout has elapsed with accumulated message IDs
            if len(batch) >= BATCH_SIZE or (len(message_ids) > 0 and (now - last_flush_time) >= BATCH_TIMEOUT):
                success = write_to_postgres(engine, batch)
                if success:
                    # Acknowledge processed messages in Redis
                    for msg_id in message_ids:
                        r.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)
                    logger.debug(f"Acknowledged {len(message_ids)} messages in Redis Stream.")
                    batch = []
                    message_ids = []
                    last_flush_time = now
                else:
                    # If DB write fails, wait a bit before retrying, do not acknowledge Redis
                    logger.warning("PostgreSQL write failed. Batch retained. Retrying in 5 seconds...")
                    time.sleep(5)

        except Exception as e:
            logger.error(f"Error in main polling loop: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()
