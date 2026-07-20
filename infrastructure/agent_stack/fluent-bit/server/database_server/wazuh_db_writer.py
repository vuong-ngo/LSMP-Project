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
from datetime import datetime
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
    """Parses raw Wazuh alert JSON and maps it to log_event schema fields."""
    try:
        alert = json.loads(raw_data)
        
        # 1. Extract and validate source_ip (INET type constraint)
        src_ip = (
            alert.get("data", {}).get("srcip") or 
            alert.get("data", {}).get("src_ip") or 
            alert.get("data", {}).get("dstip")
        )
        if not src_ip and "agent" in alert:
            src_ip = alert.get("agent", {}).get("ip")
            
        if src_ip == "any" or not src_ip:
            src_ip = None
        else:
            # Strip potential whitespace
            src_ip = str(src_ip).strip()
            # Validate IP format to prevent INET syntax errors
            if not IP_PATTERN.match(src_ip):
                logger.warning(f"Invalid IP format '{src_ip}' detected, setting to NULL.")
                src_ip = None

        # 2. Extract username
        username = (
            alert.get("data", {}).get("dstuser") or 
            alert.get("data", {}).get("srcuser") or 
            alert.get("data", {}).get("systemuser")
        )
        if username:
            username = str(username)[:100] # Truncate to match VARCHAR(100)

        # 3. Determine event_type based on location path
        location = alert.get("location", "").lower()
        if "auth" in location or "secure" in location or "pam" in location:
            event_type = "auth"
        elif "nginx" in location or "apache" in location or "web" in location:
            event_type = "nginx"
        else:
            event_type = "auth" # Default fallback

        # 4. Extract rule details
        severity = alert.get("rule", {}).get("level", 0)
        try:
            severity = int(severity)
        except (ValueError, TypeError):
            severity = 0
            
        rule_id = alert.get("rule", {}).get("id")
        try:
            rule_id = int(rule_id) if rule_id else None
        except (ValueError, TypeError):
            rule_id = None

        # 5. Extract timestamp
        timestamp_str = alert.get("timestamp", datetime.utcnow().isoformat())

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp_str,
            "source_ip": src_ip,
            "username": username,
            "event_type": event_type,
            "severity": severity,
            "rule_id": rule_id,
            "raw_log": alert.get("full_log", ""),
            "parsed_json": json.dumps(alert),
            "agent_id": alert.get("agent", {}).get("id", "000")
        }
    except Exception as e:
        logger.error(f"Error parsing raw Wazuh alert: {e}")
        return None

def write_to_postgres(engine, batch: list) -> bool:
    """Executes optimized batch inserts to PostgreSQL."""
    if not batch:
        return True
        
    query = text("""
        INSERT INTO log_event (event_id, timestamp, source_ip, username, event_type, severity, rule_id, raw_log, parsed_json, agent_id)
        VALUES (:event_id, :timestamp, :source_ip, :username, :event_type, :severity, :rule_id, :raw_log, :parsed_json, :agent_id)
    """)
    
    start_time = time.time()
    try:
        with engine.begin() as conn:
            conn.execute(query, batch)
        logger.info(f"Successfully wrote batch of {len(batch)} alerts to log_event in {time.time() - start_time:.4f}s")
        return True
    except Exception as e:
        logger.error(f"Failed to execute batch insert into log_event: {e}")
        return False

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
            # Flush if batch limit is reached, or if timeout has elapsed
            if len(batch) >= BATCH_SIZE or (len(batch) > 0 and (now - last_flush_time) >= BATCH_TIMEOUT):
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
