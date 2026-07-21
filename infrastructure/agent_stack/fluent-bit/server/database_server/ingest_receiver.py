# ============================================================================
# file: database_server/ingest_receiver.py
# description: Runs on the DATABASE & AI SERVER (Server B), colocated with lsmp-redis.
# ============================================================================

import os
import sys
import json
import logging
import redis
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s]: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("lsmp-ingest")

REDIS_HOST     = os.getenv("REDIS_HOST", "lsmp-redis")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
STREAM_KEY     = os.getenv("STREAM_KEY", "wazuh_stream")
STREAM_MAXLEN  = int(os.getenv("STREAM_MAXLEN", 100000))
LISTEN_PORT    = int(os.getenv("LISTEN_PORT", 8080))
INGEST_TOKEN   = os.getenv("INGEST_TOKEN")  # Required, no default value

if not INGEST_TOKEN:
    logger.critical("INGEST_TOKEN is not set - refusing to start (to avoid exposing unauthenticated endpoints to the network).")
    sys.exit(1)

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD)


class IngestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.debug("%s - %s" % (self.address_string(), fmt % args))

    def do_POST(self):
        if self.path != "/ingest":
            self.send_response(404)
            self.end_headers()
            return

        # Authenticate using shared secret token - HTTP does not have native
        # auth like Redis AUTH, so we implement this layer since the endpoint
        # is exposed over the network.
        token = self.headers.get("X-Ingest-Token")
        if token != INGEST_TOKEN:
            logger.warning(f"Rejected invalid request from {self.address_string()} (missing or incorrect token).")
            self.send_response(401)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
        except Exception as e:
            logger.error(f"Failed to read request body: {e}")
            self.send_response(400)
            self.end_headers()
            return

        accepted, failed = 0, 0
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
                redis_client.xadd(
                    STREAM_KEY,
                    {"data": line},
                    maxlen=STREAM_MAXLEN,
                    approximate=True,
                )
                accepted += 1
            except Exception as e:
                failed += 1
                logger.warning(f"Skipped invalid record: {e}")

        logger.info(f"Pushed {accepted} records into Redis Stream '{STREAM_KEY}' ({failed} rejected)")

        if failed > 0 and accepted == 0:
            self.send_response(422)
        else:
            self.send_response(200)
        self.end_headers()


def main():
    logger.info(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")
    try:
        redis_client.ping()
        logger.info("Successfully connected to Redis.")
    except Exception as e:
        logger.critical(f"Could not connect to Redis: {e}")
        sys.exit(1)

    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), IngestHandler)
    logger.info(f"LSMP Ingest Receiver listening at 0.0.0.0:{LISTEN_PORT}/ingest")
    server.serve_forever()


if __name__ == "__main__":
    main()
