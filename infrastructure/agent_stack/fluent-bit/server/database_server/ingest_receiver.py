# ============================================================================
# file: database_server/ingest_receiver.py
# description: Runs on the DATABASE & AI SERVER (Server B), colocated with lsmp-redis.
# ============================================================================

import os
import sys
import json
import ssl
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

# TLS / HTTPS Configuration
USE_TLS        = os.getenv("USE_TLS", "false").lower() in ("true", "1", "yes")
SSL_CERT_FILE  = os.getenv("SSL_CERT_FILE", "/etc/ssl/certs/lsmp_ingest.crt")
SSL_KEY_FILE   = os.getenv("SSL_KEY_FILE", "/etc/ssl/certs/lsmp_ingest.key")
MAX_BODY_SIZE  = int(os.getenv("MAX_BODY_SIZE", 10 * 1024 * 1024))  # Default 10 MB payload limit

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
            if length > MAX_BODY_SIZE:
                logger.warning(f"Rejected oversized request ({length} bytes > limit {MAX_BODY_SIZE} bytes) from {self.address_string()}")
                self.send_response(413)  # Payload Too Large
                self.end_headers()
                return
            body = self.rfile.read(length).decode("utf-8", errors="replace")
        except Exception as e:
            logger.error(f"Failed to read request body: {e}")
            self.send_response(400)
            self.end_headers()
            return

        accepted, failed = 0, 0
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        
        if lines:
            pipe = redis_client.pipeline()
            for line in lines:
                try:
                    json.loads(line)
                    pipe.xadd(
                        STREAM_KEY,
                        {"data": line},
                        maxlen=STREAM_MAXLEN,
                        approximate=True,
                    )
                    accepted += 1
                except Exception as e:
                    failed += 1
                    logger.warning(f"Skipped invalid record: {e}")
            
            if accepted > 0:
                try:
                    pipe.execute()
                except Exception as e:
                    logger.error(f"Redis pipeline execution failed: {e}")
                    self.send_response(500)
                    self.end_headers()
                    return

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
    
    if USE_TLS:
        if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
            logger.critical(f"TLS enabled but certificate files not found: cert='{SSL_CERT_FILE}', key='{SSL_KEY_FILE}'")
            sys.exit(1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        logger.info(f"LSMP Ingest Receiver listening securely (HTTPS/TLS) at https://0.0.0.0:{LISTEN_PORT}/ingest")
    else:
        logger.info(f"LSMP Ingest Receiver listening at http://0.0.0.0:{LISTEN_PORT}/ingest (HTTP - Plaintext)")
        
    server.serve_forever()


if __name__ == "__main__":
    main()

