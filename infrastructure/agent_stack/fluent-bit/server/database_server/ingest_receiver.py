# ============================================================================
# file: database_server/ingest_receiver.py
# Chay tren MAY DATABASE & AI (Server B), cung host voi lsmp-redis.
#
# Cau noi nhe giua Fluent Bit (output "http", format "json_lines", chay o
# Server A - may Wazuh, qua mang that) va Redis Stream (XADD) - thay the cho
# output plugin "redis" cua Fluent Bit von KHONG TON TAI trong image chinh
# thuc (chi co plugin ben thu 3, va cac plugin do cung khong ho tro XADD).
#
# Co xac thuc bang token (header X-Ingest-Token) vi day la endpoint HTTP mo
# ra mang that giua 2 may - khac voi ban chay chung 1 host truoc do.
# Cố tinh chi dung http.server built-in (khong FastAPI/Flask) de giu dung
# tinh than "nhe" cua kien truc chong nghen ban dau.
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
INGEST_TOKEN   = os.getenv("INGEST_TOKEN")  # bat buoc, khong co gia tri mac dinh

if not INGEST_TOKEN:
    logger.critical("INGEST_TOKEN chua duoc thiet lap - tu choi khoi dong (tranh mo endpoint khong xac thuc ra mang that).")
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

        # Xac thuc bang shared secret token - HTTP tu no khong co auth nhu
        # Redis AUTH, phai tu them lop nay vi endpoint nay mo ra mang that.
        token = self.headers.get("X-Ingest-Token")
        if token != INGEST_TOKEN:
            logger.warning(f"Tu choi request khong hop le tu {self.address_string()} (sai/thieu token).")
            self.send_response(401)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
        except Exception as e:
            logger.error(f"Khong doc duoc request body: {e}")
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
                logger.warning(f"Bo qua ban ghi khong hop le: {e}")

        logger.info(f"Da day {accepted} ban ghi vao Redis Stream '{STREAM_KEY}' ({failed} bi loai)")

        if failed > 0 and accepted == 0:
            self.send_response(422)
        else:
            self.send_response(200)
        self.end_headers()


def main():
    logger.info(f"Ket noi Redis tai {REDIS_HOST}:{REDIS_PORT}")
    try:
        redis_client.ping()
        logger.info("Ket noi Redis thanh cong.")
    except Exception as e:
        logger.critical(f"Khong the ket noi Redis: {e}")
        sys.exit(1)

    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), IngestHandler)
    logger.info(f"LSMP Ingest Receiver dang lang nghe tai 0.0.0.0:{LISTEN_PORT}/ingest")
    server.serve_forever()


if __name__ == "__main__":
    main()
