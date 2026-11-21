"""Low-interaction HTTP honeypot.

Every request — method, path, headers, body — becomes an event.
Responses are deliberately generic so scanners keep coming back.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .base import Sensor

MAX_BODY_BYTES = 4096


class HTTPHoneypotSensor(Sensor):
    """Wraps a stdlib threading HTTP server as a honeypot sensor."""

    def start(self):
        writer, name = self.writer, self.name

        class Handler(_RequestLogger):
            honeypot_writer = writer
            honeypot_name = name

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request, client_address):
                pass  # a honeypot ignores malformed clients

        self._server = Server((self.bind, self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"sensor-{self.name}", daemon=True)
        self._thread.start()

    def stop(self):
        server = getattr(self, "_server", None)
        if server:
            server.shutdown()
            server.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)


class _RequestLogger(BaseHTTPRequestHandler):
    honeypot_writer = None
    honeypot_name = "http"
    protocol_version = "HTTP/1.1"

    def _capture(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = b""
        if 0 < length <= MAX_BODY_BYTES:
            body = self.rfile.read(length)
        self.honeypot_writer.write(
            sensor=self.honeypot_name,
            protocol="http",
            event_type="request",
            src_ip=self.client_address[0],
            src_port=self.client_address[1],
            details={
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body.decode("utf-8", "replace"),
            },
        )

    def _respond(self, status=404):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle(self):
        self._capture()
        self._respond()

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception:
            self.close_connection = True

    def log_message(self, fmt, *args):
        pass  # events are the log; keep stderr clean
