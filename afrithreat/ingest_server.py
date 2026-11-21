"""Central multi-host collector: authenticated HTTP ingest endpoint.

Sensor hosts ship their local event logs here with `afrithreat push`.
Every accepted event is tagged with the pushing host's declared
identity (`sensor_host`) and appended to the central event log with
its original timestamp preserved.

The bearer token is the authorization boundary: without one the
server refuses to start (fail closed). Everything is bounded —
body size, batch size, event size — so a flooded or hostile pusher
can never exhaust the collector.
"""

import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .events import EventWriter

MAX_SENSOR_HOST_CHARS = 200


class IngestError(Exception):
    """The ingest server cannot start or rejected a request."""


class _IngestHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Handler(BaseHTTPRequestHandler):
    server_version = "AFRITHREAT-Ingest/2.0"

    # -- plumbing -------------------------------------------------------

    def _respond(self, code, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        return hmac.compare_digest(parts[1].strip(),
                                   self.server.ingest_token)

    def log_message(self, fmt, *args):
        # one concise stderr line per request — cron/systemd friendly
        print(f"[ingest] {self.address_string()} {fmt % args}")

    # -- routes ---------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"ok": True})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/ingest":
            self._respond(404, {"error": "not found"})
            return
        if not self._authorized():
            self._respond(401, {"error": "missing or invalid token"})
            return
        try:
            body = self._read_body()
        except IngestError as exc:
            self._respond(exc.args[1], {"error": str(exc)})
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._respond(400, {"error": "body is not valid JSON"})
            return
        accepted, skipped = self._ingest(payload)
        if accepted is None:
            return  # _ingest already responded with an error
        self._respond(200, {"accepted": accepted, "skipped": skipped})

    # -- body handling ----------------------------------------------------

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise IngestError("missing Content-Length", 411) from None
        if length <= 0:
            raise IngestError("empty body", 400)
        if length > self.server.max_body_bytes:
            self.close_connection = True
            raise IngestError("body too large", 413)
        return self.rfile.read(length)

    # -- ingestion --------------------------------------------------------

    def _ingest(self, payload):
        """Validate the batch and append it; returns (accepted, skipped).

        Returns (None, None) if the batch shape was rejected (the
        error response is sent here).
        """
        if not isinstance(payload, dict):
            self._respond(400, {"error": "payload must be a JSON object"})
            return None, None
        sensor_host = payload.get("sensor_host")
        if (not isinstance(sensor_host, str)
                or not 0 < len(sensor_host) <= MAX_SENSOR_HOST_CHARS):
            self._respond(400, {"error": "bad or missing sensor_host"})
            return None, None
        events = payload.get("events")
        if not isinstance(events, list):
            self._respond(400, {"error": "bad or missing events list"})
            return None, None
        if len(events) > self.server.max_events_per_batch:
            self._respond(400, {"error": "too many events in one batch"})
            return None, None

        accepted = skipped = 0
        for event in events:
            if not isinstance(event, dict):
                skipped += 1
                continue
            event["sensor_host"] = sensor_host
            line = json.dumps(event, separators=(",", ":"))
            if len(line) > self.server.max_event_bytes:
                skipped += 1
                continue
            self.server.writer.append_line(line)
            accepted += 1
        return accepted, skipped


class IngestServer:
    """The central collector. Run with `afrithreat collect-server`."""

    def __init__(self, bind, port, token, data_dir,
                 max_body_bytes=8 * 1024 * 1024,
                 max_events_per_batch=5000,
                 max_event_bytes=65536):
        if not token:
            raise IngestError(
                "ingest.token is not set — the collector refuses to run "
                "unauthenticated (fail closed)")
        self._writer = EventWriter(data_dir)
        self._httpd = _IngestHTTPServer((bind, port), _Handler)
        self._httpd.ingest_token = token
        self._httpd.writer = self._writer
        self._httpd.max_body_bytes = max_body_bytes
        self._httpd.max_events_per_batch = max_events_per_batch
        self._httpd.max_event_bytes = max_event_bytes
        self._lock = threading.Lock()

    @property
    def port(self):
        """The bound port (resolves ephemeral port 0)."""
        return self._httpd.server_address[1]

    @property
    def events_path(self):
        return self._writer.path

    def serve_forever(self):
        self._httpd.serve_forever()

    def shutdown(self):
        self._httpd.shutdown()
        self._httpd.server_close()
