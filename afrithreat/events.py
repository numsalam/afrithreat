"""Structured event records and append-only JSONL persistence."""

import calendar
import json
import threading
import time
from pathlib import Path

SCHEMA_VERSION = 1
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now_iso():
    """Current UTC time as an ISO-8601 second-precision string."""
    return time.strftime(TS_FORMAT, time.gmtime())


def parse_ts(value):
    """Parse a UTC ISO string to epoch seconds, or None."""
    if not isinstance(value, str):
        return None
    try:
        return calendar.timegm(time.strptime(value, TS_FORMAT))
    except ValueError:
        return None


class EventWriter:
    """Thread-safe append-only JSONL event writer.

    All sensors funnel through a single writer so events from every
    protocol interleave into one ordered log.
    """

    def __init__(self, data_dir):
        self._path = Path(data_dir) / "events.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self):
        return self._path

    def write(self, sensor, protocol, event_type, src_ip,
              src_port=None, details=None):
        record = {
            "schema": SCHEMA_VERSION,
            "ts": utc_now_iso(),
            "sensor": sensor,
            "protocol": protocol,
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "details": details or {},
        }
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return record

    def append_line(self, line):
        """Append one pre-serialized JSONL line (ingest server path).

        The record was built and validated by the caller; its original
        timestamp and fields are preserved verbatim.
        """
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")


def iter_events(data_dir, lookback_hours=None):
    """Yield event dicts from the JSONL log, oldest first.

    *lookback_hours* skips events older than the cutoff. Malformed
    lines are skipped: collection must never crash because an
    attacker wrote weird bytes into the log.
    """
    path = Path(data_dir) / "events.jsonl"
    if not path.exists():
        return
    cutoff = None
    if lookback_hours is not None:
        cutoff = time.time() - lookback_hours * 3600.0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if cutoff is not None:
                ts = parse_ts(event.get("ts"))
                if ts is not None and ts < cutoff:
                    continue
            yield event
