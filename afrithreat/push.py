"""Ship local events to the central collector (`afrithreat collect-server`).

The push cursor counts non-empty lines of the local JSONL log and is
stored in data/push_state.json. It only advances after the server
confirms a batch, so a failed or rejected push simply retries on the
next run — nothing is lost and nothing is sent twice.
"""

import json
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path


class PushError(Exception):
    """Push failed — remaining lines stay queued for the next run."""


def push(config):
    """Push all pending local events; return a summary dict."""
    cfg = config.get("collector", {})
    url = cfg.get("ingest_url")
    token = cfg.get("token")
    if not url or not token:
        raise PushError("collector.ingest_url and collector.token must "
                        "both be set (see config.json)")
    sensor_host = cfg.get("sensor_host") or socket.gethostname()
    batch_lines = max(1, int(cfg.get("batch_lines", 500)))
    timeout = float(cfg.get("timeout", 15.0))

    data_dir = Path(config["data_dir"])
    lines = _read_lines(data_dir / "events.jsonl")
    state_path = data_dir / "push_state.json"
    cursor = _load_cursor(state_path)
    if len(lines) < cursor:
        cursor = 0  # the local log was rotated or reset — push everything

    pushed = skipped = batches = 0
    pending = lines[cursor:]
    for start in range(0, len(pending), batch_lines):
        batch = pending[start:start + batch_lines]
        events, malformed = _parse_events(batch)
        skipped += malformed
        if events:
            pushed += _post(url, token, sensor_host, events, timeout)
            batches += 1
        cursor += len(batch)
        _save_cursor(state_path, cursor)
    return {"pushed": pushed, "skipped": skipped, "batches": batches,
            "cursor": cursor, "sensor_host": sensor_host}


# -- helpers -----------------------------------------------------------

def _read_lines(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return [line for line in (raw.strip() for raw in fh) if line]


def _parse_events(batch):
    events = []
    malformed = 0
    for line in batch:
        try:
            events.append(json.loads(line))
        except ValueError:
            malformed += 1
    return events, malformed


def _post(url, token, sensor_host, events, timeout):
    """POST one batch; return the server's accepted count."""
    payload = json.dumps({"sensor_host": sensor_host, "events": events},
                         separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise PushError(f"ingest server rejected the batch: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise PushError(f"cannot reach the ingest server: {reason}") from None
    if not isinstance(body, dict) or not isinstance(body.get("accepted"), int):
        raise PushError("ingest server returned an unexpected response")
    return body["accepted"]


def _load_cursor(path):
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["pushed_lines"])
    except (OSError, ValueError, KeyError):
        return 0


def _save_cursor(path, cursor):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"pushed_lines": cursor}), encoding="utf-8")
    os.replace(tmp, path)
