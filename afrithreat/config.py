"""Configuration loading and defaults (stdlib JSON only)."""

import copy
import json
from pathlib import Path

DEFAULT_CONFIG = {
    "sensors": [
        {"name": "http-1", "protocol": "http", "port": 8080, "bind": "127.0.0.1"},
        {"name": "telnet-1", "protocol": "telnet", "port": 2323, "bind": "127.0.0.1"},
        {"name": "ssh-1", "protocol": "ssh", "port": 2222, "bind": "127.0.0.1"},
    ],
    "data_dir": "data",
    "report": {
        "title": "AFRITHREAT Weekly Threat Report",
        "lookback_hours": 168,
    },
    "limits": {
        "max_line_bytes": 4096,
        "socket_timeout": 30.0,
        "max_connections_per_ip": 200,
    },
    "collector": {
        # sensor-side: ship local events to the central collect-server
        "sensor_host": None,       # None → socket.gethostname()
        "ingest_url": "http://127.0.0.1:8090/ingest",
        "token": None,             # must match ingest.token on the central host
        "batch_lines": 500,
        "timeout": 15.0,
    },
    "ingest": {
        # central-side: the collect-server itself
        "bind": "127.0.0.1",
        "port": 8090,
        "token": None,             # must be set or the server refuses to start
        "max_body_bytes": 8388608,
        "max_events_per_batch": 5000,
        "max_event_bytes": 65536,
    },
}


def load_config(path=None):
    """Return a config dict: defaults deep-merged with the JSON at *path*.

    A missing file is not an error — defaults are safe (localhost binds).
    """
    config = copy.deepcopy(DEFAULT_CONFIG)
    if path and Path(path).exists():
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        _deep_merge(config, raw)
    return config


def _deep_merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
