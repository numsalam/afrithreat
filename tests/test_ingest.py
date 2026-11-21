"""End-to-end tests for the multi-host collector (push + ingest server)."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from afrithreat.events import EventWriter
from afrithreat.ingest_server import IngestError, IngestServer
from afrithreat.push import PushError, push

TOKEN = "test-token"


@pytest.fixture
def collector(tmp_path):
    """A running ingest server on an ephemeral port."""
    server = IngestServer("127.0.0.1", 0, TOKEN, str(tmp_path / "central"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


def _write_local_events(tmp_path, count=3):
    writer = EventWriter(str(tmp_path / "local"))
    records = [writer.write(sensor="ssh-1", protocol="ssh",
                            event_type="auth", src_ip=f"10.0.0.{i}",
                            details={"username": "root",
                                     "password": f"pw{i}"})
               for i in range(count)]
    return records


def _push_config(tmp_path, port, **overrides):
    cfg = {
        "sensor_host": "sensor-a",
        "ingest_url": f"http://127.0.0.1:{port}/ingest",
        "token": TOKEN,
        "batch_lines": 2,
        "timeout": 5.0,
    }
    cfg.update(overrides)
    return {"data_dir": str(tmp_path / "local"), "collector": cfg}


def _central_events(tmp_path):
    path = tmp_path / "central" / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line]


def _post(port, path, payload, token=TOKEN):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                     data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# -- push client ---------------------------------------------------------


def test_push_roundtrip_and_tagging(collector, tmp_path):
    records = _write_local_events(tmp_path, count=3)
    summary = push(_push_config(tmp_path, collector.port))
    assert summary["pushed"] == 3
    assert summary["batches"] == 2          # batch_lines=2 → 2+1
    assert summary["skipped"] == 0
    central = _central_events(tmp_path)
    assert len(central) == 3
    for original, event in zip(records, central):
        assert event["sensor_host"] == "sensor-a"
        assert event["ts"] == original["ts"]       # original time preserved
        assert event["src_ip"] == original["src_ip"]
    state = json.loads((tmp_path / "local" / "push_state.json").read_text())
    assert state["pushed_lines"] == 3


def test_push_idempotent(collector, tmp_path):
    _write_local_events(tmp_path, count=3)
    config = _push_config(tmp_path, collector.port)
    push(config)
    summary = push(config)
    assert summary["pushed"] == 0 and summary["batches"] == 0
    assert len(_central_events(tmp_path)) == 3


def test_push_rotation_resets_cursor(collector, tmp_path):
    _write_local_events(tmp_path, count=3)
    config = _push_config(tmp_path, collector.port)
    push(config)
    # simulate log rotation: a fresh, shorter local log
    local = tmp_path / "local" / "events.jsonl"
    local.unlink()
    _write_local_events(tmp_path, count=2)
    summary = push(config)
    assert summary["pushed"] == 2
    assert len(_central_events(tmp_path)) == 5


def test_failed_push_keeps_cursor(collector, tmp_path):
    _write_local_events(tmp_path, count=3)
    bad = _push_config(tmp_path, collector.port, token="wrong-token")
    with pytest.raises(PushError):
        push(bad)
    # nothing confirmed → no state written, nothing ingested
    assert not (tmp_path / "local" / "push_state.json").exists()
    assert _central_events(tmp_path) == []
    # a retry with the right token ships everything exactly once
    summary = push(_push_config(tmp_path, collector.port))
    assert summary["pushed"] == 3
    assert len(_central_events(tmp_path)) == 3


def test_push_skips_malformed_lines(collector, tmp_path):
    _write_local_events(tmp_path, count=1)
    with (tmp_path / "local" / "events.jsonl").open("a") as fh:
        fh.write("{not json}\n")
    summary = push(_push_config(tmp_path, collector.port))
    assert summary["pushed"] == 1
    assert summary["skipped"] == 1


def test_push_requires_config(tmp_path):
    with pytest.raises(PushError):
        push({"data_dir": str(tmp_path), "collector": {}})


# -- ingest server -------------------------------------------------------


def test_health_endpoint(collector):
    with urllib.request.urlopen(
            f"http://127.0.0.1:{collector.port}/health", timeout=5) as response:
        assert response.status == 200


def test_auth_enforced(collector, tmp_path):
    payload = {"sensor_host": "x", "events": []}
    assert _post(collector.port, "/ingest", payload, token=None)[0] == 401
    assert _post(collector.port, "/ingest", payload, token="nope")[0] == 401
    assert _central_events(tmp_path) == []


def test_unknown_paths_rejected(collector):
    assert _post(collector.port, "/nope", {})[0] == 404


def test_malformed_body_rejected(collector, tmp_path):
    assert _post(collector.port, "/ingest", b"not json")[0] == 400
    assert _post(collector.port, "/ingest", b"")[0] == 400
    assert _central_events(tmp_path) == []


def test_bad_batch_shapes_rejected(collector):
    port = collector.port
    assert _post(port, "/ingest", {"events": []})[0] == 400          # no host
    assert _post(port, "/ingest", {"sensor_host": "x"})[0] == 400    # no events
    assert _post(port, "/ingest", {"sensor_host": "x", "events": {}})[0] == 400
    assert _post(port, "/ingest", {"sensor_host": "x" * 500,
                                   "events": []})[0] == 400          # host too long


def test_non_dict_events_skipped(collector, tmp_path):
    event = {"schema": 1, "ts": "2026-11-21T00:00:00Z", "sensor": "s",
             "protocol": "ssh", "event_type": "auth", "src_ip": "1.2.3.4"}
    code, body = _post(collector.port, "/ingest",
                       {"sensor_host": "sensor-b",
                        "events": [event, "junk", 42, None, event]})
    assert code == 200
    assert body == {"accepted": 2, "skipped": 3}
    central = _central_events(tmp_path)
    assert len(central) == 2
    assert all(e["sensor_host"] == "sensor-b" for e in central)


def test_oversized_body_rejected(tmp_path):
    server = IngestServer("127.0.0.1", 0, TOKEN, str(tmp_path / "central"),
                          max_body_bytes=64)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        big = {"sensor_host": "x", "events": [{"pad": "y" * 512}]}
        assert _post(server.port, "/ingest", big)[0] == 413
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_too_many_events_rejected(tmp_path):
    server = IngestServer("127.0.0.1", 0, TOKEN, str(tmp_path / "central"),
                          max_events_per_batch=2)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        batch = {"sensor_host": "x", "events": [{"i": i} for i in range(3)]}
        assert _post(server.port, "/ingest", batch)[0] == 400
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_missing_token_refuses_to_start(tmp_path):
    with pytest.raises(IngestError):
        IngestServer("127.0.0.1", 0, None, str(tmp_path / "central"))
    with pytest.raises(IngestError):
        IngestServer("127.0.0.1", 0, "", str(tmp_path / "central"))
