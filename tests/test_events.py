import json

from afrithreat.events import EventWriter, iter_events


def test_write_and_iter(tmp_path):
    writer = EventWriter(tmp_path)
    writer.write("s1", "telnet", "auth", "10.0.0.1", 5555,
                 {"username": "root", "password": "1234"})
    writer.write("s1", "http", "request", "10.0.0.2", 6666, {"path": "/admin"})
    events = list(iter_events(tmp_path))
    assert len(events) == 2
    assert events[0]["protocol"] == "telnet"
    assert events[0]["details"]["username"] == "root"
    assert events[1]["src_ip"] == "10.0.0.2"
    assert events[0]["schema"] == 1


def test_malformed_lines_skipped(tmp_path):
    writer = EventWriter(tmp_path)
    writer.write("s1", "http", "request", "10.0.0.2")
    with open(tmp_path / "events.jsonl", "a", encoding="utf-8") as fh:
        fh.write("not json\n\n")
    events = list(iter_events(tmp_path))
    assert len(events) == 1


def test_lookback_filter(tmp_path):
    writer = EventWriter(tmp_path)
    writer.write("s1", "http", "request", "10.0.0.2")
    # Backdate the single event by rewriting the file.
    path = tmp_path / "events.jsonl"
    record = json.loads(path.read_text().splitlines()[0])
    record["ts"] = "2020-01-01T00:00:00Z"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert list(iter_events(tmp_path, lookback_hours=24)) == []
    assert len(list(iter_events(tmp_path))) == 1


def test_missing_log_is_empty(tmp_path):
    assert list(iter_events(tmp_path)) == []
