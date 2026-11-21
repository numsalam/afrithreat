import json

from afrithreat.collector import collect
from afrithreat.events import EventWriter


def _seed(tmp_path):
    writer = EventWriter(tmp_path)
    writer.write("telnet-1", "telnet", "auth", "1.2.3.4", 1000,
                 {"username": "root", "password": "admin"})
    writer.write("telnet-1", "telnet", "auth", "1.2.3.4", 1001,
                 {"username": "admin", "password": "1234"})
    writer.write("telnet-1", "telnet", "command", "1.2.3.4", 1001,
                 {"command": "busybox"})
    writer.write("http-1", "http", "request", "5.6.7.8", 2000,
                 {"path": "/wp-login.php", "headers": {"User-Agent": "curl/8"}})
    writer.write("ssh-1", "ssh", "connect", "5.6.7.8", 22,
                 {"client_banner": "SSH-2.0-libssh_0.9"})
    writer.write("ssh-1", "ssh", "auth", "5.6.7.8", 22,
                 {"username": "root", "method": "password",
                  "service": "ssh-connection", "password": "hunter2"})
    writer.write("ssh-1", "ssh", "auth", "5.6.7.8", 22,
                 {"username": "oracle", "method": "publickey",
                  "service": "ssh-connection", "key_sha256": "abc123"})
    return writer


def _append_tagged(tmp_path, sensor_host):
    """Append one sensor_host-tagged event, as the ingest server does."""
    event = {"schema": 1, "ts": "2026-11-21T00:00:00Z", "sensor": "ssh-1",
             "protocol": "ssh", "event_type": "auth", "src_ip": "9.9.9.9",
             "src_port": 22, "details": {"username": "root",
                                         "method": "password",
                                         "password": "12345"},
             "sensor_host": sensor_host}
    with (tmp_path / "events.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


def test_collect_counts(tmp_path):
    _seed(tmp_path)
    agg = collect(tmp_path)
    assert agg["total_events"] == 7
    assert agg["protocols"] == {"telnet": 3, "http": 1, "ssh": 3}
    assert agg["sources"]["1.2.3.4"]["count"] == 3
    assert agg["sources"]["1.2.3.4"]["protocols"] == ["telnet"]
    assert agg["sources"]["5.6.7.8"]["protocols"] == ["http", "ssh"]
    assert agg["usernames"] == {"root": 1, "admin": 1}
    assert agg["passwords"] == {"admin": 1, "1234": 1}
    assert agg["commands"] == {"busybox": 1}
    assert agg["http_paths"] == {"/wp-login.php": 1}
    assert agg["http_user_agents"] == {"curl/8": 1}
    assert agg["ssh_banners"] == {"SSH-2.0-libssh_0.9": 1}


def test_ssh_credentials_counted(tmp_path):
    _seed(tmp_path)
    agg = collect(tmp_path)
    assert agg["ssh_usernames"] == {"root": 1, "oracle": 1}
    assert agg["ssh_passwords"] == {"hunter2": 1}   # publickey has none
    assert agg["ssh_methods"] == {"password": 1, "publickey": 1}
    assert agg["sensor_hosts"] == {"local": 7}       # untagged → local


def test_sensor_host_breakdown(tmp_path):
    _seed(tmp_path)
    _append_tagged(tmp_path, "sensor-a")
    _append_tagged(tmp_path, "sensor-a")
    _append_tagged(tmp_path, "sensor-b")
    agg = collect(tmp_path)
    assert agg["sensor_hosts"] == {"sensor-a": 2, "sensor-b": 1, "local": 7}
    assert agg["ssh_usernames"]["root"] == 4         # 1 local + 3 tagged
    assert agg["ssh_passwords"]["12345"] == 3


def test_timeline_is_chronological(tmp_path):
    _seed(tmp_path)
    agg = collect(tmp_path)
    keys = list(agg["timeline"].keys())
    assert keys == sorted(keys)
    assert sum(agg["timeline"].values()) == 7


def test_empty_log(tmp_path):
    agg = collect(tmp_path)
    assert agg["total_events"] == 0
    assert agg["sources"] == {}
    assert agg["timeline"] == {}
