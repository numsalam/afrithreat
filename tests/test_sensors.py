import socket
import time
import urllib.error
import urllib.request

from afrithreat.events import EventWriter, iter_events
from afrithreat.sensors import build_sensor


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _events(tmp_path):
    return list(iter_events(tmp_path))


def _wait_for(tmp_path, predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        events = _events(tmp_path)
        if predicate(events):
            return events
        time.sleep(0.05)
    return _events(tmp_path)


def _sensor(tmp_path, protocol):
    writer = EventWriter(tmp_path)
    port = _free_port()
    sensor = build_sensor(
        {"name": f"{protocol}-t", "protocol": protocol,
         "port": port, "bind": "127.0.0.1"},
        writer, {})
    return sensor, port


def test_http_honeypot_logs_requests(tmp_path):
    sensor, port = _sensor(tmp_path, "http")
    sensor.start()
    try:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/admin.php", timeout=5) as resp:
                assert resp.status == 404
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        sensor.stop()
    events = _wait_for(
        tmp_path, lambda evs: any(e["protocol"] == "http" for e in evs))
    http_events = [e for e in events if e["protocol"] == "http"]
    assert http_events
    assert http_events[0]["details"]["path"] == "/admin.php"
    assert http_events[0]["details"]["method"] == "GET"


def test_telnet_honeypot_captures_credentials(tmp_path):
    sensor, port = _sensor(tmp_path, "telnet")
    sensor.start()
    time.sleep(0.1)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            time.sleep(0.1)
            conn.sendall(b"root\n")
            time.sleep(0.1)
            conn.sendall(b"1234\n")
            time.sleep(0.1)
    finally:
        sensor.stop()
    events = _wait_for(
        tmp_path, lambda evs: any(e["event_type"] == "auth" for e in evs))
    auth = [e for e in events if e["event_type"] == "auth"]
    assert auth
    assert auth[0]["details"] == {"username": "root", "password": "1234"}


def test_telnet_honeypot_strips_iac_and_replies(tmp_path):
    sensor, port = _sensor(tmp_path, "telnet")
    sensor.start()
    time.sleep(0.1)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.settimeout(2.0)
            time.sleep(0.1)
            # negotiate: IAC DO TERMINAL-TYPE(24) → server must answer WONT 24
            conn.sendall(bytes((255, 253, 24)))
            got = b""
            deadline = time.time() + 2.0
            while bytes((255, 252, 24)) not in got and time.time() < deadline:
                try:
                    got += conn.recv(1024)
                except socket.timeout:
                    break
            assert bytes((255, 252, 24)) in got        # IAC WONT 24 replied
            # username with an embedded NOP must land clean
            conn.sendall(bytes((255, 241)) + b"root\n")
            time.sleep(0.1)
            conn.sendall(b"1234\n")
            time.sleep(0.1)
    finally:
        sensor.stop()
    events = _wait_for(
        tmp_path, lambda evs: any(e["event_type"] == "auth" for e in evs))
    auth = [e for e in events if e["event_type"] == "auth"]
    assert auth
    assert auth[0]["details"] == {"username": "root", "password": "1234"}


def test_ssh_honeypot_captures_banner(tmp_path):
    sensor, port = _sensor(tmp_path, "ssh")
    sensor.start()
    time.sleep(0.1)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
            time.sleep(0.2)
    finally:
        sensor.stop()
    events = _wait_for(
        tmp_path, lambda evs: any(e["event_type"] == "connect" for e in evs))
    connects = [e for e in events if e["event_type"] == "connect"]
    assert connects
    assert "OpenSSH_8.9" in connects[0]["details"]["client_banner"]


def test_unknown_protocol_rejected(tmp_path):
    writer = EventWriter(tmp_path)
    try:
        build_sensor({"name": "bad", "protocol": "ftp", "port": 21},
                     writer, {})
    except ValueError as exc:
        assert "ftp" in str(exc)
    else:
        raise AssertionError("expected ValueError")
