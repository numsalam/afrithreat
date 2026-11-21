"""Integration tests: real SSH clients against the SSH honeypot.

These are the end-to-end proof of the pure-Python transport: if key
exchange, signature, encryption, or MAC handling is wrong by a single
byte, the client aborts before sending credentials and no auth event
is captured.

- test_openssh: uses the system `ssh` binary (skipped if unavailable
  or if the environment cannot run it, e.g. no passwd entry).
- test_paramiko: uses paramiko when installed (skipped otherwise).
"""

import os
import shutil
import socket
import stat
import subprocess
import time

import pytest

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


def _wait_for_password_auth(tmp_path, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        auths = [e for e in _events(tmp_path) if e["event_type"] == "auth"]
        if any(a["details"].get("method") == "password" for a in auths):
            return auths
        time.sleep(0.1)
    return [e for e in _events(tmp_path) if e["event_type"] == "auth"]


def _assert_captured(tmp_path, auths):
    passwords = [a for a in auths
                 if a["details"].get("method") == "password"]
    assert passwords, f"no password auth captured; events: {_events(tmp_path)}"
    assert passwords[0]["details"]["username"] == "root"
    assert passwords[0]["details"]["password"] == "hunter2"

    kex_events = [e for e in _events(tmp_path) if e["event_type"] == "kex"]
    assert kex_events, "no kex event captured"
    assert kex_events[0]["details"]["kex"] in (
        "diffie-hellman-group14-sha256", "diffie-hellman-group1-sha1")
    assert kex_events[0]["details"]["cipher"] == "aes128-ctr"


def test_ssh_client_credential_capture_openssh(tmp_path):
    if shutil.which("ssh") is None:
        pytest.skip("openssh client not installed")
    writer = EventWriter(tmp_path)
    port = _free_port()
    sensor = build_sensor(
        {"name": "ssh-t", "protocol": "ssh", "port": port,
         "bind": "127.0.0.1"}, writer, {})
    sensor.start()
    try:
        askpass = tmp_path / "askpass.sh"
        askpass.write_text("#!/bin/sh\necho hunter2\n")
        askpass.chmod(askpass.stat().st_mode | stat.S_IEXEC)
        env = os.environ.copy()
        env.update({
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": ":0",
        })
        result = subprocess.run(
            ["ssh", "-p", str(port),
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no",
             "-o", "NumberOfPasswordPrompts=1",
             "-o", "ConnectTimeout=10",
             "root@127.0.0.1", "true"],
            env=env, capture_output=True, timeout=60)
        if b"No user exists for uid" in result.stderr:
            pytest.skip("openssh cannot run here (no passwd entry for uid)")
        assert result.returncode != 0
        assert b"Permission denied" in result.stderr
    finally:
        sensor.stop()
    _assert_captured(tmp_path, _wait_for_password_auth(tmp_path))


def test_ssh_client_credential_capture_paramiko(tmp_path):
    paramiko = pytest.importorskip("paramiko")
    writer = EventWriter(tmp_path)
    port = _free_port()
    sensor = build_sensor(
        {"name": "ssh-t", "protocol": "ssh", "port": port,
         "bind": "127.0.0.1"}, writer, {})
    sensor.start()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            client.connect(
                "127.0.0.1", port=port, username="root", password="hunter2",
                look_for_keys=False, allow_agent=False,
                timeout=10, banner_timeout=10, auth_timeout=10)
        client.close()
    finally:
        sensor.stop()
    _assert_captured(tmp_path, _wait_for_password_auth(tmp_path))
