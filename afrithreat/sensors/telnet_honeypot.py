"""Low-interaction Telnet honeypot.

IoT-style attackers still brute-force Telnet in plaintext. We play a
minimal login dialog, record every credential attempt, then serve a
fake shell that logs commands and executes nothing.

All RFC 854 IAC negotiation bytes are stripped from captured input
(and answered like a minimal server that refuses every option), so
credentials and commands land in the log clean. Sequences split
across TCP chunks are handled by the stateful filter.
"""

import socket

from .base import Sensor
from .telnet_iac import IACFilter

MAX_SHELL_COMMANDS = 50  # bounded: one client can never fill the disk


class TelnetHoneypotSensor(Sensor):

    def handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        self._emit(ip, port, "connect")
        self._iac = IACFilter()
        conn.sendall(b"\r\nLogin: ")
        username = self.recv_line(conn)
        if not username:
            return
        conn.sendall(b"Password: ")
        password = self.recv_line(conn)
        self._emit(ip, port, "auth", {
            "username": username.decode("utf-8", "replace"),
            "password": password.decode("utf-8", "replace"),
        })
        # Accept the login and log whatever they type into the fake shell.
        conn.sendall(b"\r\nWelcome.\r\n# ")
        for _ in range(MAX_SHELL_COMMANDS):
            line = self.recv_line(conn)
            if not line:
                break
            self._emit(ip, port, "command",
                       {"command": line.decode("utf-8", "replace")})
            try:
                conn.sendall(b"# ")
            except OSError:
                break

    def recv_line(self, conn, max_bytes=None):
        """Read one line with IAC sequences stripped and answered.

        Overrides the base reader: chunks pass through the stateful
        filter before newline detection, so negotiation bytes never
        pollute captured input no matter how they land in TCP chunks.
        """
        max_bytes = max_bytes or self.limits.get("max_line_bytes", 4096)
        parts = []
        total = 0
        while total < max_bytes:
            try:
                chunk = conn.recv(min(1024, max_bytes - total))
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            clean, reply = self._iac.feed(chunk)
            if reply:
                try:
                    conn.sendall(reply)
                except OSError:
                    break
            newline = clean.find(b"\n")
            if newline != -1:
                parts.append(clean[:newline])
                return b"".join(parts).rstrip(b"\r")
            parts.append(clean)
            total += len(clean)
        return b"".join(parts).rstrip(b"\r")

    def _emit(self, ip, port, event_type, details=None):
        self.writer.write(sensor=self.name, protocol=self.protocol,
                          event_type=event_type, src_ip=ip, src_port=port,
                          details=details)
