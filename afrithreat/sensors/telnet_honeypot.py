"""Low-interaction Telnet honeypot.

IoT-style attackers still brute-force Telnet in plaintext. We play a
minimal login dialog, record every credential attempt, then serve a
fake shell that logs commands and executes nothing.

v1 does not strip Telnet IAC negotiation bytes; they may appear in
captured input (decoded with replacement). IAC stripping is v2.
"""

from .base import Sensor

MAX_SHELL_COMMANDS = 50  # bounded: one client can never fill the disk


class TelnetHoneypotSensor(Sensor):

    def handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        self._emit(ip, port, "connect")
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

    def _emit(self, ip, port, event_type, details=None):
        self.writer.write(sensor=self.name, protocol=self.protocol,
                          event_type=event_type, src_ip=ip, src_port=port,
                          details=details)
