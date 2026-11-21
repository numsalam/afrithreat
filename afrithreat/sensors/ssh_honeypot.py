"""SSH honeypot: full low-interaction SSH transport.

Completes a real key exchange (pure-Python: DH group14-sha256 /
group1-sha1, RSA host key, AES-128-CTR, HMAC) so real clients send
real credentials. Captures every auth attempt and always refuses.
No channels, no shells, no execution.
"""

from pathlib import Path

from ..ssh.keys import load_or_create_host_key
from ..ssh.server import SSHSession
from .base import Sensor

SERVER_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n"


class SSHHoneypotSensor(Sensor):

    def start(self):
        # Host key: loaded from cache or generated once (pure-Python
        # 2048-bit keygen takes a few seconds on first run).
        key_path = Path(self.writer.path.parent) / "host_key.json"
        self.hostkey = load_or_create_host_key(key_path)
        super().start()

    def handle(self, conn, addr):
        session = SSHSession(
            conn, addr, writer=self.writer, sensor=self.name,
            hostkey=self.hostkey, server_banner=SERVER_BANNER,
            max_auth_attempts=self.limits.get("max_auth_attempts", 20))
        session.run()
