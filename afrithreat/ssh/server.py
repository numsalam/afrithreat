"""SSH session state machine: banner → kex → newkeys → auth capture.

Completes a real key exchange so real clients send real credentials,
captures every auth attempt, and always refuses. No channels, no
shells, no execution.
"""

import hashlib
import secrets

from .kex import (CIPHERS, COMPRESSION, DH_GROUPS, HOSTKEY_ALGOS, KEX_ALGOS,
                  MACS, build_kexinit, derive_keys, exchange_hash, negotiate,
                  parse_kexinit)
from .wire import (PacketIO, Reader, SSHError, pack_bool, pack_mpint,
                   pack_string, pack_uint32)

MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_DEBUG = 3
MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6
MSG_KEXINIT = 20
MSG_NEWKEYS = 21
MSG_KEXDH_INIT = 30
MSG_KEXDH_REPLY = 31
MSG_USERAUTH_REQUEST = 50
MSG_USERAUTH_FAILURE = 51
MSG_USERAUTH_BANNER = 53

DISCONNECT_KEY_EXCHANGE_FAILED = 3
DISCONNECT_NO_MORE_AUTH = 14

MAX_UNKNOWN_MESSAGES = 10
FAKE_BANNER = (b"Welcome to Ubuntu 22.04.3 LTS "
               b"(GNU/Linux 6.2.0-37-generic x86_64)\r\n")


class SSHSession:
    """One client connection: kex + credential capture, never accepts."""

    def __init__(self, conn, addr, writer, sensor, hostkey, server_banner,
                 max_auth_attempts=20):
        self.conn = conn
        self.addr = addr
        self.writer = writer
        self.sensor = sensor
        self.hostkey = hostkey
        self.server_banner = server_banner
        self.max_auth_attempts = max_auth_attempts
        self.io = PacketIO(conn)

    # -- helpers ---------------------------------------------------------

    def _emit(self, event_type, details):
        self.writer.write(sensor=self.sensor, protocol="ssh",
                          event_type=event_type, src_ip=self.addr[0],
                          src_port=self.addr[1], details=details)

    def _disconnect(self, code, text):
        try:
            self.io.send_packet(bytes([MSG_DISCONNECT]) + pack_uint32(code)
                                + pack_string(text.encode("utf-8"))
                                + pack_string(b""))
        except OSError:
            pass

    def _read_banner(self):
        chunks = []
        while len(chunks) < 255:
            chunk = self.conn.recv(1)
            if not chunk:
                raise SSHError("closed before banner")
            chunks.append(chunk)
            if chunk == b"\n":
                return b"".join(chunks).rstrip(b"\r\n")
        raise SSHError("banner too long")

    # -- main -----------------------------------------------------------

    def run(self):
        try:
            self._run_inner()
        except (SSHError, OSError, ValueError):
            pass  # a honeypot never crashes on attacker input

    def _run_inner(self):
        # 1. Version banner exchange.
        client_banner = self._read_banner()
        banner_text = client_banner.decode("utf-8", "replace")
        self._emit("connect", {"client_banner": banner_text})
        self.conn.sendall(self.server_banner)

        # 2. KEXINIT exchange + algorithm negotiation.
        i_c = self.io.recv_packet()
        if i_c[0] != MSG_KEXINIT:
            raise SSHError("expected KEXINIT")
        client = parse_kexinit(i_c)
        i_s = build_kexinit()
        self.io.send_packet(i_s)

        chosen = {
            "kex": negotiate(client["kex"], KEX_ALGOS),
            "hostkey": negotiate(client["hostkey"], HOSTKEY_ALGOS),
            "cipher_c2s": negotiate(client["cipher_c2s"], CIPHERS),
            "cipher_s2c": negotiate(client["cipher_s2c"], CIPHERS),
            "mac_c2s": negotiate(client["mac_c2s"], MACS),
            "mac_s2c": negotiate(client["mac_s2c"], MACS),
            "comp_c2s": negotiate(client["comp_c2s"], COMPRESSION),
            "comp_s2c": negotiate(client["comp_s2c"], COMPRESSION),
        }
        if any(value is None for value in chosen.values()):
            self._disconnect(DISCONNECT_KEY_EXCHANGE_FAILED,
                             "no compatible algorithm")
            return

        # Discard a wrongly-guessed first kex packet (RFC 4253 §7.1).
        if client["first_kex_follows"] and (
                client["kex"][0] != chosen["kex"]
                or client["cipher_c2s"][0] != chosen["cipher_c2s"]
                or client["mac_c2s"][0] != chosen["mac_c2s"]
                or client["hostkey"][0] != chosen["hostkey"]):
            self.io.recv_packet()

        self._emit("kex", {
            "kex": chosen["kex"],
            "hostkey": chosen["hostkey"],
            "cipher": chosen["cipher_c2s"],
            "mac": chosen["mac_c2s"],
            "client_banner": banner_text,
        })

        # 3. DH exchange.
        p, g, hash_name = DH_GROUPS[chosen["kex"]]
        kexdh = self.io.recv_packet()
        if kexdh[0] != MSG_KEXDH_INIT:
            raise SSHError("expected KEXDH_INIT")
        reader = Reader(kexdh)
        reader.byte()
        e = reader.mpint()
        if not 1 < e < p:
            self._disconnect(DISCONNECT_KEY_EXCHANGE_FAILED, "bad dh value")
            return
        y = 2 + secrets.randbelow(p - 3)
        f = pow(g, y, p)
        k = pow(e, y, p)
        if k == 0:
            self._disconnect(DISCONNECT_KEY_EXCHANGE_FAILED,
                             "degenerate shared secret")
            return

        h = exchange_hash(hash_name, client_banner,
                          self.server_banner.rstrip(b"\r\n"),
                          i_c, i_s, self.hostkey.public_blob, e, f, k)
        session_id = h
        signature = self.hostkey.sign(h, chosen["hostkey"])
        self.io.send_packet(bytes([MSG_KEXDH_REPLY])
                            + pack_string(self.hostkey.public_blob)
                            + pack_mpint(f)
                            + pack_string(signature))

        # 4. NEWKEYS: switch to the encrypted transport.
        self.io.send_packet(bytes([MSG_NEWKEYS]))
        keys = derive_keys(hash_name, k, h, session_id,
                           chosen["mac_c2s"], chosen["mac_s2c"])
        self.io.set_outgoing(keys["iv_s2c"], keys["ek_s2c"],
                             chosen["mac_s2c"], keys["ik_s2c"])
        newkeys = self.io.recv_packet()
        if newkeys[0] != MSG_NEWKEYS:
            raise SSHError("expected NEWKEYS")
        self.io.set_incoming(keys["iv_c2s"], keys["ek_c2s"],
                             chosen["mac_c2s"], keys["ik_c2s"])

        # 5. Service request + auth loop: capture everything.
        attempts = 0
        unknown = 0
        banner_sent = False
        while True:
            payload = self.io.recv_packet()
            msg = payload[0]
            if msg == MSG_USERAUTH_REQUEST:
                details = self._parse_userauth(payload)
                self._emit("auth", details)
                attempts += 1
                if not banner_sent:
                    banner_sent = True
                    self.io.send_packet(bytes([MSG_USERAUTH_BANNER])
                                        + pack_string(FAKE_BANNER)
                                        + pack_string(b""))
                if attempts >= self.max_auth_attempts:
                    self._disconnect(DISCONNECT_NO_MORE_AUTH,
                                     "Too many authentication failures.")
                    return
                self.io.send_packet(bytes([MSG_USERAUTH_FAILURE])
                                    + pack_string(b"password,publickey")
                                    + pack_bool(False))
            elif msg == MSG_SERVICE_REQUEST:
                self.io.send_packet(bytes([MSG_SERVICE_ACCEPT])
                                    + pack_string(b"ssh-userauth"))
            elif msg == MSG_DISCONNECT:
                return
            elif msg in (MSG_IGNORE, MSG_DEBUG):
                continue
            else:
                unknown += 1
                if unknown > MAX_UNKNOWN_MESSAGES:
                    return

    def _parse_userauth(self, payload):
        reader = Reader(payload)
        reader.byte()
        username = reader.string().decode("utf-8", "replace")
        service = reader.string().decode("utf-8", "replace")
        method = reader.string().decode("utf-8", "replace")
        details = {"username": username, "method": method,
                   "service": service}
        try:
            if method == "password":
                if reader.bool():
                    reader.string()  # old password
                    details["password"] = reader.string().decode(
                        "utf-8", "replace")
                    details["change_request"] = True
                else:
                    details["password"] = reader.string().decode(
                        "utf-8", "replace")
            elif method == "publickey":
                reader.bool()  # has signature
                details["key_algorithm"] = reader.string().decode(
                    "ascii", "replace")
                blob = reader.string()
                details["key_sha256"] = hashlib.sha256(blob).hexdigest()
        except SSHError:
            details["truncated"] = True
        return details
