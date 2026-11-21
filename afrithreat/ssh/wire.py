"""SSH binary wire primitives (RFC 4251 §5) and packet framing (§6)."""

import hashlib
import hmac
import struct


class SSHError(Exception):
    """Protocol violation or transport failure."""


# -- packing -----------------------------------------------------------

def pack_byte(value):
    return bytes([value])


def pack_bool(value):
    return b"\x01" if value else b"\x00"


def pack_uint32(value):
    return struct.pack(">I", value)


def pack_string(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return pack_uint32(len(data)) + data


def pack_mpint(n):
    if n == 0:
        return pack_uint32(0)
    data = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return pack_string(data)


# -- unpacking ---------------------------------------------------------

class Reader:
    """Sequential reader over an SSH payload."""

    def __init__(self, data):
        self.data = data
        self.off = 0

    def _take(self, n):
        if self.off + n > len(self.data):
            raise SSHError("short payload")
        chunk = self.data[self.off:self.off + n]
        self.off += n
        return chunk

    def byte(self):
        return self._take(1)[0]

    def bool(self):
        return self._take(1)[0] != 0

    def uint32(self):
        return struct.unpack(">I", self._take(4))[0]

    def string(self):
        return self._take(self.uint32())

    def mpint(self):
        return int.from_bytes(self.string(), "big", signed=True)

    def name_list(self):
        return self.string().decode("ascii", "replace").split(",")

    def remaining(self):
        return len(self.data) - self.off


# -- MAC ---------------------------------------------------------------

class MAC:
    def __init__(self, name, key):
        if name == "hmac-sha2-256":
            self._digest = hashlib.sha256
        elif name == "hmac-sha1":
            self._digest = hashlib.sha1
        else:
            raise SSHError(f"unsupported mac: {name}")
        self.name = name
        self.key = key
        self.size = self._digest().digest_size

    def sign(self, seq, packet):
        return hmac.new(self.key, pack_uint32(seq) + packet,
                        self._digest).digest()


# -- packet framing ------------------------------------------------------

MAX_PACKET = 65536


class PacketIO:
    """Reads and writes SSH packets over a socket, plaintext or encrypted."""

    def __init__(self, sock):
        self.sock = sock
        self.seq_in = 0
        self.seq_out = 0
        self._encryptor = None   # CTRStream for our sends
        self._decryptor = None   # CTRStream for receives
        self._mac_out = None
        self._mac_in = None
        self._block_in = 8
        self._block_out = 8

    def set_outgoing(self, iv, key, mac_name, mac_key):
        from .crypto import CTRStream
        self._encryptor = CTRStream(key, iv)
        self._mac_out = MAC(mac_name, mac_key)
        self._block_out = 16
        # NOTE: sequence numbers are NOT reset here — RFC 4253 §6.4
        # keeps them incrementing across NEWKEYS (the reset only
        # happens with the strict-kex extension, which we don't offer).

    def set_incoming(self, iv, key, mac_name, mac_key):
        from .crypto import CTRStream
        self._decryptor = CTRStream(key, iv)
        self._mac_in = MAC(mac_name, mac_key)
        self._block_in = 16

    # -- send ------------------------------------------------------------

    def send_packet(self, payload):
        pad_len = self._block_out - ((5 + len(payload)) % self._block_out)
        if pad_len < 4:
            pad_len += self._block_out
        packet = (pack_uint32(1 + len(payload) + pad_len)
                  + bytes([pad_len]) + payload + bytes(pad_len))
        if self._encryptor is not None:
            self.sock.sendall(self._encryptor.crypt(packet)
                              + self._mac_out.sign(self.seq_out, packet))
        else:
            self.sock.sendall(packet)
        self.seq_out = (self.seq_out + 1) & 0xFFFFFFFF

    # -- receive -----------------------------------------------------------

    def recv_packet(self):
        if self._decryptor is None:
            header = self._read_exact(4)
            length = struct.unpack(">I", header)[0]
            if not (5 <= length <= MAX_PACKET) or (4 + length) % self._block_in:
                raise SSHError(f"bad packet length {length}")
            packet = header + self._read_exact(length)
        else:
            first = self._decryptor.crypt(self._read_exact(self._block_in))
            length = struct.unpack(">I", first[:4])[0]
            if not (5 <= length <= MAX_PACKET) or (4 + length) % self._block_in:
                raise SSHError(f"bad encrypted length {length}")
            total = 4 + length
            rest = b""
            if total > self._block_in:
                rest = self._decryptor.crypt(
                    self._read_exact(total - self._block_in))
            packet = first + rest
            got_mac = self._read_exact(self._mac_in.size)
            if not hmac.compare_digest(got_mac, self._mac_in.sign(self.seq_in, packet)):
                raise SSHError("bad mac")
        pad_len = packet[4]
        if pad_len < 4 or 5 + pad_len > len(packet):
            raise SSHError("bad padding")
        payload = packet[5:len(packet) - pad_len]
        self.seq_in = (self.seq_in + 1) & 0xFFFFFFFF
        return payload

    def _read_exact(self, n):
        chunks = []
        remaining = n
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise SSHError("connection closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
