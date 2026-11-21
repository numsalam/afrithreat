import socket

import pytest

from afrithreat.ssh.wire import (MAC, PacketIO, Reader, SSHError,
                                 pack_bool, pack_byte, pack_mpint,
                                 pack_string, pack_uint32)


def test_pack_roundtrip():
    data = (pack_byte(7) + pack_bool(True) + pack_uint32(0xDEADBEEF)
            + pack_string(b"hello") + pack_mpint(0x123456789ABCDEF))
    reader = Reader(data)
    assert reader.byte() == 7
    assert reader.bool() is True
    assert reader.uint32() == 0xDEADBEEF
    assert reader.string() == b"hello"
    assert reader.mpint() == 0x123456789ABCDEF
    assert reader.remaining() == 0


def test_mpint_edge_cases():
    for value in (0, 1, 127, 128, 255, 256, 2 ** 255, 2 ** 256 - 1):
        assert Reader(pack_mpint(value)).mpint() == value
    # high-bit set -> sign byte prepended
    assert pack_mpint(128) == b"\x00\x00\x00\x02\x00\x80"
    assert pack_mpint(127) == b"\x00\x00\x00\x01\x7f"


def test_reader_short_payload():
    with pytest.raises(SSHError):
        Reader(b"\x00\x00\x00\x05ab").string()


def test_mac_sign():
    mac = MAC("hmac-sha2-256", b"k" * 32)
    assert len(mac.sign(0, b"packet")) == 32
    mac1 = MAC("hmac-sha1", b"k" * 20)
    assert len(mac1.sign(42, b"packet")) == 20


def test_packetio_plaintext_loopback():
    a, b = socket.socketpair()
    try:
        client = PacketIO(a)
        server = PacketIO(b)
        payload = bytes([50]) + pack_string(b"root") + pack_string(
            b"ssh-userauth") + pack_string(b"password")
        client.send_packet(payload)
        assert server.recv_packet() == payload
        server.send_packet(bytes([51]) + pack_string(b"password")
                            + pack_bool(False))
        assert client.recv_packet()[0] == 51
    finally:
        a.close()
        b.close()


def test_packetio_encrypted_loopback():
    from afrithreat.ssh.crypto import CTRStream  # noqa: F401
    a, b = socket.socketpair()
    try:
        client = PacketIO(a)
        server = PacketIO(b)
        key, iv = b"\x07" * 16, b"\x08" * 16
        mac_key = b"\x09" * 32
        client.set_outgoing(iv, key, "hmac-sha2-256", mac_key)
        server.set_incoming(iv, key, "hmac-sha2-256", mac_key)
        server.set_outgoing(b"\x0a" * 16, b"\x0b" * 16,
                            "hmac-sha2-256", b"\x0c" * 32)
        client.set_incoming(b"\x0a" * 16, b"\x0b" * 16,
                            "hmac-sha2-256", b"\x0c" * 32)
        payloads = [b"\x15" + b"x" * 13, b"\x32" + b"y" * 200, bytes([6])]
        for payload in payloads:
            client.send_packet(payload)
            assert server.recv_packet() == payload
            server.send_packet(payload)
            assert client.recv_packet() == payload
    finally:
        a.close()
        b.close()


def test_packetio_rejects_bad_length():
    a, b = socket.socketpair()
    try:
        a.sendall(b"\xff\xff\xff\xff")
        with pytest.raises(SSHError):
            PacketIO(b).recv_packet()
    finally:
        a.close()
        b.close()
