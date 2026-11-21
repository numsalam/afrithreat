import hashlib
import json

import pytest

from afrithreat.ssh.keys import (HostKey, generate_rsa, is_probable_prime,
                                 load_or_create_host_key)
from afrithreat.ssh.wire import Reader, pack_string


def test_is_probable_prime():
    assert is_probable_prime(2 ** 127 - 1)          # Mersenne prime
    assert is_probable_prime(2 ** 521 - 1)
    assert not is_probable_prime(2 ** 128 - 1)      # composite
    assert not is_probable_prime(1)
    assert not is_probable_prime(1000003 * 1000033)


def test_rsa_sign_verify_roundtrip(tmp_path):
    key = generate_rsa(bits=1024)
    hostkey = HostKey(key["n"], key["e"], key["d"])
    data = b"exchange hash bytes"
    digest_info = {
        "ssh-rsa": ("sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
        "rsa-sha2-256": ("sha256",
                        bytes.fromhex("3031300d060960864801650304020105000420")),
        "rsa-sha2-512": ("sha512",
                        bytes.fromhex("3051300d060960864801650304020305000440")),
    }
    for algo, (hash_name, prefix) in digest_info.items():
        blob = hostkey.sign(data, algo)
        reader = Reader(blob)
        assert reader.string().decode() == algo
        # the signature field carries RAW fixed-size signature bytes
        # (the OpenSSH/paramiko convention) — not an mpint
        sig_bytes = reader.string()
        assert len(sig_bytes) == (hostkey.n.bit_length() + 7) // 8
        signature = int.from_bytes(sig_bytes, "big")
        # verify: s^e mod n must decode to the exact PKCS#1 v1.5 EM
        em = pow(signature, hostkey.e, hostkey.n).to_bytes(
            (hostkey.n.bit_length() + 7) // 8, "big")
        assert em[:2] == b"\x00\x01"
        assert b"\x00" in em[2:]
        t = em[em.index(b"\x00", 2) + 1:]
        assert t == prefix + hashlib.new(hash_name, data).digest()


def test_rsa_sign_paramiko_crosscheck():
    """Our signature blobs must verify with a real SSH client library."""
    paramiko = pytest.importorskip("paramiko")
    from paramiko.message import Message
    key = generate_rsa(bits=1024)
    hostkey = HostKey(key["n"], key["e"], key["d"])
    data = b"exchange hash bytes"
    pkey = paramiko.RSAKey(data=hostkey.public_blob)
    for algo in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
        assert pkey.verify_ssh_sig(data, Message(hostkey.sign(data, algo))), algo


def test_public_blob_format():
    key = generate_rsa(bits=512)
    hostkey = HostKey(key["n"], key["e"], key["d"])
    reader = Reader(hostkey.public_blob)
    assert reader.string() == b"ssh-rsa"
    assert reader.mpint() == 65537
    assert reader.mpint() == key["n"]


def test_load_or_create_caches(tmp_path):
    path = tmp_path / "host_key.json"
    key1 = load_or_create_host_key(path, bits=512)
    assert path.exists()
    raw = json.loads(path.read_text())
    assert int(raw["n"], 16) == key1.n
    key2 = load_or_create_host_key(path)
    assert key2.n == key1.n and key2.d == key1.d
