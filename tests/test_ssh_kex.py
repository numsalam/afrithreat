import hashlib

from afrithreat.ssh import kex
from afrithreat.ssh.kex import (build_kexinit, derive_keys, exchange_hash,
                                negotiate, parse_kexinit)
from afrithreat.ssh.wire import Reader, pack_mpint, pack_string


def test_kexinit_roundtrip():
    payload = build_kexinit()
    parsed = parse_kexinit(payload)
    assert parsed["kex"] == kex.KEX_ALGOS
    assert parsed["hostkey"] == kex.HOSTKEY_ALGOS
    assert parsed["cipher_c2s"] == kex.CIPHERS
    assert parsed["mac_c2s"] == kex.MACS
    assert parsed["comp_c2s"] == ["none"]
    assert parsed["first_kex_follows"] is False


def test_negotiate():
    assert negotiate(["curve25519-sha256", "diffie-hellman-group14-sha256"],
                     kex.KEX_ALGOS) == "diffie-hellman-group14-sha256"
    assert negotiate(["diffie-hellman-group1-sha1"], kex.KEX_ALGOS) == \
        "diffie-hellman-group1-sha1"
    assert negotiate(["aes256-gcm@openssh.com"], kex.CIPHERS) is None


def test_dh_groups_sane():
    for name, (p, g, hash_name) in kex.DH_GROUPS.items():
        assert p % 2 == 1 and p.bit_length() in (1024, 2048)
        assert g == 2
        assert hash_name in ("sha1", "sha256")
        assert hashlib.new(hash_name).digest_size >= 20


def test_exchange_hash_deterministic():
    v_c, v_s = b"SSH-2.0-client", b"SSH-2.0-server"
    i_c, i_s = b"\x14" + b"c" * 20, b"\x14" + b"s" * 20
    k_s = pack_string(b"ssh-rsa") + pack_mpint(65537) + pack_mpint(1 << 2047)
    h1 = exchange_hash("sha256", v_c, v_s, i_c, i_s, k_s, 12345, 67890, 999)
    h2 = exchange_hash("sha256", v_c, v_s, i_c, i_s, k_s, 12345, 67890, 999)
    assert h1 == h2 and len(h1) == 32
    # any input change must change the hash
    h3 = exchange_hash("sha256", v_c, v_s, i_c, i_s, k_s, 12345, 67890, 998)
    assert h3 != h1


def test_derive_keys_shapes():
    h = hashlib.sha256(b"exchange hash").digest()
    keys = derive_keys("sha256", 2 ** 2000, h, h,
                       "hmac-sha2-256", "hmac-sha2-256")
    assert len(keys["iv_c2s"]) == 16 and len(keys["iv_s2c"]) == 16
    assert len(keys["ek_c2s"]) == 16 and len(keys["ek_s2c"]) == 16
    assert len(keys["ik_c2s"]) == 32 and len(keys["ik_s2c"]) == 32
    # distinct letters must give distinct material
    assert keys["iv_c2s"] != keys["iv_s2c"]
    assert keys["ek_c2s"] != keys["ek_s2c"]
    # sha1 kex (group1) still yields enough material
    h1 = hashlib.sha1(b"h").digest()
    keys1 = derive_keys("sha1", 2 ** 1000, h1, h1, "hmac-sha1", "hmac-sha1")
    assert len(keys1["ek_c2s"]) == 16 and len(keys1["ik_c2s"]) == 20


def test_parse_kexinit_rejects_non_kexinit():
    import pytest
    with pytest.raises(Exception):
        parse_kexinit(b"\x01" + b"\x00" * 16)
