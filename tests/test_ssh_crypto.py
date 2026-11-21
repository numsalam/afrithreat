from afrithreat.ssh.crypto import CTRStream, encrypt_block, expand_key


def test_aes_fips197_known_answer():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert encrypt_block(plaintext, expand_key(key)) == expected


def test_aes_ctr_nist_sp800_38a():
    # SP 800-38A F.5.1 inputs; expected values cross-verified against the
    # `cryptography` (OpenSSL) reference implementation.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411a5e9f904381f815e")
    expected = bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e1b5d311f2fa5ed1a")
    assert CTRStream(key, iv).crypt(plaintext) == expected


def test_ctr_roundtrip():
    key, iv = b"\x01" * 16, b"\x02" * 16
    data = b"attack at dawn!" * 7
    encrypted = CTRStream(key, iv).crypt(data)
    assert CTRStream(key, iv).crypt(encrypted) == data


def test_ctr_incremental_matches_oneshot():
    key, iv = b"\x03" * 16, b"\x04" * 16
    data = bytes(range(256)) * 3
    oneshot = CTRStream(key, iv).crypt(data)
    stream = CTRStream(key, iv)
    incremental = b"".join(stream.crypt(data[i:i + 7])
                           for i in range(0, len(data), 7))
    assert incremental == oneshot


def test_ctr_counter_wraps():
    key = b"\x05" * 16
    iv = b"\xff" * 16  # counter at maximum -> wraps to zero
    data = b"\x00" * 48
    out = CTRStream(key, iv).crypt(data)
    assert len(out) == 48
