"""Pure-Python AES-128 (encrypt-only) with SSH CTR keystream.

Encrypt-only is sufficient: CTR mode applies the forward cipher to
counter blocks for both encryption and decryption. Verified against
FIPS-197 and NIST SP 800-38A test vectors in the test suite.
"""

import hashlib  # noqa: F401  (kept for clarity of crypto deps)


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _gf_mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _make_sbox():
    """Generate the AES S-box: GF(2^8) inverse + affine transform."""
    sbox = [0] * 256
    for a in range(256):
        if a == 0:
            inv = 0
        else:
            inv = 1
            # brute-force inverse via GF exponentiation logs
            for candidate in range(1, 256):
                if _gf_mul(a, candidate) == 1:
                    inv = candidate
                    break
        s = inv ^ 0x63
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox[a] = s & 0xFF
    return sbox


SBOX = _make_sbox()
# Known-answer spot checks (FIPS-197): fail fast on a broken table.
assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0xFF] == 0x16


def expand_key(key):
    """AES-128 key schedule: 16-byte key -> 44 4-byte words."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    words = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return words


def _round_key_bytes(words, rnd):
    out = []
    for i in range(4):
        out.extend(words[4 * rnd + i])
    return out


def _shift_rows(s):
    out = [0] * 16
    for r in range(4):
        row = [s[r], s[r + 4], s[r + 8], s[r + 12]]
        row = row[r:] + row[:r]
        for c in range(4):
            out[c * 4 + r] = row[c]
    return out


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        out[4 * c + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
    return out


def encrypt_block(block, words):
    """Encrypt one 16-byte block with a pre-expanded key schedule."""
    rk = _round_key_bytes(words, 0)
    s = [block[i] ^ rk[i] for i in range(16)]
    for rnd in range(1, 10):
        s = [SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        rk = _round_key_bytes(words, rnd)
        s = [s[i] ^ rk[i] for i in range(16)]
    s = [SBOX[b] for b in s]
    s = _shift_rows(s)
    rk = _round_key_bytes(words, 10)
    return bytes(s[i] ^ rk[i] for i in range(16))


class CTRStream:
    """SSH AES-CTR keystream: 128-bit big-endian counter over the full IV."""

    def __init__(self, key, iv):
        if len(key) != 16 or len(iv) != 16:
            raise ValueError("AES-128-CTR needs 16-byte key and IV")
        self._words = expand_key(key)
        self._counter = bytearray(iv)
        self._buf = bytearray()

    def _refill(self):
        self._buf += encrypt_block(bytes(self._counter), self._words)
        for i in range(15, -1, -1):
            self._counter[i] = (self._counter[i] + 1) & 0xFF
            if self._counter[i]:
                break

    def crypt(self, data):
        while len(self._buf) < len(data):
            self._refill()
        keystream = self._buf[:len(data)]
        del self._buf[:len(data)]
        return bytes(a ^ b for a, b in zip(data, keystream))
