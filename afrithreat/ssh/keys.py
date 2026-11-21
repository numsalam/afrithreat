"""RSA host key: pure-Python keygen (Miller-Rabin) + PKCS#1 v1.5 signing.

The key is generated once and cached as JSON next to the event log.
Pure-Python 2048-bit key generation takes a few seconds — a one-time
cost per sensor host.
"""

import hashlib
import json
import secrets
from pathlib import Path

from .wire import pack_mpint, pack_string


def _small_primes(limit=2048):
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = b"\x00" * len(sieve[i * i::i])
    return [i for i in range(limit + 1) if sieve[i]]


_SMALL_PRIMES = _small_primes()


def _miller_rabin(n, rounds=40):
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def is_probable_prime(n):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return _miller_rabin(n)


def _gen_prime(bits):
    while True:
        candidate = (secrets.randbits(bits)
                     | (1 << (bits - 1)) | (1 << (bits - 2)) | 1)
        if is_probable_prime(candidate):
            return candidate


def _invmod(a, m):
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("not invertible")
    return old_s % m


def generate_rsa(bits=2048):
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        return {"n": p * q, "e": e, "d": _invmod(e, phi)}


# DigestInfo DER prefixes per RFC 8017 §9.2
_DIGEST_INFO = {
    "ssh-rsa": ("sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
    "rsa-sha2-256": ("sha256", bytes.fromhex("3031300d060960864801650304020105000420")),
    "rsa-sha2-512": ("sha512", bytes.fromhex("3051300d060960864801650304020305000440")),
}


class HostKey:
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d

    @property
    def public_blob(self):
        """Host public key in SSH wire format (the K_S string)."""
        return pack_string(b"ssh-rsa") + pack_mpint(self.e) + pack_mpint(self.n)

    def sign(self, data, algo):
        """Return the SSH signature blob for *algo* over *data*."""
        hash_name, prefix = _DIGEST_INFO[algo]
        digest = hashlib.new(hash_name, data).digest()
        k = (self.n.bit_length() + 7) // 8
        t = prefix + digest
        ps_len = k - len(t) - 3
        if ps_len < 8:
            raise ValueError("key too small for digest")
        em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
        signature = pow(int.from_bytes(em, "big"), self.d, self.n)
        # The signature string carries the raw fixed-size signature
        # bytes — the OpenSSH/paramiko convention. It is NOT an mpint:
        # wrapping it in a length prefix makes real clients read 260
        # bytes for a 2048-bit key and reject the signature.
        return (pack_string(algo.encode())
                + pack_string(signature.to_bytes(k, "big")))


def load_or_create_host_key(path, bits=2048):
    """Load the cached host key JSON at *path*, generating it if absent."""
    path = Path(path)
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        return HostKey(int(raw["n"], 16), int(raw["e"], 16),
                       int(raw["d"], 16))
    key = generate_rsa(bits)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "bits": bits,
        "n": hex(key["n"]),
        "e": hex(key["e"]),
        "d": hex(key["d"]),
    }), encoding="utf-8")
    return HostKey(key["n"], key["e"], key["d"])
