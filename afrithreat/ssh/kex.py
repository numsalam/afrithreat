"""Key exchange: KEXINIT build/parse, DH groups, exchange hash, KDF."""

import hashlib
import secrets

from . import groups
from .wire import Reader, SSHError, pack_bool, pack_mpint, pack_string, pack_uint32

KEX_ALGOS = ["diffie-hellman-group14-sha256", "diffie-hellman-group1-sha1"]
HOSTKEY_ALGOS = ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]
CIPHERS = ["aes128-ctr"]
MACS = ["hmac-sha2-256", "hmac-sha1"]
COMPRESSION = ["none"]

DH_GROUPS = {
    "diffie-hellman-group14-sha256": (groups.GROUP14_P, groups.GROUP14_G, "sha256"),
    "diffie-hellman-group1-sha1": (groups.GROUP1_P, groups.GROUP1_G, "sha1"),
}


def build_kexinit():
    """Return our KEXINIT payload (msg 20)."""
    payload = bytes([20]) + secrets.token_bytes(16)
    for name_list in (KEX_ALGOS, HOSTKEY_ALGOS, CIPHERS, CIPHERS,
                      MACS, MACS, COMPRESSION, COMPRESSION, [], []):
        payload += pack_string(",".join(name_list).encode("ascii"))
    payload += pack_bool(False) + pack_uint32(0)
    return payload


def parse_kexinit(payload):
    """Parse a client KEXINIT payload into a dict of algorithm lists."""
    reader = Reader(payload)
    if reader.byte() != 20:
        raise SSHError("not a KEXINIT")
    reader._take(16)  # cookie
    out = {
        "kex": reader.name_list(),
        "hostkey": reader.name_list(),
        "cipher_c2s": reader.name_list(),
        "cipher_s2c": reader.name_list(),
        "mac_c2s": reader.name_list(),
        "mac_s2c": reader.name_list(),
        "comp_c2s": reader.name_list(),
        "comp_s2c": reader.name_list(),
    }
    reader.name_list()  # lang c2s
    reader.name_list()  # lang s2c
    out["first_kex_follows"] = reader.bool()
    return out


def negotiate(client_list, server_list):
    """First client algorithm also offered by us, or None."""
    for algo in client_list:
        if algo in server_list:
            return algo
    return None


def exchange_hash(hash_name, v_c, v_s, i_c, i_s, k_s_blob, e, f, k):
    """RFC 4253 §8: H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K)."""
    digest = hashlib.new(hash_name)
    for piece in (v_c, v_s, i_c, i_s, k_s_blob):
        digest.update(pack_string(piece))
    digest.update(pack_mpint(e))
    digest.update(pack_mpint(f))
    digest.update(pack_mpint(k))
    return digest.digest()


def _kdf(hash_name, k_mpint, h, session_id, length, letter):
    """RFC 4253 §7.2 key material: HASH(K || H || letter || session_id)."""
    out = b""
    x = ord(letter)
    while len(out) < length:
        out += hashlib.new(hash_name,
                           k_mpint + h + bytes([x]) + session_id).digest()
        x += 1
    return out[:length]


def derive_keys(hash_name, k, h, session_id, mac_c2s, mac_s2c):
    """Derive the six session secrets. Returns a dict."""
    k_mpint = pack_mpint(k)
    mac_len = {"hmac-sha2-256": 32, "hmac-sha1": 20}
    return {
        "iv_c2s": _kdf(hash_name, k_mpint, h, session_id, 16, "A"),
        "iv_s2c": _kdf(hash_name, k_mpint, h, session_id, 16, "B"),
        "ek_c2s": _kdf(hash_name, k_mpint, h, session_id, 16, "C"),
        "ek_s2c": _kdf(hash_name, k_mpint, h, session_id, 16, "D"),
        "ik_c2s": _kdf(hash_name, k_mpint, h, session_id,
                       mac_len[mac_c2s], "E"),
        "ik_s2c": _kdf(hash_name, k_mpint, h, session_id,
                       mac_len[mac_s2c], "F"),
    }
