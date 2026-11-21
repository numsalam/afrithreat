"""Pure-Python SSH transport for the honeypot.

Completes real key exchanges so real clients send real credentials:
AES-128-CTR, HMAC, DH group14-sha256 / group1-sha1, RSA host keys.
"""
