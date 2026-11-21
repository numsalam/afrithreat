"""Unit tests for the RFC 854 IAC stripper (Telnet negotiation)."""

from afrithreat.sensors.telnet_iac import (DO, DONT, IAC, IACFilter, SB, SE,
                                           WILL, WONT)


def test_plain_data_passes_through():
    filt = IACFilter()
    assert filt.feed(b"root\n") == (b"root\n", b"")


def test_iac_iac_is_literal_255():
    filt = IACFilter()
    clean, reply = filt.feed(bytes((IAC, IAC)) + b"x")
    assert clean == b"\xffx"
    assert reply == b""


def test_will_gets_dont_reply():
    filt = IACFilter()
    clean, reply = filt.feed(bytes((IAC, WILL, 24)) + b"root\n")
    assert clean == b"root\n"
    assert reply == bytes((IAC, DONT, 24))


def test_do_gets_wont_reply():
    filt = IACFilter()
    assert filt.feed(bytes((IAC, DO, 24))) == (b"", bytes((IAC, WONT, 24)))


def test_wont_dont_stripped_silently():
    filt = IACFilter()
    clean, reply = filt.feed(bytes((IAC, WONT, 24, IAC, DONT, 25)) + b"hi")
    assert (clean, reply) == (b"hi", b"")


def test_simple_commands_stripped():
    # NOP (241), GA (249), IP (244), AYT (246) — all two-byte commands
    filt = IACFilter()
    clean, _ = filt.feed(
        bytes((IAC, 241, IAC, 249, IAC, 244, IAC, 246)) + b"ok")
    assert clean == b"ok"


def test_suboption_skipped():
    # IAC SB TERMINAL-TYPE(24) IS(0) "xterm" IAC SE
    filt = IACFilter()
    payload = bytes((IAC, SB, 24, 0)) + b"xterm" + bytes((IAC, SE)) + b"root"
    assert filt.feed(payload) == (b"root", b"")


def test_option_sequence_split_across_chunks():
    filt = IACFilter()
    assert filt.feed(bytes((IAC, DO))) == (b"", b"")       # partial sequence
    clean, reply = filt.feed(bytes((24,)) + b"root\n")     # option byte + data
    assert clean == b"root\n"
    assert reply == bytes((IAC, WONT, 24))


def test_suboption_split_across_chunks():
    filt = IACFilter()
    assert filt.feed(bytes((IAC, SB, 24))) == (b"", b"")
    assert filt.feed(b"xterm") == (b"", b"")
    clean, _ = filt.feed(bytes((IAC, SE)) + b"admin")
    assert clean == b"admin"


def test_unknown_command_stripped_defensively():
    filt = IACFilter()
    clean, _ = filt.feed(bytes((IAC, 200)) + b"data")  # 200 is not a command
    assert clean == b"data"


def test_escaped_iac_inside_suboption():
    filt = IACFilter()
    payload = (bytes((IAC, SB, 24)) + bytes((IAC, IAC))
               + bytes((IAC, SE)) + b"ok")
    clean, _ = filt.feed(payload)
    assert clean == b"ok"
