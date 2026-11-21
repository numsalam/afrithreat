"""RFC 854/855 Telnet in-band negotiation (IAC) handling.

Telnet clients interleave control sequences with user data: every
0xFF (IAC) starts a command — simple commands (NOP, GA, IP, ...),
option negotiations (WILL/WONT/DO/DONT + option byte), and
variable-length suboptions (IAC SB ... IAC SE). Left unstripped these
bytes pollute captured credentials and commands.

`IACFilter` is a small state machine: feed it raw socket chunks and it
returns the clean user data plus any replies a minimal server should
send (we refuse every option — WONT for DO, DONT for WILL). State
persists across feeds, so a sequence split across TCP chunks is
handled correctly. Every byte advances the machine; nothing is
unbounded.
"""

IAC = 255
SE = 240
SB = 250
WILL = 251
WONT = 252
DO = 253
DONT = 254

# commands that are exactly two bytes (IAC + command)
_SIMPLE = frozenset({SE, 241, 242, 243, 244, 245, 246, 247, 248, 249})
_OPTIONS = frozenset({WILL, WONT, DO, DONT})


class IACFilter:
    """Stateful IAC stripper + minimal-server negotiator."""

    def __init__(self):
        self._state = "data"      # data | iac | opt | sub | sub_iac
        self._reply_cmd = 0       # pending option command to answer

    def feed(self, chunk):
        """Consume raw bytes; return (clean_data, reply_bytes)."""
        out = bytearray()
        reply = bytearray()
        for byte in chunk:
            state = self._state
            if state == "data":
                if byte == IAC:
                    self._state = "iac"
                else:
                    out.append(byte)
            elif state == "iac":
                if byte == IAC:                    # IAC IAC → literal 0xFF
                    out.append(IAC)
                    self._state = "data"
                elif byte == SB:
                    self._state = "sub"
                elif byte in _OPTIONS:
                    self._reply_cmd = byte
                    self._state = "opt"
                else:                              # simple/unknown command
                    self._state = "data"
            elif state == "opt":
                if self._reply_cmd == WILL:        # refuse everything
                    reply += bytes((IAC, DONT, byte))
                elif self._reply_cmd == DO:
                    reply += bytes((IAC, WONT, byte))
                self._state = "data"
            elif state == "sub":
                if byte == IAC:
                    self._state = "sub_iac"
            else:                                  # sub_iac
                if byte == SE:
                    self._state = "data"           # end of suboption
                elif byte != IAC:
                    self._state = "sub"            # keep skipping
        return bytes(out), bytes(reply)
