"""Sensor base class: lifecycle, accept loop, and connection guards."""

import socket
import threading


class Sensor:
    """A low-interaction honeypot sensor.

    Subclasses implement `handle(conn, addr)`; the base class owns the
    listening socket, the accept loop, per-connection threads, and a
    per-IP connection cap so one attacker cannot exhaust the host.
    """

    def __init__(self, name, protocol, bind, port, writer, limits=None):
        self.name = name
        self.protocol = protocol
        self.bind = bind
        self.port = port
        self.writer = writer
        self.limits = limits or {}
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._conn_counts = {}
        self._conn_lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind, self.port))
        self._sock.listen(64)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._accept_loop, name=f"sensor-{self.name}", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._allow_connection(addr[0]):
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._serve, args=(conn, addr),
                             daemon=True).start()

    def _serve(self, conn, addr):
        try:
            conn.settimeout(self.limits.get("socket_timeout", 30.0))
            self.handle(conn, addr)
        except Exception:
            pass  # a honeypot never dies because of attacker input
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _allow_connection(self, ip):
        cap = self.limits.get("max_connections_per_ip")
        if not cap:
            return True
        with self._conn_lock:
            count = self._conn_counts.get(ip, 0) + 1
            self._conn_counts[ip] = count
        return count <= cap

    # -- subclass API --------------------------------------------------

    def handle(self, conn, addr):
        raise NotImplementedError

    def recv_line(self, conn, max_bytes=None):
        """Read one newline-terminated line, size-bounded, timeout-safe.

        Bytes after the first newline in a single recv are discarded:
        low-interaction sensors only need the first line of each client
        write, and bounding keeps attackers from pinning our threads.
        """
        max_bytes = max_bytes or self.limits.get("max_line_bytes", 4096)
        parts = []
        total = 0
        while total < max_bytes:
            try:
                chunk = conn.recv(min(1024, max_bytes - total))
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            newline = chunk.find(b"\n")
            if newline != -1:
                parts.append(chunk[:newline])
                return b"".join(parts).rstrip(b"\r")
            parts.append(chunk)
            total += len(chunk)
        return b"".join(parts).rstrip(b"\r")
