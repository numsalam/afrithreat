"""Honeypot sensors."""

from .base import Sensor
from .http_honeypot import HTTPHoneypotSensor
from .ssh_honeypot import SSHHoneypotSensor
from .telnet_honeypot import TelnetHoneypotSensor

SENSORS = {
    "http": HTTPHoneypotSensor,
    "telnet": TelnetHoneypotSensor,
    "ssh": SSHHoneypotSensor,
}


def build_sensor(spec, writer, limits):
    """Instantiate a sensor from a config spec dict."""
    protocol = spec.get("protocol")
    try:
        cls = SENSORS[protocol]
    except KeyError:
        raise ValueError(f"unknown protocol: {protocol!r}") from None
    return cls(
        name=spec["name"],
        protocol=protocol,
        bind=spec.get("bind", "127.0.0.1"),
        port=int(spec["port"]),
        writer=writer,
        limits=limits,
    )
