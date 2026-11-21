"""Aggregate raw events into a threat-activity summary."""

from collections import Counter

from .events import iter_events


def collect(data_dir, lookback_hours=None):
    """Return an aggregate dict over the event log."""
    agg = {
        "total_events": 0,
        "first_seen": None,
        "last_seen": None,
        "protocols": Counter(),
        "sources": {},  # ip -> {count, protocols, first, last}
        "usernames": Counter(),
        "passwords": Counter(),
        "http_paths": Counter(),
        "http_user_agents": Counter(),
        "commands": Counter(),
        "ssh_banners": Counter(),
        "ssh_usernames": Counter(),
        "ssh_passwords": Counter(),
        "ssh_methods": Counter(),
        "sensor_hosts": Counter(),  # reporting host -> event count
        "timeline": Counter(),  # UTC hour bucket -> count
    }
    for event in iter_events(data_dir, lookback_hours=lookback_hours):
        _absorb(agg, event)
    _finalize(agg)
    return agg


def _absorb(agg, event):
    agg["total_events"] += 1
    ts = event.get("ts")
    if ts:
        if agg["first_seen"] is None:
            agg["first_seen"] = ts
        agg["last_seen"] = ts
        agg["timeline"][ts[:13]] += 1  # "2026-11-21T14"

    proto = event.get("protocol", "?")
    agg["protocols"][proto] += 1
    agg["sensor_hosts"][event.get("sensor_host") or "local"] += 1

    ip = event.get("src_ip") or "?"
    src = agg["sources"].setdefault(
        ip, {"count": 0, "protocols": set(), "first": ts, "last": ts})
    src["count"] += 1
    src["protocols"].add(proto)
    if ts:
        src["last"] = ts

    details = event.get("details") or {}
    etype = event.get("event_type")
    if proto == "telnet" and etype == "auth":
        agg["usernames"][details.get("username", "")] += 1
        agg["passwords"][details.get("password", "")] += 1
    elif proto == "telnet" and etype == "command":
        agg["commands"][details.get("command", "")] += 1
    elif proto == "http" and etype == "request":
        agg["http_paths"][details.get("path", "")] += 1
        headers = details.get("headers") or {}
        agg["http_user_agents"][headers.get("User-Agent", "")] += 1
    elif proto == "ssh" and etype == "connect":
        agg["ssh_banners"][details.get("client_banner", "")] += 1
    elif proto == "ssh" and etype == "auth":
        agg["ssh_usernames"][details.get("username", "")] += 1
        agg["ssh_methods"][details.get("method", "")] += 1
        if "password" in details:
            agg["ssh_passwords"][details["password"]] += 1


def _finalize(agg):
    for src in agg["sources"].values():
        src["protocols"] = sorted(src["protocols"])
    for key in ("protocols", "usernames", "passwords", "http_paths",
                "http_user_agents", "commands", "ssh_banners",
                "ssh_usernames", "ssh_passwords", "ssh_methods",
                "sensor_hosts"):
        agg[key] = dict(agg[key].most_common())
    agg["timeline"] = dict(sorted(agg["timeline"].items()))
