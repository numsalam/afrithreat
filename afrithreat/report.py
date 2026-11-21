"""Markdown + JSON report generation from collected aggregates."""

import json
from pathlib import Path

from .collector import collect
from .enrich import build_enricher
from .events import utc_now_iso

TOP_SOURCES = 25
TOP_ROWS = 15


def generate_report(config, out_dir):
    """Write report.md + report.json into *out_dir*; return the md path."""
    lookback = config.get("report", {}).get("lookback_hours", 168)
    agg = collect(config["data_dir"], lookback_hours=lookback)
    enricher = build_enricher(config)
    sources = _enriched_sources(agg, enricher)
    markdown = _markdown(config, agg, sources, lookback)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path = out / "report.md"
    md_path.write_text(markdown, encoding="utf-8")
    (out / "report.json").write_text(
        json.dumps({
            "generated": utc_now_iso(),
            "lookback_hours": lookback,
            "aggregate": agg,
            "sources": sources,
        }, indent=2, default=str),
        encoding="utf-8",
    )
    return md_path


def _enriched_sources(agg, enricher):
    rows = []
    ranked = sorted(agg["sources"].items(), key=lambda item: -item[1]["count"])
    for ip, src in ranked:
        rows.append({"ip": ip, **src, **enricher.enrich(ip)})
    return rows


def _top_asns(sources):
    """Aggregate enriched sources by ASN → total events (report-ready rows)."""
    totals = {}
    for s in sources:
        asn = s.get("asn")
        if not asn:
            continue
        key = (asn, s.get("org") or "", s.get("country") or "")
        totals[key] = totals.get(key, 0) + s["count"]
    return [[asn, org or "—", country or "—", count]
            for (asn, org, country), count in
            sorted(totals.items(), key=lambda item: -item[1])]


def _table(rows, headers):
    lines = [
        "| " + " | ".join(str(h) for h in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _section(out, title, pairs, headers):
    out.extend([f"## {title}", ""])
    if pairs:
        out.extend([_table(pairs, headers), ""])
    else:
        out.extend(["_none recorded_", ""])


def _markdown(config, agg, sources, lookback):
    title = config.get("report", {}).get("title", "AFRITHREAT Threat Report")
    out = [f"# {title}", "",
           f"_Generated {utc_now_iso()} · window: last {lookback} hours_", ""]

    out.extend(["## Overview", ""])
    out.extend([
        f"- **{agg['total_events']}** events recorded",
        f"- Window: `{agg['first_seen'] or 'n/a'}` → `{agg['last_seen'] or 'n/a'}`",
        f"- **{len(sources)}** unique source IPs",
        f"- **{len(agg['sensor_hosts'])}** sensor host(s) reporting",
        "",
    ])

    out.extend(["## Top source IPs", ""])
    if sources:
        has_geo = any(s.get("country") for s in sources)
        has_asn = any(s.get("asn") for s in sources)
        headers = ["IP", "Events", "Protocols", "First seen", "Last seen"]
        row_geo_at = None
        if has_geo:
            headers.insert(3, "Country")
            row_geo_at = 3
        if has_asn:
            at = (row_geo_at or 0) + 1 if row_geo_at else 3
            headers[at:at] = ["ASN", "Org"]
        rows = []
        for s in sources[:TOP_SOURCES]:
            row = [s["ip"], s["count"], ", ".join(s["protocols"]),
                   s["first"] or "?", s["last"] or "?"]
            if has_geo:
                row.insert(3, s.get("country") or "—")
            if has_asn:
                at = 4 if has_geo else 3
                row[at:at] = [s.get("asn") or "—", s.get("org") or "—"]
            rows.append(row)
        out.extend([_table(rows, headers), ""])
    else:
        out.extend(["_No events yet — run a sensor and let the internet knock._", ""])

    top_asns = _top_asns(sources)
    if top_asns:
        _section(out, "Top ASNs", top_asns[:TOP_ROWS],
                 ["ASN", "Org", "Country", "Events"])

    _section(out, "Protocol breakdown", list(agg["protocols"].items()),
             ["Protocol", "Events"])
    _section(out, "Top Telnet usernames tried",
             list(agg["usernames"].items())[:TOP_ROWS], ["Username", "Attempts"])
    _section(out, "Top Telnet passwords tried",
             list(agg["passwords"].items())[:TOP_ROWS], ["Password", "Attempts"])
    _section(out, "Top Telnet commands",
             list(agg["commands"].items())[:TOP_ROWS], ["Command", "Count"])
    _section(out, "Top HTTP paths requested",
             list(agg["http_paths"].items())[:TOP_ROWS], ["Path", "Hits"])
    _section(out, "Top HTTP user agents",
             list(agg["http_user_agents"].items())[:TOP_ROWS], ["User-Agent", "Hits"])
    _section(out, "SSH client banners seen",
             list(agg["ssh_banners"].items())[:TOP_ROWS], ["Banner", "Count"])
    _section(out, "Top SSH usernames tried",
             list(agg["ssh_usernames"].items())[:TOP_ROWS],
             ["Username", "Attempts"])
    _section(out, "Top SSH passwords tried",
             list(agg["ssh_passwords"].items())[:TOP_ROWS],
             ["Password", "Attempts"])
    _section(out, "SSH auth methods",
             list(agg["ssh_methods"].items()), ["Method", "Attempts"])
    _section(out, "Events per sensor host",
             list(agg["sensor_hosts"].items()), ["Sensor host", "Events"])

    out.extend(["## Timeline (events per hour, UTC)", ""])
    if agg["timeline"]:
        out.extend([_table(list(agg["timeline"].items()), ["Hour", "Events"]), ""])
    else:
        out.extend(["_none_", ""])

    out.extend([
        "---",
        "_AFRITHREAT (NUMAWARE) · low-interaction honeypots · deploy only on "
        "infrastructure you own or are authorized to monitor · data is "
        "minimized to attack metadata_",
    ])
    return "\n".join(out)
