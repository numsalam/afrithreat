"""Pluggable source-IP enrichment.

v1 ships a null enricher plus an offline CSV enricher so reports can
label country/ASN without any network dependency. Point `enrich.csv_path`
at any CSV with columns `network,country,asn,org` (CIDR supported,
header row optional) — e.g. a GeoLite dump you are licensed to use.

Lookups are a linear scan: fine for country-level datasets and the
v1 scale of unique attackers per report window.
"""

import csv
from ipaddress import ip_address, ip_network
from pathlib import Path


class NullEnricher:
    """Default: no enrichment data available."""

    def enrich(self, ip):
        return {}


class CSVRangeEnricher:
    """Offline enricher over CIDR ranges loaded from a CSV file."""

    def __init__(self, csv_path):
        self._networks = []
        self._load(csv_path)

    def _load(self, csv_path):
        with open(csv_path, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if not row or row[0] in ("network", ""):
                    continue
                try:
                    net = ip_network(row[0], strict=False)
                except ValueError:
                    continue
                self._networks.append((net, {
                    "country": row[1] if len(row) > 1 else "",
                    "asn": row[2] if len(row) > 2 else "",
                    "org": row[3] if len(row) > 3 else "",
                }))
        self._networks.sort(key=lambda item: int(item[0].network_address))

    def enrich(self, ip):
        try:
            addr = ip_address(ip)
        except ValueError:
            return {}
        for net, meta in self._networks:
            if addr in net:
                return meta
        return {}


def build_enricher(config):
    """Choose an enricher from config: `enrich.csv_path` if present."""
    enrich_cfg = (config or {}).get("enrich") or {}
    csv_path = enrich_cfg.get("csv_path")
    if csv_path and Path(csv_path).exists():
        return CSVRangeEnricher(csv_path)
    return NullEnricher()
