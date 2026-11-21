# AFRITHREAT

**African honeypot network & threat intelligence.** Pure Python. Zero dependencies.

Nobody publishes threat telemetry focused on African IP space. AFRITHREAT deploys
low-interaction honeypots, records attacker behavior, and turns it into weekly
reports — an independent, African-owned view of the threat landscape, built by
NUMAWARE.

> Philosophy: architecture-first, authorized-by-design, observe — never retaliate.

## Architecture

```
  internet attackers
         │
         ▼
┌──────────────┐    ┌───────────────┐    ┌────────────┐    ┌──────────────┐
│    SENSORS   │───▶│  events.jsonl │───▶│  COLLECTOR │───▶│   REPORTS    │
│  http        │    │ append-only   │    │ aggregate  │    │  report.md   │
│  telnet      │    │ thread-safe   │    │ enrich     │    │  report.json │
│  ssh (full   │    │ JSONL log     │    │ by source  │    │ human+machine│
│  kex+auth)   │    └───────────────┘    │ + host     │    └──────────────┘
└──────────────┘              │          └────────────┘           │
                              │ push                            │ --commit
                              ▼                                 ▼
                     ┌──────────────────┐             ┌──────────────────┐
                     │ collect-server   │             │ git history of   │
                     │ (central, token- │             │ weekly reports   │
                     │  gated ingest)   │             │ (cron/systemd)   │
                     └──────────────────┘             └──────────────────┘
```

- **http** — logs every request: method, path, headers, body. Answers 404 so scanners keep coming back.
- **telnet** — plays a login dialog, captures every username/password attempt, then a fake shell that logs commands and executes nothing. RFC 854 IAC negotiation bytes are stripped (and answered like a minimal server), so credentials land clean even from negotiating clients.
- **ssh** — completes a **real SSH-2 key exchange** (pure-Python transport: DH group14-sha256/group1-sha1, RSA host key, aes128-ctr, hmac-sha2-256/sha1), then captures **every username/password/public-key attempt** and always refuses. No channels, no shells, no execution.
- **collector** — aggregates by source IP, protocol, credentials, paths, banners, sensor host, and hour.
- **enrichment** — pluggable; offline CSV (`network,country,asn,org`, CIDR supported), no network calls; ASN/org columns and a per-ASN event breakdown appear in reports when the data is present.
- **reports** — Markdown for humans, JSON for machines; optionally auto-committed and pushed to git on a weekly schedule.

## Quickstart

```bash
python -m afrithreat serve           # run sensors (reads config.json)
python -m afrithreat stats           # quick console summary
python -m afrithreat report          # writes reports/report.md + report.json
python -m afrithreat push            # ship events to the central collect-server
python -m afrithreat collect-server  # run the central multi-host collector
```

Or `python run.py serve`. Test locally first — the default config binds
`127.0.0.1`, so nothing is exposed until you deliberately change it.

## Configuration (`config.json`)

```json
{
  "sensors": [
    {"name": "http-1",   "protocol": "http",   "port": 8080, "bind": "127.0.0.1"},
    {"name": "telnet-1", "protocol": "telnet", "port": 2323, "bind": "127.0.0.1"},
    {"name": "ssh-1",    "protocol": "ssh",    "port": 2222, "bind": "127.0.0.1"}
  ],
  "data_dir": "data",
  "report": {"title": "AFRITHREAT Weekly Threat Report", "lookback_hours": 168},
  "limits": {"max_line_bytes": 4096, "socket_timeout": 30.0, "max_connections_per_ip": 200},
  "enrich": {"csv_path": null},
  "collector": {
    "sensor_host": null,
    "ingest_url": "http://127.0.0.1:8090/ingest",
    "token": null,
    "batch_lines": 500,
    "timeout": 15.0
  },
  "ingest": {
    "bind": "127.0.0.1",
    "port": 8090,
    "token": null,
    "max_body_bytes": 8388608,
    "max_events_per_batch": 5000,
    "max_event_bytes": 65536
  }
}
```

- `bind` — `127.0.0.1` for local testing; your public interface only on servers you control.
- `limits` — size/time/connection caps so attackers cannot exhaust the host.
- `enrich.csv_path` — optional offline CSV with columns `network,country,asn,org`.
- `collector` — sensor-side push settings. `sensor_host` defaults to the machine's hostname; `token` must match the collector's.
- `ingest` — central-side collect-server settings. **`token` must be set or the server refuses to start** (fail closed); everything is bounded (body/batch/event size).

## Multi-host collection

Each sensor host appends to its own local `events.jsonl` and periodically runs
`afrithreat push`. The central host runs `afrithreat collect-server`, which
authenticates pushes with a bearer token, tags every event with the pushing
host's `sensor_host` identity, and appends to one merged log. Reports on the
central host then cover the whole fleet, with a per-host breakdown.

The push cursor (`data/push_state.json`) only advances after the collector
confirms a batch — a failed or rejected push simply retries next run, so
nothing is lost and nothing is sent twice. Log rotation is detected and
handled (the cursor resets).

Deployment sketch:

```
sensor-a  ─┐
sensor-b  ─┼─▶ collect-server (token-gated) ─▶ merged events.jsonl ─▶ report
sensor-c  ─┘         on the central host
```

On sensor hosts, push on a timer (see `deploy/afrithreat-push.timer` — every
5 minutes) or from cron:

```
*/5 * * * * cd /opt/afrithreat && python3 -m afrithreat push
```

## Weekly reports on a schedule

`report --commit` git-commits the generated report files when they changed
(no empty commits); `--push` also pushes (implies `--commit`). Only `git add`
of the two report files, `git commit`, and a plain `git push` are ever run —
never any history-rewriting operation.

```bash
# cron — Sundays 06:00
0 6 * * sun /opt/afrithreat/scripts/weekly-report.sh /opt/afrithreat

# or systemd (preferred: catches up after downtime via Persistent=true)
sudo cp deploy/afrithreat-report.* /etc/systemd/system/
sudo systemctl enable --now afrithreat-report.timer
```

## Deployment & ethics

1. **Deploy only on infrastructure you own or are explicitly authorized to monitor.**
2. Low-interaction by design: attacker input is **logged, never executed**.
3. Data minimization: attack metadata only — no legitimate-user data is ever collected.
4. Observe and report. **Never scan back, never retaliate.**
5. If you publish reports, anonymize your own infrastructure details.

## Roadmap

- **v1** — HTTP + Telnet + SSH-banner sensors, JSONL event log, collector, Markdown/JSON reports, offline CSV enrichment, per-IP connection caps.
- **v2 (this)** — full SSH-2 key exchange + credential capture (pure-Python transport), Telnet IAC stripping, central token-gated collector for multi-host fleets (`push` / `collect-server`), per-sensor-host report breakdown, ASN enrichment in reports, weekly report automation (cron/systemd + git auto-commit/push).
- **v3** — weekly public reports + dataset releases; Bridge/CYBERAGENT integration (findings become objectives); SENTINEL alerting on aggressive sources; richer timelines.

## Layout

```
afrithreat/
├── afrithreat/          # the package
│   ├── sensors/         # http, telnet, ssh honeypots
│   ├── ssh/             # pure-Python SSH-2 transport (kex, crypto, keys)
│   ├── events.py        # JSONL event log
│   ├── collector.py     # aggregation
│   ├── enrich.py        # pluggable IP enrichment
│   ├── report.py        # markdown + json reports
│   ├── ingest_server.py # central token-gated collector
│   ├── push.py          # sensor-side shipper (resumable cursor)
│   ├── vcs.py           # git auto-commit for weekly reports
│   └── cli.py           # serve / report / stats / push / collect-server
├── tests/               # pytest suite (real-client integration tests)
├── scripts/             # weekly-report.sh (cron entry point)
├── deploy/              # systemd service + timer units
├── config.json          # safe local defaults
└── run.py               # thin entry point
```

## Tests

```bash
python -m pytest -q
```

## License

MIT — © 2026 Abdussalam Numaan Oluwatiloba (NUMSALAM) / NUMAWARE
