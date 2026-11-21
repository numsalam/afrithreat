"""Command-line interface: serve / report / stats."""

import argparse
import sys
import time
from pathlib import Path

from .config import load_config
from .events import EventWriter, utc_now_iso
from .sensors import build_sensor


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="afrithreat",
        description="AFRITHREAT — African honeypot network & threat intelligence",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run honeypot sensors until Ctrl+C")
    p.add_argument("--config", default="config.json")

    p = sub.add_parser("report",
                       help="generate report.md + report.json from collected events")
    p.add_argument("--config", default="config.json")
    p.add_argument("--out", default="reports")
    p.add_argument("--commit", action="store_true",
                   help="git-commit the generated report files if they changed")
    p.add_argument("--push", action="store_true",
                   help="git-push after committing (implies --commit)")

    p = sub.add_parser("stats", help="print a quick console summary")
    p.add_argument("--config", default="config.json")

    p = sub.add_parser("push",
                       help="ship local events to the central collect-server")
    p.add_argument("--config", default="config.json")

    p = sub.add_parser("collect-server",
                       help="run the central multi-host collector")
    p.add_argument("--config", default="config.json")

    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.command == "serve":
        _serve(config)
    elif args.command == "report":
        _report(config, args.out, args.commit, args.push)
    elif args.command == "push":
        _push(config)
    elif args.command == "collect-server":
        _collect_server(config)
    else:
        _stats(config)


def _serve(config):
    writer = EventWriter(config["data_dir"])
    sensors = [build_sensor(spec, writer, config.get("limits", {}))
               for spec in config["sensors"]]
    for sensor in sensors:
        try:
            sensor.start()
        except OSError as exc:
            print(f"[afrithreat] cannot start {sensor.name} on "
                  f"{sensor.bind}:{sensor.port}: {exc}", file=sys.stderr)
            raise SystemExit(1) from None
        print(f"[afrithreat] {sensor.name} [{sensor.protocol}] "
              f"listening on {sensor.bind}:{sensor.port}")
    print(f"[afrithreat] logging to {writer.path} — Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for sensor in sensors:
            sensor.stop()
        print("[afrithreat] stopped")


def _report(config, out_dir, do_commit=False, do_push=False):
    from .report import generate_report
    path = generate_report(config, out_dir)
    print(f"[afrithreat] report written: {path}")
    if not (do_commit or do_push):
        return

    from .vcs import VcsError, commit_if_changed, push as git_push
    files = [Path(path), Path(path).with_name("report.json")]
    try:
        commit_hash = commit_if_changed(
            files, f"afrithreat: weekly threat report {utc_now_iso()}")
    except VcsError as exc:
        print(f"[afrithreat] git commit failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    if commit_hash is None:
        print("[afrithreat] report unchanged — no commit made")
        return
    print(f"[afrithreat] committed {commit_hash[:12]}")
    if do_push:
        from .vcs import repo_root
        try:
            git_push(repo_root(path))
        except VcsError as exc:
            print(f"[afrithreat] git push failed: {exc}", file=sys.stderr)
            raise SystemExit(1) from None
        print("[afrithreat] pushed to remote")


def _stats(config):
    from .collector import collect
    agg = collect(config["data_dir"])
    print(f"events: {agg['total_events']}  unique sources: {len(agg['sources'])}"
          f"  sensor hosts: {len(agg['sensor_hosts'])}")
    for protocol, count in agg["protocols"].items():
        print(f"  {protocol}: {count}")
    if agg["first_seen"]:
        print(f"window: {agg['first_seen']} -> {agg['last_seen']}")


def _push(config):
    from .push import PushError, push
    try:
        summary = push(config)
    except PushError as exc:
        print(f"[afrithreat] push failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(f"[afrithreat] pushed {summary['pushed']} events as "
          f"'{summary['sensor_host']}' in {summary['batches']} batch(es)"
          + (f" ({summary['skipped']} malformed lines skipped)"
             if summary["skipped"] else ""))


def _collect_server(config):
    from .ingest_server import IngestError, IngestServer
    ingest = config.get("ingest", {})
    try:
        server = IngestServer(
            ingest.get("bind", "127.0.0.1"),
            int(ingest.get("port", 8090)),
            ingest.get("token"),
            config["data_dir"],
            max_body_bytes=int(ingest.get("max_body_bytes", 8388608)),
            max_events_per_batch=int(ingest.get("max_events_per_batch", 5000)),
            max_event_bytes=int(ingest.get("max_event_bytes", 65536)),
        )
    except IngestError as exc:
        print(f"[afrithreat] {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(f"[afrithreat] collect-server listening on "
          f"{ingest.get('bind', '127.0.0.1')}:{server.port} — Ctrl+C to stop")
    print(f"[afrithreat] appending to {server.events_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        print("[afrithreat] stopped")
