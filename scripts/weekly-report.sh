#!/bin/sh
# AFRITHREAT weekly report: generate → git commit → git push.
#
# Install from cron (Sundays 06:00):
#   0 6 * * sun /opt/afrithreat/scripts/weekly-report.sh /opt/afrithreat
#
# Or use the provided systemd timer: deploy/afrithreat-report.timer
# (preferred — it catches up after downtime via Persistent=true).
set -eu

REPO_DIR="${1:?usage: weekly-report.sh <afrithreat-repo-dir>}"
cd "$REPO_DIR"
python3 -m afrithreat report --config config.json --out reports --commit --push
