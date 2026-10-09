#!/bin/bash
# scan.sh — legacy wrapper (kept for backward compat). Use ./auto_scan.sh for full triage.
# Old usage: ./scan.sh <target>  →  forwards to auto_scan.sh
DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${1:-}" ]; then
  echo "Usage: ./scan.sh <target-ip-or-domain>  (or new: ./auto_scan.sh -t <target> [--fast] [--json])"
  exit 1
fi
exec "$DIR/auto_scan.sh" -t "$1"
