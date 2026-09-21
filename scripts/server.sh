#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
if [[ ! -x .venv/bin/python ]]; then
  echo '请先执行 ./scripts/setup.sh' >&2
  exit 1
fi
exec .venv/bin/python scripts/server.py "${1:-start}"
