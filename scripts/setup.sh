#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
if command -v uv >/dev/null 2>&1; then
  if [[ ! -x .venv/bin/python ]]; then uv venv .venv --python 3.13; fi
  uv pip install --python .venv/bin/python -r requirements.lock.txt
else
  if [[ ! -x .venv/bin/python ]]; then python3 -m venv .venv; fi
  .venv/bin/python -m pip install -r requirements.lock.txt
fi
.venv/bin/python - <<'PY'
from DrissionPage import ChromiumOptions
from core.browser_startup import _executable

try:
    browser = _executable(ChromiumOptions(read_file=False))
except FileNotFoundError:
    print('尚未找到 Chrome/Chromium。请按 README 的 Linux 部署说明安装浏览器，或设置 DRISSION_BROWSER_PATH 后再启动。')
else:
    print(f'已找到本机浏览器：{browser}')
PY
cd frontend
npm ci --no-audit --no-fund
npm run build
echo '安装完成。运行 ./scripts/server.sh start 启动服务。'
