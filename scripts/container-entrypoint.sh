#!/usr/bin/env sh
set -eu
python -m alembic upgrade head
exec python main.py
