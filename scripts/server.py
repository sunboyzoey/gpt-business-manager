#!/usr/bin/env python3
"""Control only this checkout's backend; never signal a process by port/name."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import psutil

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PID_FILE = DATA / "server.pid"
HOST = os.getenv("GBM_HOST", "127.0.0.1")
PORT = int(os.getenv("GBM_PORT", "8011"))
URL = f"http://127.0.0.1:{PORT}"


def process_url(proc=None):
    """Report the port owned by this checkout, not another compatible app."""
    port = PORT
    if proc is not None:
        try:
            read_environment = getattr(proc, "environ", None)
            if callable(read_environment):
                port = int(read_environment().get("GBM_PORT", port))
        except (psutil.Error, TypeError, ValueError):
            pass
    return f"http://127.0.0.1:{port}"


def process():
    if not PID_FILE.exists():
        return None
    try:
        proc = psutil.Process(int(PID_FILE.read_text().strip()))
        if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
            return None
        if Path(proc.cwd()).resolve() != ROOT or not any(Path(arg).name == "main.py" for arg in proc.cmdline()[1:]):
            raise RuntimeError("PID 文件对应其他进程，未执行任何停止操作")
        return proc
    except psutil.NoSuchProcess:
        return None


def healthy(proc=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(process_url(proc) + "/healthz", timeout=1) as response:
            payload = json.load(response)
            return payload.get("ok") and payload.get("project") == "gmail-business-manager"
    except (OSError, ValueError):
        return False


def stop():
    proc = process()
    if not proc:
        print("[stop] 未运行")
        return
    proc.terminate()
    try:
        proc.wait(timeout=60)
    except psutil.TimeoutExpired:
        raise RuntimeError("服务仍在等待任务安全退出，请查看日志后重试；未强制终止") from None
    PID_FILE.unlink(missing_ok=True)
    print("[stop] 已停止")


def start():
    proc = process()
    if proc:
        print(f"[start] 已运行 PID {proc.pid}：{process_url(proc)}")
        return
    if not (ROOT / "static/index.html").exists():
        raise RuntimeError("请先构建前端：cd frontend && npm ci && npm run build")
    with socket.socket() as sock:
        # A clean restart can leave the previous listener's connections in
        # TIME_WAIT briefly. Match uvicorn's reusable listener semantics so a
        # completed stop can be followed by an immediate start.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((HOST, PORT))
        except OSError:
            raise RuntimeError(f"端口 {PORT} 已被占用，未启动第二个服务") from None
    DATA.mkdir(exist_ok=True)
    migration = subprocess.run(
        [str(ROOT / ".venv/bin/python"), "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    if migration.returncode != 0:
        detail = (migration.stderr or migration.stdout or "数据库迁移失败").strip().splitlines()[-1]
        raise RuntimeError(f"数据库迁移失败：{detail}")
    with (DATA / "server.log").open("ab") as log:
        proc = subprocess.Popen([str(ROOT / ".venv/bin/python"), "main.py"], cwd=ROOT,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    PID_FILE.write_text(str(proc.pid))
    for _ in range(50):
        if proc.poll() is not None:
            raise RuntimeError("服务启动失败，请查看 data/server.log")
        if healthy(proc):
            print(f"[start] {URL}（PID {proc.pid}）")
            return
        time.sleep(0.5)
    raise RuntimeError("服务尚未就绪，请查看 data/server.log")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["start", "stop", "restart", "status"])
    args = parser.parse_args()
    try:
        if args.action in ("stop", "restart"):
            stop()
        if args.action in ("start", "restart"):
            start()
        if args.action == "status":
            proc = process()
            print(f"运行中：{process_url(proc)}" if proc and healthy(proc) else "未运行或尚未就绪")
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)
