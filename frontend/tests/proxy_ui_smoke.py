"""Exercise the built UI with isolated API fixtures; never starts real registrations.

Run after npm run build: ../.venv/bin/python tests/proxy_ui_smoke.py
"""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from threading import Thread
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright

STATIC = Path(__file__).resolve().parents[2] / "static"


class StaticHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def do_GET(self):
        if not (STATIC / self.path.lstrip("/")).is_file():
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, *args):
        pass


def run():
    server = ThreadingHTTPServer(("127.0.0.1", 0), StaticHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    manual_option = {"key": "manual:1", "label": "Fixture US", "kind": "manual"}
    sub_option = {"key": "subscription:Fixture SG", "label": "Fixture SG", "kind": "subscription"}
    fixtures = {"options": [], "options_error": False, "check_started": False, "polls": 0, "payloads": []}
    unexpected = []
    errors = []

    def handle(route):
        request = route.request
        if not request.url.startswith(base + "/"):
            route.abort()
            return
        path = urlparse(request.url).path
        if not path.startswith("/api/"):
            route.continue_()
            return
        status = 200
        if path == "/api/auth/status":
            payload = {"has_password": True, "authenticated": True}
        elif path == "/api/config":
            payload = {"default_proxy": "http://unused.example:1234"}
        elif path == "/api/gmail/sources":
            payload = {"items": [{"id": 1, "email": "fixture@gmail.com", "enabled": True, "usability_status": "usable", "receive_ready": True, "alias_count": 1}]}
        elif path == "/api/gmail/aliases":
            payload = {"items": [{"id": 1, "source_id": 1, "email": "fixture+child@gmail.com", "registration_status": "unregistered"}]}
        elif path == "/api/proxies/registration-options":
            payload = {"items": fixtures["options"]}
            if fixtures["options_error"]:
                status, payload = 503, {"detail": "fixture unavailable"}
        elif path == "/api/tasks/register":
            fixtures["payloads"].append(request.post_data_json)
            payload = {"task_id": "fixture-task"}
        elif path == "/api/tasks/fixture-task":
            payload = {"status": "done", "logs": ["Fixture task; no external requests"]}
        elif path == "/api/proxies":
            done = fixtures["polls"] >= 5
            payload = [{"id": 1, "url": "http://127.0.0.1:1234", "region": "US", "is_active": True,
                        "is_usable": done, "last_check_at": "2026-09-16T01:02:03Z" if done else None,
                        "last_check_ok": True if done else None, "last_check_error": "", "latency_ms": 42 if done else None,
                        "success_count": 1 if done else 0, "fail_count": 0}]
        elif path in ("/api/proxies/check", "/api/proxies/check-status"):
            if request.method == "POST":
                fixtures["check_started"] = True
            elif fixtures["check_started"]:
                fixtures["polls"] += 1
            done = fixtures["polls"] >= 5
            payload = {"running": fixtures["check_started"] and not done, "total": 1, "completed": int(done),
                       "ok": int(done), "fail": 0, "started_at": "2026-09-16T01:02:00Z" if fixtures["check_started"] else None,
                       "finished_at": "2026-09-16T01:02:03Z" if done else None}
        elif path == "/api/proxies/subscription/status":
            payload = {"installed": True, "running": True, "pool": [], "nodes": [{"name": "Unchecked fixture", "type": "ss"}], "test": {"running": False, "results": []}}
        elif path == "/api/proxies/subscription/chatgpt-protocol-status":
            payload = {"running": False, "pool": [], "results": [], "updated_at": 0}
        else:
            unexpected.append(f"{request.method} {path}")
            status, payload = 500, {"detail": "Unexpected API request in fixture test"}
        route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(channel="chrome", headless=True)
            except Exception:
                browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1050})
            page.set_default_timeout(10000)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/*", handle)
            page.goto(base, wait_until="networkidle")
            expect(page.get_by_role("tab")).to_have_count(2)
            page.get_by_role("button", name=re.compile(r"注册 \/ 继续所选$")).click()
            dialog = page.get_by_role("dialog", name="注册 Gmail 普通账号")
            start = dialog.get_by_role("button", name="启动 1 个账号", exact=True)
            expect(start).to_be_disabled()
            expect(dialog.get_by_text("暂无检测通过的可用代理，请先前往代理管理添加并检测。", exact=True)).to_be_visible()
            expect(dialog.get_by_text("无头浏览器（默认）", exact=True)).to_be_visible()
            expect(dialog.get_by_placeholder("代理地址（可选）")).to_have_count(0)

            fixtures["options"] = [manual_option, sub_option]
            dialog.get_by_role("button", name=re.compile(r"刷新可用代理$")).click()
            proxy_select = dialog.get_by_role("combobox", name="注册代理", exact=True)
            proxy_select.press("ArrowDown")
            page.get_by_title("手动 · Fixture US", exact=True).click()
            expect(start).to_be_enabled()

            fixtures["options_error"] = True
            dialog.get_by_role("button", name=re.compile(r"刷新可用代理$")).click()
            expect(dialog.get_by_text("可用代理读取失败：fixture unavailable", exact=True)).to_be_visible()
            expect(start).to_be_disabled()
            expect(dialog.get_by_text("手动 · Fixture US", exact=True)).to_be_visible()

            fixtures["options_error"] = False
            fixtures["options"] = [sub_option]
            dialog.get_by_role("button", name=re.compile(r"刷新可用代理$")).click()
            expect(dialog.get_by_text("所选代理已不可用或检测结果已失效，请重新检测并选择可用代理。", exact=True)).to_be_visible()
            expect(start).to_be_disabled()
            expect(dialog.get_by_text("手动 · Fixture US（已不可用）", exact=True)).to_be_visible()
            proxy_select.press("ArrowDown")
            page.get_by_title("订阅 · Fixture SG", exact=True).click()
            expect(start).to_be_enabled()
            # The selected node can disappear after rendering but before submit.
            fixtures["options"] = []
            start.click()
            expect(dialog.get_by_text("注册任务未启动", exact=True)).to_be_visible()
            expect(start).to_be_disabled()
            assert not fixtures["payloads"]
            fixtures["options"] = [sub_option]
            dialog.get_by_role("button", name=re.compile(r"刷新可用代理$")).click()
            expect(start).to_be_enabled()
            start.click()
            expect(page.get_by_role("dialog", name="GPT 注册任务")).to_be_visible()
            assert len(fixtures["payloads"]) == 1
            payload = fixtures["payloads"][0]
            assert payload["proxy_key"] == sub_option["key"]
            assert payload["executor_type"] == "headless"
            assert "proxy" not in payload
            page.get_by_role("dialog", name="GPT 注册任务").get_by_role("button", name=re.compile(r"关\s*闭$")).click()

            page.get_by_role("banner").get_by_role("button", name=re.compile(r"代理管理$")).click()
            expect(page).to_have_url(base + "/proxies")
            expect(page.get_by_text("Unchecked fixture", exact=True)).to_be_visible()
            expect(page.get_by_text("未检测", exact=True)).to_be_visible()
            page.get_by_role("tab", name="手动代理", exact=True).click()
            check = page.get_by_role("button", name=re.compile(r"检测全部（ChatGPT CSRF）$"))
            check.click()
            expect(page.get_by_text("检测进行中", exact=True)).to_be_visible()
            page.wait_for_timeout(3400)
            expect(page.get_by_text("检测进行中", exact=True)).to_be_visible()
            expect(check).to_be_disabled()
            expect(page.get_by_text("检测已结束", exact=True)).to_be_visible()
            expect(page.get_by_text("可选用", exact=True)).to_be_visible()
            expect(page.get_by_text("42 ms", exact=True)).to_be_visible()
            assert fixtures["polls"] >= 5
            page.screenshot(path="/tmp/gbm-proxy-ui-smoke.png", full_page=True)
            page.get_by_role("button", name=re.compile(r"设\s*置$")).click()
            expect(page.get_by_text("无头浏览器（默认）", exact=True)).to_be_visible()
            expect(page.get_by_text("注册任务必须选择检测通过的代理", exact=True)).to_be_visible()
            assert not unexpected, unexpected
            assert not errors, errors
            browser.close()
        print("PASS: two tabs, headless default, proxy-only registration, manual/subscription selection, empty/error/stale blocking, real async polling past 3 seconds")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    run()
