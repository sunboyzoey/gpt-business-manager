"""Real browser/API smoke test using a disposable database, never live accounts."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]


def run():
    with tempfile.TemporaryDirectory(prefix="gbm-browser-test-") as directory:
        runtime = Path(directory)
        with socket.socket() as socket_:
            socket_.bind(("127.0.0.1", 0))
            port = socket_.getsockname()[1]
        env = {**os.environ, "GBM_PORT": str(port), "GBM_HOST": "127.0.0.1",
               "GBM_DATABASE_URL": "sqlite:///" + str(runtime / "test.db"), "GBM_RUNTIME_DIR": str(runtime)}
        # Fixtures represent local verified state. No Gmail/ChatGPT requests are sent.
        seed = '''
import main
from core.db import engine
from sqlmodel import SQLModel,Session
from services.gmail_store import GmailSource, generate_aliases, _encrypt
SQLModel.metadata.create_all(engine)
with Session(engine) as s:
    s.add(GmailSource(email="fixturemother@gmail.com",enabled=True,usability_status="usable",receive_verified=True,app_password_ciphertext=_encrypt("fixturemother@gmail.com","fixtureapppasswd")))
    s.commit()
generate_aliases(1,count=3,prefix="child")
'''
        subprocess.run([sys.executable, "-c", seed], cwd=ROOT, env=env, check=True)
        with (runtime / "server.log").open("wb") as log:
            proc = subprocess.Popen([sys.executable, "main.py"], cwd=ROOT, env=env, stdout=log, stderr=log)
        base = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError("Disposable test server failed to start")
                try:
                    with opener.open(base + "/healthz", timeout=1) as response:
                        if json.load(response)["ok"]:
                            break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("Disposable test server startup timed out")

            def api(path, payload):
                request = urllib.request.Request(base + path, data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"})
                with opener.open(request, timeout=10) as response:
                    return json.load(response)

            api("/api/workspace/ordinary/import", {"data": "fixturemother+child1@gmail.com----fixture-password", "registration_status": "registered"})
            api("/api/workspace/ordinary/import", {"data": "fixturemother+child2@gmail.com", "registration_status": "unregistered"})
            api("/api/workspace/business/import", {"data": "mother@example.com----fixture-password----JBSWY3DPEHPK3PXP", "mail_provider": "outlook"})
            with sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(channel="chrome", headless=True)
                except Exception:
                    browser = playwright.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 1050})
                page.set_default_timeout(8000)
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                # The browser is restricted to our fixture server for this test.
                page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
                page.goto(base, wait_until="networkidle")
                expect(page.get_by_text("已注册 1", exact=True)).to_be_visible()
                expect(page.get_by_text("未注册 / 待处理 2", exact=True)).to_be_visible()
                expect(page.get_by_text("fixturemother+child1@gmail.com", exact=True)).to_be_visible()
                expect(page.get_by_role("button", name="登录核验", exact=True)).to_be_visible()
                page.get_by_role("tab", name="BUSINESS 母号").click()
                expect(page.get_by_text("mother@example.com", exact=True).first).to_be_visible()
                expect(page.get_by_role("button", name=re.compile(r"登录核验$")).first).to_be_enabled()
                assert page.locator('[data-business-usage-select="true"]').count() == 0
                assert page.locator('[data-business-usage-filter="true"]').count() == 0
                page.get_by_label("更多母号操作 · mother@example.com").click()
                menu = page.locator('.ant-dropdown-menu:visible')
                expect(menu).to_be_visible()
                assert menu.get_by_text("设置密码与 2FA", exact=True).count() == 0
                page.keyboard.press("Escape")
                page.get_by_role("button", name=re.compile(r"导入 BUSINESS 母号$")).click()
                expect(page.get_by_role("dialog")).to_be_visible()
                expect(page.get_by_role("dialog").get_by_text("从当前系统迁移", exact=True)).to_be_visible()
                assert page.get_by_role("dialog").locator('input[type="file"][accept*="json"]').count() == 1
                page.get_by_role("dialog").get_by_role("button", name=re.compile(r"取\s*消$")).click()
                page.get_by_role("button", name=re.compile(r"设\s*置$")).click()
                expect(page.get_by_text("项目设置", exact=True)).to_be_visible()
                page.get_by_label("新密码", exact=True).fill("local-fixture-admin-password")
                page.get_by_label("确认密码", exact=True).fill("local-fixture-admin-password")
                page.get_by_role("button", name="启用访问密码", exact=True).click()
                expect(page.get_by_text("当前项目已启用密码保护。", exact=True)).to_be_visible()
                page.get_by_role("button", name="返回账号", exact=True).click()
                expect(page.get_by_text("fixturemother+child1@gmail.com", exact=True)).to_be_visible()
                assert not errors, errors
                browser.close()
            print("PASS: two tabs, registered/unregistered aliases, mother import/login entry, settings and admin auth; isolated fixture DB")
        finally:
            proc.terminate()
            proc.wait(timeout=45)


if __name__ == "__main__":
    run()
