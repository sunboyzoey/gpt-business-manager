"""Browser discovery without launching a process or relying on the host install."""
from types import SimpleNamespace

from DrissionPage._functions import browser as drission_browser
import pytest

from core import browser_startup


@pytest.fixture
def discovery(monkeypatch):
    for key in ("DRISSION_BROWSER_PATH", "CHROME_PATH", "CHROMIUM_PATH", "GOOGLE_CHROME_SHIM"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(browser_startup.shutil, "which", lambda value: None)
    monkeypatch.setattr(drission_browser, "get_chrome_path", lambda ini: None)
    return SimpleNamespace(browser_path="chrome", ini_path=None)


def executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def test_environment_path_wins_without_platform_discovery(discovery, tmp_path, monkeypatch):
    default = executable(tmp_path, "chrome")
    selected = executable(tmp_path, "chosen-chromium")
    monkeypatch.setattr(browser_startup.shutil, "which", lambda value: str(default) if value == "chrome" else None)
    monkeypatch.setenv("DRISSION_BROWSER_PATH", str(selected))

    def unexpected_scan(ini):
        pytest.fail("A valid override must not need platform discovery")

    monkeypatch.setattr(drission_browser, "get_chrome_path", unexpected_scan)
    assert browser_startup._executable(discovery) == str(selected)


def test_linux_chromium_browser_name_is_found_on_path(discovery, tmp_path, monkeypatch):
    selected = executable(tmp_path, "chromium-browser")
    monkeypatch.setattr(browser_startup.shutil, "which", lambda value: str(selected) if value == "chromium-browser" else None)
    assert browser_startup._executable(discovery) == str(selected)


def test_nonexecutable_candidate_falls_back_to_drission(discovery, tmp_path, monkeypatch):
    unavailable = tmp_path / "not-executable"
    unavailable.write_text("placeholder")
    monkeypatch.setenv("DRISSION_BROWSER_PATH", str(unavailable))
    selected = executable(tmp_path, "detected-chrome")
    monkeypatch.setattr(drission_browser, "get_chrome_path", lambda ini: str(selected))
    assert browser_startup._executable(discovery) == str(selected)


def test_missing_browser_fails_before_startup(discovery):
    with pytest.raises(FileNotFoundError, match="Chromium"):
        browser_startup._executable(discovery)


@pytest.mark.parametrize("error", [OSError("unavailable config"), RuntimeError("discovery failed")])
def test_platform_discovery_failure_has_missing_browser_diagnostic(discovery, monkeypatch, error):
    def failed_scan(ini):
        raise error

    monkeypatch.setattr(drission_browser, "get_chrome_path", failed_scan)
    with pytest.raises(FileNotFoundError, match="没有可用的本地 Chromium"):
        browser_startup._executable(discovery)
