"""Browser runtime helpers for headless/headed resolution."""

from __future__ import annotations

import logging
import os
import sys
from typing import Iterable


logger = logging.getLogger(__name__)

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def parse_env_bool(name: str) -> bool | None:
    raw = os.getenv(name)
    if raw is None:
        return None

    value = str(raw).strip().lower()
    if not value:
        return None
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    logger.warning("忽略无效布尔环境变量 %s=%r", name, raw)
    return None


def resolve_browser_headless(
    requested_headless: bool | None,
    *,
    default_headless: bool = True,
    override_env_names: Iterable[str] = ("PLAYWRIGHT_HEADLESS", "REGISTER_HEADLESS"),
) -> tuple[bool, str]:
    for env_name in override_env_names:
        override = parse_env_bool(env_name)
        if override is not None:
            return override, f"env:{env_name}={str(override).lower()}"

    if requested_headless is not None:
        return bool(
            requested_headless
        ), f"requested:{str(bool(requested_headless)).lower()}"

    return bool(default_headless), f"default:{str(bool(default_headless)).lower()}"


def ensure_browser_display_available(headless: bool) -> None:
    if headless:
        return
    if not sys.platform.startswith("linux"):
        return
    if os.getenv("DISPLAY"):
        return

    raise RuntimeError(
        "当前为 Linux 有头浏览器模式，但未检测到 DISPLAY。"
        "Docker 内请启用 Xvfb；本地 Linux 请先启动图形环境或改用无头模式。"
    )
