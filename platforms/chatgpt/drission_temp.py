"""Utilities for DrissionPage temporary Chromium profiles.

DrissionPage creates per-browser profiles under /tmp/DrissionPage/autoPortData.
Failed or timed-out browser sessions can leave large profile directories behind,
so cleanup must be both regular and careful:

- per-run cleanup removes the exact profile for a browser after it exits;
- manual cleanup removes only inactive profiles old enough to avoid races.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


DRISSION_TEMP_ROOT = Path(
    os.getenv("DRISSION_TEMP_ROOT", str(Path(tempfile.gettempdir()) / "DrissionPage"))
).resolve()
DRISSION_PROFILE_ROOT = DRISSION_TEMP_ROOT / "autoPortData"
_SNAPSHOT_CACHE: dict[str, Any] = {"at": 0.0, "data": None}


def format_bytes(size: int) -> str:
    value = float(max(0, int(size or 0)))
    units = ("B", "KB", "MB", "GB", "TB")
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    if unit == "B":
        return f"{int(value)}B"
    return f"{value:.1f}{unit}"


def _resolve_path(path: str | os.PathLike[str]) -> Path:
    return Path(path).expanduser().resolve()


def _is_child_path(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_profile_path(path: str | os.PathLike[str] | None) -> Path | None:
    if not path:
        return None
    try:
        resolved = _resolve_path(path)
    except Exception:
        return None
    if resolved == DRISSION_PROFILE_ROOT or resolved == DRISSION_TEMP_ROOT:
        return None
    if not _is_child_path(resolved, DRISSION_PROFILE_ROOT):
        return None
    return resolved


def _active_profile_paths() -> set[Path]:
    """Return profile dirs currently referenced by running Chromium processes."""
    try:
        output = subprocess.check_output(
            ["ps", "-eo", "args"],
            text=True,
            stderr=subprocess.DEVNULL,
            errors="ignore",
        )
    except Exception:
        return set()

    active: set[Path] = set()
    pattern = re.compile(r"--user-data-dir=(\"[^\"]+\"|'[^']+'|\S+)")
    for line in output.splitlines():
        if "DrissionPage/autoPortData" not in line:
            continue
        for match in pattern.finditer(line):
            raw = match.group(1).strip().strip("\"'")
            profile = _safe_profile_path(raw)
            if profile:
                active.add(profile)
    return active


def _dir_size(path: Path) -> int:
    total = 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def invalidate_drission_temp_snapshot() -> None:
    _SNAPSHOT_CACHE["at"] = 0.0
    _SNAPSHOT_CACHE["data"] = None


def drission_temp_snapshot(*, cache_ttl_seconds: float = 30.0) -> dict[str, Any]:
    now = time.monotonic()
    cached = _SNAPSHOT_CACHE.get("data")
    if cached and now - float(_SNAPSHOT_CACHE.get("at") or 0) < cache_ttl_seconds:
        return dict(cached)

    active = _active_profile_paths()
    profile_dirs: list[Path] = []
    if DRISSION_PROFILE_ROOT.is_dir():
        try:
            profile_dirs = [p.resolve() for p in DRISSION_PROFILE_ROOT.iterdir() if p.is_dir()]
        except OSError:
            profile_dirs = []

    total_bytes = _dir_size(DRISSION_TEMP_ROOT) if DRISSION_TEMP_ROOT.exists() else 0
    active_count = sum(1 for p in profile_dirs if p in active)
    data = {
        "root": str(DRISSION_TEMP_ROOT),
        "profile_root": str(DRISSION_PROFILE_ROOT),
        "exists": DRISSION_TEMP_ROOT.exists(),
        "total_bytes": total_bytes,
        "total_human": format_bytes(total_bytes),
        "profile_count": len(profile_dirs),
        "active_profile_count": active_count,
        "inactive_profile_count": max(0, len(profile_dirs) - active_count),
        "scanned_at": time.time(),
    }
    _SNAPSHOT_CACHE["at"] = now
    _SNAPSHOT_CACHE["data"] = dict(data)
    return data


def cleanup_profile_path(
    path: str | os.PathLike[str] | None,
    *,
    wait_seconds: float = 5.0,
) -> dict[str, Any]:
    """Delete one Drission profile after its browser exits."""
    profile = _safe_profile_path(path)
    if not profile:
        return {"deleted": False, "reason": "invalid_path", "path": str(path or "")}
    if not profile.exists():
        return {"deleted": False, "reason": "missing", "path": str(profile)}

    deadline = time.monotonic() + max(0.0, wait_seconds)
    while time.monotonic() < deadline:
        if profile not in _active_profile_paths():
            break
        time.sleep(0.25)

    if profile in _active_profile_paths():
        return {"deleted": False, "reason": "active", "path": str(profile)}

    freed = _dir_size(profile)
    try:
        shutil.rmtree(profile)
    except FileNotFoundError:
        freed = 0
    except Exception as exc:
        return {
            "deleted": False,
            "reason": f"delete_failed: {exc}",
            "path": str(profile),
        }
    invalidate_drission_temp_snapshot()
    return {
        "deleted": True,
        "path": str(profile),
        "freed_bytes": freed,
        "freed_human": format_bytes(freed),
    }


def cleanup_inactive_profiles(*, min_age_seconds: int = 60) -> dict[str, Any]:
    """Delete inactive Drission profiles older than min_age_seconds."""
    min_age = max(0, int(min_age_seconds or 0))
    DRISSION_PROFILE_ROOT.mkdir(parents=True, exist_ok=True)
    active = _active_profile_paths()
    now = time.time()

    deleted = 0
    freed = 0
    skipped_active = 0
    skipped_recent = 0
    errors: list[str] = []

    try:
        profile_dirs = [p.resolve() for p in DRISSION_PROFILE_ROOT.iterdir() if p.is_dir()]
    except OSError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "deleted": 0,
            "freed_bytes": 0,
            "freed_human": format_bytes(0),
            "snapshot": drission_temp_snapshot(cache_ttl_seconds=0),
        }

    for profile in profile_dirs:
        safe = _safe_profile_path(profile)
        if not safe:
            continue
        if safe in active:
            skipped_active += 1
            continue
        try:
            age = now - safe.stat().st_mtime
        except OSError:
            continue
        if age < min_age:
            skipped_recent += 1
            continue
        size = _dir_size(safe)
        try:
            shutil.rmtree(safe)
        except FileNotFoundError:
            continue
        except Exception as exc:
            errors.append(f"{safe.name}: {exc}")
            continue
        deleted += 1
        freed += size

    invalidate_drission_temp_snapshot()
    return {
        "ok": not errors,
        "deleted": deleted,
        "freed_bytes": freed,
        "freed_human": format_bytes(freed),
        "skipped_active": skipped_active,
        "skipped_recent": skipped_recent,
        "errors": errors[:20],
        "snapshot": drission_temp_snapshot(cache_ttl_seconds=0),
    }
