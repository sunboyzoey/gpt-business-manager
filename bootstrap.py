"""Project-local runtime paths, also inherited by isolated browser workers."""
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent


def _load_environment_file(path: Path) -> None:
    """Load simple KEY=VALUE deployment settings without executing shell code."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def configure():
    _load_environment_file(ROOT / ".env")
    os.chdir(ROOT)
    runtime = Path(os.getenv("GBM_RUNTIME_DIR", str(ROOT / "data"))).expanduser().resolve()
    runtime.mkdir(parents=True, exist_ok=True)
    os.environ["DATABASE_URL"] = os.getenv("GBM_DATABASE_URL", "sqlite:///" + str(runtime / "workspace.db"))
    os.environ["APP_RUNTIME_DIR"] = str(runtime)
    # A different project must never accidentally decrypt or mutate its neighbour's data.
    for key in ("APP_CREDENTIAL_ENCRYPTION_KEY", "APP_CREDENTIAL_ENCRYPTION_KEY_FILE", "APP_JWT_SECRET"):
        os.environ.pop(key, None)
        if os.getenv("GBM_" + key):
            os.environ[key] = os.environ["GBM_" + key]
    os.environ["APP_ENABLE_SOLVER"] = "0"
    os.environ["SOLVER_PORT"] = "8891"
    os.environ["LOCAL_SOLVER_URL"] = "http://127.0.0.1:8891"
    return runtime
