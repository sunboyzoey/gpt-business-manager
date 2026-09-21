"""All tests run with their own files, never the running workspace database."""
import os
from pathlib import Path
import tempfile

_runtime = tempfile.TemporaryDirectory(prefix="gmail-business-tests-")
_root = Path(_runtime.name)
os.environ["DATABASE_URL"] = os.environ["GBM_DATABASE_URL"] = "sqlite:///" + str(_root / "tests.db")
os.environ["APP_RUNTIME_DIR"] = os.environ["GBM_RUNTIME_DIR"] = str(_root)
os.environ.pop("APP_CREDENTIAL_ENCRYPTION_KEY", None)
os.environ.pop("APP_CREDENTIAL_ENCRYPTION_KEY_FILE", None)
os.environ["APP_ENABLE_SOLVER"] = "0"


def pytest_sessionfinish(session, exitstatus):
    _runtime.cleanup()
