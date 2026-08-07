

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "index.html"
DEFAULT_LIMIT = 300
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


def load_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, minimum), maximum)


load_env_file()


OPENAI_MODEL = os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL
OPENAI_CLASSIFY_MODEL = os.environ.get("OPENAI_CLASSIFY_MODEL", OPENAI_MODEL).strip() or OPENAI_MODEL
OPENAI_CLASSIFY_BATCH_SIZE = env_int("OPENAI_CLASSIFY_BATCH_SIZE", 50, 1, 100)
ABUSEIPDB_MAX_AGE_DAYS = env_int("ABUSEIPDB_MAX_AGE_DAYS", 90, 1, 365)





VALID_CLASSIFICATIONS = {"critical", "high", "warning", "info"}
CLASSIFICATION_SCORES = {"critical": 6, "high": 4, "warning": 2, "info": 0}


STATE: dict[str, Any] = {
    "source": "none",
    "es": {
        "url": "",
        "username": "",
        "password": "",
        "index": "logs-*",
        "connected": False,
        "error": "",
    },
    "uploaded_logs": [],
    "uploaded_label": "Uploaded logs",
}
