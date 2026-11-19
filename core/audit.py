"""audit.log: one line per action the tool performs (FR-3)."""
from __future__ import annotations

import getpass
import threading
from pathlib import Path

from .timeutil import now_iso

_lock = threading.Lock()


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def audit(case_dir: Path, module: str, message: str, level: str = "INFO") -> None:
    line = f"{now_iso()} {level:<5} [{module}] ({_user()}) {message}\n"
    with _lock:
        with open(Path(case_dir) / "audit.log", "a", encoding="utf-8") as f:
            f.write(line)


def read_audit(case_dir: Path) -> list[str]:
    p = Path(case_dir) / "audit.log"
    return p.read_text(encoding="utf-8").splitlines() if p.exists() else []
