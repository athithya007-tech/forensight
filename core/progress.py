"""Progress events written to progress.jsonl so the dashboard WebSocket can stream them (FR-40),
whether collection runs inside the API process or from the CLI on another terminal."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from .timeutil import now_iso

_lock = threading.Lock()


def emit(case_dir: Path, module: str, status: str, pct: float | None = None, file: str | None = None,
         sha256: str | None = None, message: str | None = None) -> dict:
    ev = {"ts": now_iso(), "module": module, "status": status}
    if pct is not None:
        ev["pct"] = round(float(pct), 1)
    if file:
        ev["file"] = file
    if sha256:
        ev["sha256"] = sha256
    if message:
        ev["message"] = message
    with _lock:
        with open(Path(case_dir) / "progress.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
    return ev


def reset(case_dir: Path) -> None:
    p = Path(case_dir) / "progress.jsonl"
    if p.exists():
        p.unlink()
