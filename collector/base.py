"""Shared helpers for collection modules: write evidence, hash it, report progress."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable

from core import manifest, progress
from core.audit import audit


class Ctx:
    """Collection context passed to every module."""

    def __init__(self, case_dir: Path, case: dict, listener: Callable[[dict], None] | None = None,
                 baseline: bool = False, incident_start=None):
        self.case_dir = Path(case_dir)
        self.case = case
        self.listener = listener
        self.baseline = baseline
        self.incident_start = incident_start
        self.snapshot: dict[str, dict] = {}   # category -> {key: value} for baseline diff
        self.count = 0
        self.bytes = 0

    @property
    def live_dir(self) -> Path:
        d = self.case_dir / ("raw/baseline" if self.baseline else "raw/live")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def emit(self, module: str, status: str, **kw) -> None:
        ev = progress.emit(self.case_dir, module, status, **kw)
        if self.listener:
            self.listener(ev)

    def log(self, module: str, msg: str, level: str = "INFO") -> None:
        audit(self.case_dir, module, msg, level)

    def register(self, module: str, path: Path, pct: float | None = None) -> dict:
        entry = manifest.add_artifact(self.case_dir, path, module)
        self.count += 1
        self.bytes += entry["size"]
        self.emit(module, "file", file=entry["path"], sha256=entry["sha256"], pct=pct)
        return entry

    def write_json(self, module: str, rel: str, data, pct: float | None = None) -> dict:
        path = self.case_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return self.register(module, path, pct)

    def copy(self, module: str, src: Path, rel: str) -> dict | None:
        """Copy a file into the case (never opened in place), then hash it."""
        dest = self.case_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            stem, i = dest.stem, 1
            while dest.exists():
                dest = dest.with_name(f"{stem}_{i}{dest.suffix}")
                i += 1
        try:
            shutil.copy2(src, dest)
        except (PermissionError, OSError) as e:
            # Locked SQLite databases (browsers): fall back to the online backup API, read-only URI.
            if str(src).endswith(("History", ".sqlite")):
                try:
                    import sqlite3
                    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
                    d = sqlite3.connect(dest)
                    s.backup(d)
                    s.close(); d.close()
                except Exception as e2:  # noqa: BLE001
                    self.log(module, f"could not copy {src}: {e2}", "WARN")
                    return None
            else:
                self.log(module, f"could not copy {src}: {e}", "WARN")
                return None
        return self.register(module, dest)

    def add_snapshot(self, category: str, key: str, value) -> None:
        self.snapshot.setdefault(category, {})[key] = value


def run_cmd(args: list[str], timeout: int = 60) -> str:
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.stdout
    except Exception:
        return ""
