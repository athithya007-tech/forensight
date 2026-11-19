"""Case management (US-001, FR-1..3)."""
from __future__ import annotations

import json
import platform
import socket
from datetime import timedelta
from pathlib import Path

from .audit import audit
from .paths import cases_root
from .timeutil import local_tz_name, now_utc, iso, now_iso

SUBDIRS = ["raw", "raw/live", "raw/logs", "raw/artifacts", "analysis", "report"]


def next_case_id(root: Path, when=None) -> str:
    when = when or now_utc()
    prefix = f"CASE-{when:%Y%m%d}-"
    n = 0
    if root.exists():
        for d in root.iterdir():
            if d.name.startswith(prefix):
                try:
                    n = max(n, int(d.name[len(prefix):]))
                except ValueError:
                    pass
    return f"{prefix}{n + 1:03d}"


def host_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "arch": platform.machine(),
        "timezone": local_tz_name(),
    }


def create_case(name: str, investigator: str, notes: str = "", root: Path | None = None,
                host: dict | None = None, case_id: str | None = None) -> Path:
    root = Path(root or cases_root())
    root.mkdir(parents=True, exist_ok=True)
    cid = case_id or next_case_id(root)
    d = root / cid
    d.mkdir(parents=True, exist_ok=False)
    for s in SUBDIRS:
        (d / s).mkdir(parents=True, exist_ok=True)
    h = host or host_info()
    start = now_utc()
    doc = {
        "id": cid,
        "name": name,
        "investigator": investigator,
        "notes": notes,
        "host": h.get("hostname"),
        "os": h.get("os"),
        "host_info": h,
        "created_at": iso(start),
        "start_time_utc": iso(start),
        "incident_window": {"start": iso(start - timedelta(days=7)), "end": None},
        "status": "created",
    }
    (d / "case.json").write_text(json.dumps(doc, indent=2))
    audit(d, "case", f"case {cid} created name={name!r} investigator={investigator!r} host={doc['host']}")
    return d


def load_case(case_dir: Path) -> dict:
    return json.loads((Path(case_dir) / "case.json").read_text())


def update_case(case_dir: Path, **fields) -> dict:
    doc = load_case(case_dir)
    for k, v in fields.items():
        if isinstance(v, dict) and isinstance(doc.get(k), dict):
            doc[k].update(v)
        else:
            doc[k] = v
    doc["updated_at"] = now_iso()
    (Path(case_dir) / "case.json").write_text(json.dumps(doc, indent=2))
    return doc


def list_cases(root: Path | None = None) -> list[dict]:
    root = Path(root or cases_root())
    out = []
    if not root.exists():
        return out
    for d in sorted(root.iterdir(), reverse=True):
        cj = d / "case.json"
        if cj.exists():
            try:
                out.append(json.loads(cj.read_text()))
            except json.JSONDecodeError:
                continue
    return out
