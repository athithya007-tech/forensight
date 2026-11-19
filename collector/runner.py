"""Collection orchestrator: order of volatility (RFC 3227, FR-4), failure isolation, baseline mode."""
from __future__ import annotations

import time
import traceback
from pathlib import Path
from typing import Callable

from core import progress
from core.case import load_case, update_case
from core.manifest import sign_manifest
from core.timeutil import now_iso

from . import artifacts, live, logs, memory
from .base import Ctx

# (module name, function) in order of volatility
MODULES: list[tuple[str, Callable]] = [
    ("memory", memory.collect),
    ("network", live.network),
    ("processes", live.processes),
    ("users", live.users),
    ("services", live.services),
    ("tasks", live.tasks),
    ("logs", logs.collect),
    ("browser", artifacts.browsers),
    ("persistence", artifacts.persistence),
    ("programs", live.programs),
    ("files", artifacts.files),
]

PROFILES = {
    "full": [m for m, _ in MODULES],
    "quick": [m for m, _ in MODULES if m not in ("memory", "files", "programs")],
    "baseline": ["network", "users", "services", "tasks", "persistence", "programs"],
}


def run(case_dir: Path, profile: str = "full", modules: list[str] | None = None, baseline: bool = False,
        listener: Callable[[dict], None] | None = None) -> dict:
    case_dir = Path(case_dir)
    case = load_case(case_dir)
    if baseline:
        selected = PROFILES["baseline"]
    elif profile == "custom":
        selected = [m for m, _ in MODULES if m in (modules or [])]
        if not selected:
            raise ValueError(f"--profile custom needs --modules from: {', '.join(m for m, _ in MODULES)}")
    else:
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile {profile!r}; use quick, full or custom")
        selected = PROFILES[profile]
    progress.reset(case_dir)
    ctx = Ctx(case_dir, case, listener, baseline=baseline)
    ctx.log("collect", f"collection started profile={'baseline' if baseline else profile} modules={selected}")
    update_case(case_dir, status="collecting")
    ctx.emit("collect", "start", pct=0, message=f"{len(selected)} modules")
    t0 = time.time()
    results = {}
    for i, (name, fn) in enumerate([(m, f) for m, f in MODULES if m in selected]):
        ctx.emit(name, "running", pct=100 * i / len(selected))
        started = time.time()
        try:
            outcome = fn(ctx)
            results[name] = outcome if isinstance(outcome, str) else "ok"
            if results[name] == "ok":
                ctx.emit(name, "done", pct=100 * (i + 1) / len(selected))
            ctx.log(name, f"module finished in {time.time() - started:.1f}s")
        except Exception as e:  # noqa: BLE001  — one failing module never stops collection
            results[name] = f"failed: {e}"
            ctx.log(name, f"module failed: {e}\n{traceback.format_exc(limit=3)}", "ERROR")
            ctx.emit(name, "failed", pct=100 * (i + 1) / len(selected), message=str(e)[:200])
    snap_name = "raw/baseline/snapshot.json" if baseline else "raw/live/snapshot.json"
    ctx.write_json("baseline" if baseline else "snapshot", snap_name,
                   {"snapshot": "baseline" if baseline else "incident", "taken_at": now_iso(), "items": ctx.snapshot})
    sign_manifest(case_dir)
    elapsed = time.time() - t0
    update_case(case_dir, status="collected", collected_at=now_iso(), collection={
        "profile": "baseline" if baseline else profile, "modules": results, "artifacts": ctx.count,
        "bytes": ctx.bytes, "seconds": round(elapsed, 1)})
    ctx.log("collect", f"collection finished: {ctx.count} artifacts, {ctx.bytes} bytes in {elapsed:.1f}s")
    ctx.emit("collect", "complete", pct=100, message=f"{ctx.count} artifacts hashed in {elapsed:.0f}s")
    return {"modules": results, "artifacts": ctx.count, "bytes": ctx.bytes, "seconds": elapsed}
