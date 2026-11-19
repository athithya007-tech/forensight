"""RAM capture first (US-002, FR-5): WinPmem on Windows, AVML (fallback LiME) on Linux."""
from __future__ import annotations

import platform
import subprocess
import time
from pathlib import Path

import psutil

from core.paths import find_tool

from .base import Ctx

MODULE = "memory"


def _command(dest: Path) -> list[str] | None:
    system = platform.system()
    if system == "Windows":
        tool = find_tool("go-winpmem_amd64", "go-winpmem", "winpmem_mini_x64_rc2", "winpmem_mini_x64", "winpmem")
        if not tool:
            return None
        if "go-winpmem" in Path(tool).name:
            return [tool, "acquire", str(dest)]
        return [tool, str(dest)]
    if system == "Linux":
        tool = find_tool("avml")
        if tool:
            return [tool, str(dest)]
        lime = find_tool("lime.ko")
        if lime:
            return ["insmod", lime, f"path={dest}", "format=raw"]
    return None


def collect(ctx: Ctx) -> None:
    dest = ctx.case_dir / "raw" / "memory.raw"
    cmd = _command(dest)
    if not cmd:
        ctx.log(MODULE, "no RAM acquisition tool found (put winpmem/avml in tools/); skipping RAM capture", "WARN")
        ctx.emit(MODULE, "skipped", message="No winpmem/avml found in tools/ or PATH")
        return "skipped"
    total = psutil.virtual_memory().total
    ctx.log(MODULE, f"starting RAM capture: {' '.join(cmd)} (expected ~{total // 2**20} MB)")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    last = -1
    while proc.poll() is None:
        size = dest.stat().st_size if dest.exists() else 0
        mb = size // 2**20
        if mb != last:
            ctx.emit(MODULE, "running", pct=min(99.0, 100 * size / total), message=f"{mb} MB written")
            last = mb
        time.sleep(0.5)
    err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    if proc.returncode != 0 or not dest.exists() or dest.stat().st_size == 0:
        ctx.log(MODULE, f"RAM capture failed (exit {proc.returncode}): {err.strip()[:300]}", "ERROR")
        ctx.emit(MODULE, "failed", message="RAM capture failed; continuing with live collection")
        return "failed: RAM capture tool error (see audit.log)"
    ctx.register(MODULE, dest, pct=100)
