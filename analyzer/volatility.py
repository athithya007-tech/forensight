"""Volatility 3 automation (US-006, FR-15, FR-16).

Runs the plugins against raw/memory.raw (opened read-only) and stores JSON in analysis/volatility/.
If Volatility is unavailable but cached JSON output exists there, the cached output is used
(PRD risk mitigation: pre-run analysis for the demo).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.paths import find_tool

WIN_PLUGINS = {
    "pslist": "windows.pslist.PsList", "pstree": "windows.pstree.PsTree", "psscan": "windows.psscan.PsScan",
    "netscan": "windows.netscan.NetScan", "cmdline": "windows.cmdline.CmdLine", "malfind": "windows.malfind.Malfind",
    "svcscan": "windows.svcscan.SvcScan",
}
LINUX_PLUGINS = {
    "pslist": "linux.pslist.PsList", "pstree": "linux.pstree.PsTree", "psscan": "linux.psscan.PsScan",
    "netscan": "linux.sockstat.Sockstat", "cmdline": "linux.psaux.PsAux", "malfind": "linux.malfind.Malfind",
}


def _vol_cmd() -> list[str] | None:
    tool = find_tool("vol", "vol.py", "volatility3")
    if tool:
        return [tool] if not tool.endswith(".py") else [sys.executable, tool]
    try:
        import volatility3  # noqa: F401
        return [sys.executable, "-m", "volatility3.cli"]
    except ImportError:
        return None


def run(case_dir: Path, os_name: str, log, emit=None) -> dict[str, list]:
    out_dir = case_dir / "analysis/volatility"
    out_dir.mkdir(parents=True, exist_ok=True)
    mem = case_dir / "raw/memory.raw"
    plugins = WIN_PLUGINS if (os_name or "Windows").lower().startswith("win") else LINUX_PLUGINS
    vol = _vol_cmd()
    if mem.exists() and vol:
        for i, (short, plugin) in enumerate(plugins.items()):
            if emit:
                emit("volatility", "running", pct=100 * i / len(plugins), message=plugin)
            try:
                r = subprocess.run(vol + ["-q", "-f", str(mem), "-r", "json", plugin], capture_output=True,
                                   text=True, timeout=1800)
                data = json.loads(r.stdout) if r.stdout.strip().startswith("[") else []
                (out_dir / f"{short}.json").write_text(json.dumps(data, indent=1))
                log(f"volatility {plugin}: {len(data)} rows")
            except Exception as e:  # noqa: BLE001
                log(f"volatility {plugin} failed: {e}", "ERROR")
    elif mem.exists():
        log("memory.raw present but Volatility 3 not installed (pip install volatility3); using cached output if any", "WARN")
    results = {}
    for short in plugins:
        p = out_dir / f"{short}.json"
        if p.exists():
            try:
                results[short] = json.loads(p.read_text())
            except json.JSONDecodeError:
                results[short] = []
    if results and not (mem.exists() and vol):
        log(f"using cached Volatility output: {', '.join(sorted(results))}")
    return results


def _flatten(rows: list) -> list[dict]:
    out = []
    for r in rows or []:
        children = r.get("__children") or []
        out.append({k: v for k, v in r.items() if k != "__children"})
        out.extend(_flatten(children))
    return out


def to_records(loader, vol: dict[str, list]) -> int:
    """Add process / netconn / malfind / hidden_process records from Volatility output."""
    n0 = len(loader.records)
    ref_base = "analysis/volatility/{}.json"
    pslist = _flatten(vol.get("pslist", []))
    psscan = _flatten(vol.get("psscan", []))
    cmd = {r.get("PID"): r.get("Args") for r in _flatten(vol.get("cmdline", []))}
    names = {r.get("PID"): r.get("ImageFileName") or r.get("COMM") for r in pslist + psscan}
    listed = {r.get("PID") for r in pslist}
    for r in pslist:
        pid = r.get("PID")
        f = {"pid": pid, "ppid": r.get("PPID"), "name": r.get("ImageFileName") or r.get("COMM"),
             "parent_name": names.get(r.get("PPID")), "cmdline": cmd.get(pid), "origin": "memory",
             "path": None, "user": None}
        loader.add("process", "volatility:pslist", r.get("CreateTime"), f, f"{ref_base.format('pslist')}#PID={pid}")
    for r in psscan:
        pid = r.get("PID")
        if pid not in listed and not r.get("ExitTime"):
            f = {"pid": pid, "ppid": r.get("PPID"), "name": r.get("ImageFileName") or r.get("COMM"),
                 "parent_name": names.get(r.get("PPID")), "cmdline": cmd.get(pid), "origin": "memory"}
            loader.add("hidden_process", "volatility:psscan", r.get("CreateTime"), f,
                       f"{ref_base.format('psscan')}#PID={pid}")
    for r in _flatten(vol.get("malfind", [])):
        pid = r.get("PID")
        f = {"pid": pid, "name": r.get("Process") or names.get(pid), "protection": r.get("Protection"),
             "tag": r.get("Tag"), "start": r.get("Start VPN"), "file_output": r.get("File output"),
             "private": r.get("PrivateMemory"), "hexdump": (r.get("Hexdump") or "")[:200]}
        loader.add("malfind", "volatility:malfind", loader.collected_at, f,
                   f"{ref_base.format('malfind')}#PID={pid}@{r.get('Start VPN')}")
    for r in _flatten(vol.get("netscan", [])):
        pid = r.get("PID") or r.get("Pid")
        f = {"proto": (r.get("Proto") or "").lower(), "laddr": r.get("LocalAddr") or r.get("Source Addr"),
             "lport": r.get("LocalPort") or r.get("Source Port"), "raddr": r.get("ForeignAddr") or r.get("Destination Addr"),
             "rport": r.get("ForeignPort") or r.get("Destination Port"), "state": r.get("State"), "pid": pid,
             "process": r.get("Owner") or names.get(pid), "origin": "memory"}
        if f["raddr"] in ("*", "0.0.0.0", "::", None):
            f["raddr"] = None
        loader.add("netconn", "volatility:netscan", r.get("Created") or loader.collected_at, f,
                   f"{ref_base.format('netscan')}#PID={pid}:{f['raddr']}:{f['rport']}")
    for r in _flatten(vol.get("svcscan", [])):
        f = {"name": r.get("Name"), "display": r.get("Display"), "binpath": r.get("Binary"), "state": r.get("State"),
             "start_type": r.get("Start"), "pid": r.get("PID"), "origin": "memory"}
        loader.add("service", "volatility:svcscan", loader.collected_at, f, f"{ref_base.format('svcscan')}#{r.get('Name')}")
    return len(loader.records) - n0
