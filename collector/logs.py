"""Event logs and shell histories (US-004, FR-8)."""
from __future__ import annotations

import os
import platform
import subprocess
import tempfile
from pathlib import Path

from .base import Ctx

WINDOWS = platform.system() == "Windows"

WIN_CHANNELS = {
    "Security": "Security.evtx",
    "System": "System.evtx",
    "Microsoft-Windows-PowerShell/Operational": "PowerShell-Operational.evtx",
    "Microsoft-Windows-Sysmon/Operational": "Sysmon.evtx",
    "Microsoft-Windows-TaskScheduler/Operational": "TaskScheduler-Operational.evtx",
}

LINUX_LOGS = ["/var/log/auth.log", "/var/log/auth.log.1", "/var/log/secure", "/var/log/syslog",
              "/var/log/syslog.1", "/var/log/messages", "/var/log/kern.log"]


def homes() -> list[Path]:
    if WINDOWS:
        base = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
    else:
        base = Path("/home")
    out = [p for p in base.glob("*") if p.is_dir()] if base.exists() else []
    if not WINDOWS and Path("/root").exists():
        out.append(Path("/root"))
    return out


def collect(ctx: Ctx) -> None:
    if WINDOWS:
        for channel, fname in WIN_CHANNELS.items():
            # wevtutil export avoids touching the live, locked log file
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td) / fname
                r = subprocess.run(["wevtutil", "epl", channel, str(tmp)], capture_output=True, text=True)
                if r.returncode == 0 and tmp.exists():
                    ctx.copy("logs", tmp, f"raw/logs/{fname}")
                else:
                    ctx.log("logs", f"channel {channel} not exported ({r.stderr.strip()[:120] or 'not present'})", "WARN")
        for h in homes():
            hist = h / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
            if hist.exists():
                ctx.copy("logs", hist, f"raw/logs/ps_history_{h.name}.txt")
    else:
        for p in LINUX_LOGS:
            if Path(p).exists():
                ctx.copy("logs", Path(p), f"raw/logs/{Path(p).name}")
        for h in homes():
            for name in (".bash_history", ".zsh_history"):
                f = h / name
                if f.exists():
                    ctx.copy("logs", f, f"raw/logs/{name.lstrip('.')}_{h.name}")
        cron_files = [Path("/etc/crontab"), *Path("/etc/cron.d").glob("*"), *Path("/var/spool/cron/crontabs").glob("*")]
        for f in cron_files:
            if f.is_file():
                ctx.copy("logs", f, f"raw/logs/cron/{str(f).strip('/').replace('/', '_')}")
