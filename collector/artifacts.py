"""Browser history, prefetch, persistence locations and suspicious files (US-004, US-008, FR-8)."""
from __future__ import annotations

import os
import platform
from datetime import datetime, timezone
from pathlib import Path

from core.manifest import sha256_file
from core.timeutil import iso, parse_ts

from .base import Ctx
from .logs import homes

WINDOWS = platform.system() == "Windows"
SUSPICIOUS_EXT = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".com", ".msi", ".jar",
                  ".sh", ".py", ".elf", ".bin", ".docm", ".xlsm"}
MAX_FILE = 25 * 2**20
MAX_FILES = 400


def browsers(ctx: Ctx) -> None:
    for h in homes():
        if WINDOWS:
            local = h / "AppData/Local"
            roaming = h / "AppData/Roaming"
            cands = list((local / "Google/Chrome/User Data").glob("*/History")) + \
                list((local / "Microsoft/Edge/User Data").glob("*/History")) + \
                list((roaming / "Mozilla/Firefox/Profiles").glob("*/places.sqlite"))
        else:
            cands = list((h / ".config/google-chrome").glob("*/History")) + \
                list((h / ".config/chromium").glob("*/History")) + \
                list((h / ".config/microsoft-edge").glob("*/History")) + \
                list((h / ".mozilla/firefox").glob("*/places.sqlite"))
        for c in cands:
            browser = "firefox" if "firefox" in str(c).lower() else ("edge" if "edge" in str(c).lower() else "chrome")
            ctx.copy("browser", c, f"raw/artifacts/browser/{h.name}_{browser}_{c.parent.name}_{c.name}")


def persistence(ctx: Ctx) -> None:
    run_keys, startup = [], []
    if WINDOWS:
        import winreg  # type: ignore
        locations = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, hname, path in locations:
            try:
                k = winreg.OpenKey(hive, path)
            except OSError:
                continue
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                run_keys.append({"key": f"{hname}\\{path}", "name": name, "value": str(value)})
                i += 1
        dirs = [Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"]
        dirs += [h / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" for h in homes()]
        prefetch = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
        for pf in sorted(prefetch.glob("*.pf"))[:1024] if prefetch.exists() else []:
            ctx.copy("persistence", pf, f"raw/artifacts/prefetch/{pf.name}")
    else:
        dirs = [Path("/etc/xdg/autostart")] + [h / ".config/autostart" for h in homes()]
        for unit in Path("/etc/systemd/system").glob("*.service"):
            if unit.is_file():
                ctx.copy("persistence", unit, f"raw/artifacts/systemd/{unit.name}")
                ctx.add_snapshot("services", unit.name, {"unit_file": str(unit)})
        for h in homes():
            ak = h / ".ssh/authorized_keys"
            if ak.exists():
                ctx.copy("persistence", ak, f"raw/artifacts/ssh/{h.name}_authorized_keys")
    for d in dirs:
        if d.exists():
            for f in d.iterdir():
                if f.is_file():
                    startup.append({"folder": str(d), "name": f.name, "path": str(f),
                                    "mtime": iso(datetime.fromtimestamp(f.stat().st_mtime, timezone.utc))})
    for r in run_keys:
        ctx.add_snapshot("run_keys", f"{r['key']}\\{r['name']}", {"value": r["value"]})
    for s in startup:
        ctx.add_snapshot("startup", s["path"], {"mtime": s["mtime"]})
    rel = ctx.live_dir.relative_to(ctx.case_dir).as_posix()
    ctx.write_json("persistence", f"{rel}/runkeys.json", run_keys)
    ctx.write_json("persistence", f"{rel}/startup.json", startup)


def _sweep_dirs() -> list[Path]:
    out = []
    for h in homes():
        if WINDOWS:
            out += [h / "AppData/Local/Temp", h / "Downloads", h / "AppData/Roaming", h / "Desktop"]
        else:
            out += [h / "Downloads", h / ".local/bin"]
    if WINDOWS:
        out += [Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"]
    else:
        out += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    return [p for p in out if p.exists()]


def files(ctx: Ctx) -> None:
    """Copy recently changed executables/scripts from Temp, Downloads, AppData for YARA + hash checks."""
    since = parse_ts(ctx.case.get("incident_window", {}).get("start"))
    index = []
    for base in _sweep_dirs():
        for root, dnames, fnames in os.walk(base):
            depth = Path(root).relative_to(base).parts
            if len(depth) > 4:
                dnames[:] = []
                continue
            for fn in fnames:
                if len(index) >= MAX_FILES:
                    break
                p = Path(root) / fn
                try:
                    st = p.stat()
                except OSError:
                    continue
                if not p.is_file() or st.st_size > MAX_FILE or st.st_size == 0:
                    continue
                execbit = (not WINDOWS) and os.access(p, os.X_OK)
                if p.suffix.lower() not in SUSPICIOUS_EXT and not execbit:
                    continue
                mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc)
                if since and mtime < since:
                    continue
                entry = ctx.copy("files", p, f"raw/artifacts/files/{len(index):04d}_{fn}")
                if entry:
                    index.append({"original_path": str(p), "copy": entry["path"], "sha256": entry["sha256"],
                                  "size": st.st_size, "mtime": iso(mtime)})
    ctx.write_json("files", "raw/artifacts/files_index.json", index)


def sha_only(path: Path) -> str:
    return sha256_file(path)
