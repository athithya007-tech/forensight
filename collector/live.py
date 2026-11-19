"""Live system state (US-003, FR-6, FR-7): network, processes, users, services, tasks."""
from __future__ import annotations

import csv
import io
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path

import psutil

from core.manifest import sha256_file
from core.timeutil import iso

from .base import Ctx, run_cmd

WINDOWS = platform.system() == "Windows"
_hash_cache: dict[str, str | None] = {}


def _exe_hash(path: str | None) -> str | None:
    if not path:
        return None
    if path in _hash_cache:
        return _hash_cache[path]
    try:
        h = sha256_file(Path(path)) if os.path.getsize(path) < 200 * 2**20 else None
    except OSError:
        h = None
    _hash_cache[path] = h
    return h


def network(ctx: Ctx) -> None:
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []
        ctx.log("network", "net_connections needs admin/root; partial results", "WARN")
    names = {}
    for c in conns:
        if c.pid and c.pid not in names:
            try:
                names[c.pid] = psutil.Process(c.pid).name()
            except Exception:
                names[c.pid] = None
        rows.append({
            "proto": "tcp" if c.type == 1 else "udp",
            "laddr": c.laddr.ip if c.laddr else None,
            "lport": c.laddr.port if c.laddr else None,
            "raddr": c.raddr.ip if c.raddr else None,
            "rport": c.raddr.port if c.raddr else None,
            "state": c.status,
            "pid": c.pid,
            "process": names.get(c.pid),
        })
        if c.status == "LISTEN" and c.laddr:
            ctx.add_snapshot("ports", f"{c.laddr.port}/{'tcp' if c.type == 1 else 'udp'}", {"addr": c.laddr.ip, "process": names.get(c.pid)})
    ctx.write_json("network", f"{ctx.live_dir.relative_to(ctx.case_dir).as_posix()}/netconns.json", rows)


def processes(ctx: Ctx) -> None:
    procs = {}
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
        i = p.info
        procs[i["pid"]] = i
    rows = []
    for pid, i in procs.items():
        parent = procs.get(i.get("ppid"))
        rows.append({
            "pid": pid,
            "ppid": i.get("ppid"),
            "name": i.get("name"),
            "parent_name": parent.get("name") if parent else None,
            "path": i.get("exe"),
            "cmdline": " ".join(i.get("cmdline") or []) or None,
            "user": i.get("username"),
            "start_time": iso(datetime.fromtimestamp(i["create_time"], timezone.utc)) if i.get("create_time") else None,
            "sha256": _exe_hash(i.get("exe")),
        })
    ctx.write_json("processes", f"{ctx.live_dir.relative_to(ctx.case_dir).as_posix()}/processes.json", rows)


def users(ctx: Ctx) -> None:
    logged = [{"name": u.name, "terminal": u.terminal, "host": u.host,
               "started": iso(datetime.fromtimestamp(u.started, timezone.utc))} for u in psutil.users()]
    accounts, admins = [], []
    if WINDOWS:
        out = run_cmd(["powershell", "-NoProfile", "-Command",
                       "Get-LocalUser | Select Name,Enabled,LastLogon,PasswordLastSet,SID | ConvertTo-Json -Compress"])
        try:
            data = json.loads(out) if out.strip() else []
            accounts = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
        out = run_cmd(["powershell", "-NoProfile", "-Command",
                       "Get-LocalGroupMember -SID S-1-5-32-544 | Select Name,ObjectClass | ConvertTo-Json -Compress"])
        try:
            data = json.loads(out) if out.strip() else []
            admins = [d.get("Name") for d in (data if isinstance(data, list) else [data])]
        except json.JSONDecodeError:
            pass
    else:
        try:
            for line in Path("/etc/passwd").read_text().splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    uid = int(parts[2])
                    if uid == 0 or uid >= 1000 and not parts[6].endswith(("nologin", "false")):
                        accounts.append({"Name": parts[0], "uid": uid, "home": parts[5], "shell": parts[6]})
        except OSError:
            pass
        try:
            for line in Path("/etc/group").read_text().splitlines():
                parts = line.split(":")
                if parts[0] in ("sudo", "wheel", "admin") and len(parts) >= 4 and parts[3]:
                    admins.extend(parts[3].split(","))
        except OSError:
            pass
    for a in accounts:
        ctx.add_snapshot("users", str(a.get("Name")), {k: a.get(k) for k in ("Enabled", "uid", "shell") if k in a})
    for m in admins:
        ctx.add_snapshot("groups", f"Administrators:{m}", {"group": "Administrators", "member": m})
    ctx.write_json("users", f"{ctx.live_dir.relative_to(ctx.case_dir).as_posix()}/users.json",
                   {"logged_in": logged, "accounts": accounts, "admins": admins})


def services(ctx: Ctx) -> None:
    rows = []
    if WINDOWS:
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
            except Exception:
                continue
            rows.append({"name": d.get("name"), "display": d.get("display_name"), "binpath": d.get("binpath"),
                         "start_type": d.get("start_type"), "status": d.get("status"), "user": d.get("username")})
    else:
        out = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"])
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                rows.append({"name": parts[0], "load": parts[1], "status": parts[3],
                             "display": parts[4] if len(parts) > 4 else ""})
    for r in rows:
        ctx.add_snapshot("services", r["name"], {"binpath": r.get("binpath"), "start_type": r.get("start_type")})
    ctx.write_json("services", f"{ctx.live_dir.relative_to(ctx.case_dir).as_posix()}/services.json", rows)


def tasks(ctx: Ctx) -> None:
    rows = []
    if WINDOWS:
        out = run_cmd(["schtasks", "/query", "/fo", "csv", "/v"], timeout=120)
        seen = set()
        for r in csv.DictReader(io.StringIO(out)):
            name = r.get("TaskName")
            if not name or name == "TaskName" or name in seen:
                continue
            seen.add(name)
            rows.append({"name": name, "action": r.get("Task To Run"), "author": r.get("Author"),
                         "run_as": r.get("Run As User"), "next_run": r.get("Next Run Time"),
                         "status": r.get("Status"), "schedule": r.get("Schedule Type")})
    else:
        for f in [Path("/etc/crontab"), *Path("/etc/cron.d").glob("*"), *Path("/var/spool/cron/crontabs").glob("*"),
                  *Path("/var/spool/cron").glob("*")]:
            try:
                if not f.is_file():
                    continue
                mtime = iso(datetime.fromtimestamp(f.stat().st_mtime, timezone.utc))
                for line in f.read_text(errors="replace").splitlines():
                    s = line.strip()
                    if s and not s.startswith("#") and not s.split("=")[0].isidentifier():
                        rows.append({"name": f"{f}:{s[:60]}", "file": str(f), "line": s, "mtime": mtime,
                                     "user": f.name if "spool" in str(f) else "root"})
            except OSError:
                continue
    for r in rows:
        ctx.add_snapshot("tasks", r["name"], {"action": r.get("action") or r.get("line")})
    ctx.write_json("tasks", f"{ctx.live_dir.relative_to(ctx.case_dir).as_posix()}/tasks.json", rows)


def programs(ctx: Ctx) -> None:
    rows = []
    if WINDOWS:
        import winreg  # type: ignore
        for hive, path in [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                           (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                           (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")]:
            try:
                k = winreg.OpenKey(hive, path)
            except OSError:
                continue
            for i in range(winreg.QueryInfoKey(k)[0]):
                try:
                    sk = winreg.OpenKey(k, winreg.EnumKey(k, i))
                    name = winreg.QueryValueEx(sk, "DisplayName")[0]
                    try:
                        ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                    except OSError:
                        ver = None
                    rows.append({"name": name, "version": ver})
                except OSError:
                    continue
    else:
        out = run_cmd(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"])
        rows = [{"name": l.split("\t")[0], "version": l.split("\t")[1]} for l in out.splitlines() if "\t" in l]
    for r in rows:
        ctx.add_snapshot("programs", r["name"], {"version": r.get("version")})
    ctx.write_json("programs", f"{ctx.live_dir.relative_to(ctx.case_dir).as_posix()}/programs.json", rows)
