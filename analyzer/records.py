"""Turn raw evidence (working copies) into normalized records the rule engine can match.

record = {ts, original_ts, original_tz, kind, source, host, fields{...}, evidence_ref}
"""
from __future__ import annotations

import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from core.timeutil import iso, parse_ts, to_iso

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class Loader:
    def __init__(self, case_dir: Path, work_dir: Path, case: dict, log):
        self.case_dir = case_dir
        self.work = work_dir          # analysis/work: copies of raw/ (FR-14)
        self.case = case
        self.host = case.get("host") or "unknown"
        self.tz = (case.get("host_info") or {}).get("timezone") or "UTC"
        self.collected_at = case.get("collected_at") or case.get("created_at")
        self.log = log
        self.records: list[dict] = []

    # -- helpers -----------------------------------------------------------
    def ref(self, work_path: Path, anchor: str | None = None) -> str:
        rel = "raw/" + work_path.relative_to(self.work).as_posix()
        return f"{rel}#{anchor}" if anchor else rel

    def add(self, kind: str, source: str, ts, fields: dict, evidence_ref: str, original_tz: str = "UTC",
            host: str | None = None) -> dict:
        dt = parse_ts(ts, None if original_tz == "UTC" else _iana(original_tz)) if ts else None
        rec = {
            "ts": iso(dt) if dt else to_iso(self.collected_at),
            "original_ts": str(ts) if ts is not None else None,
            "original_tz": original_tz,
            "kind": kind,
            "source": source,
            "host": host or self.host,
            "fields": fields,
            "evidence_ref": evidence_ref,
        }
        self.records.append(rec)
        return rec

    def jload(self, rel: str):
        p = self.work / rel
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            self.log(f"could not parse {rel}: {e}", "WARN")
            return None

    # -- Windows event logs ---------------------------------------------------
    def evtx(self) -> int:
        n0 = len(self.records)
        logs = self.work / "logs"
        if not logs.exists():
            return 0
        for p in sorted(logs.glob("*.evtx")):
            try:
                import Evtx.Evtx as evtx  # python-evtx
            except ImportError:
                self.log("python-evtx not installed; .evtx files skipped (pip install python-evtx)", "WARN")
                break
            try:
                with evtx.Evtx(str(p)) as log:
                    for rec in log.records():
                        try:
                            self._evtx_record(parse_evtx_xml(rec.xml()), p)
                        except Exception:  # noqa: BLE001 - skip corrupt records
                            continue
            except Exception as e:  # noqa: BLE001
                self.log(f"failed to parse {p.name}: {e}", "ERROR")
        # JSON-lines exports (one flattened event per line), e.g. from Get-WinEvent | ConvertTo-Json or the demo case
        for p in sorted(logs.glob("*.evtx.jsonl")):
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._evtx_record(json.loads(line), p)
        return len(self.records) - n0

    def _evtx_record(self, ev: dict, path: Path) -> None:
        fields = {"EventID": int(ev.get("EventID", 0)), "Channel": ev.get("Channel"), "Computer": ev.get("Computer"),
                  "EventRecordID": ev.get("EventRecordID"), "ProcessID": ev.get("ProcessID"), "Provider": ev.get("Provider")}
        fields.update(ev.get("Data") or {})
        _alias(fields)
        source = path.name.replace(".jsonl", "")
        self.add("evtx", source, ev.get("TimeCreated"), fields,
                 self.ref(path, f"EventRecordID={ev.get('EventRecordID')}").replace(".evtx.jsonl", ".evtx.jsonl"),
                 host=(ev.get("Computer") or self.host).split(".")[0])

    # -- live state -----------------------------------------------------------
    def live(self) -> int:
        n0 = len(self.records)
        for p in self.work.glob("live/processes.json"):
            for r in self.jload("live/processes.json") or []:
                self.add("process", "live:processes", r.get("start_time"), {**r, "origin": "live"},
                         self.ref(p, f"pid={r.get('pid')}"))
        p = self.work / "live/netconns.json"
        for r in self.jload("live/netconns.json") or []:
            self.add("netconn", "live:netconns", r.get("created") or self.collected_at, {**r, "origin": "live"},
                     self.ref(p, f"pid={r.get('pid')}:{r.get('raddr')}:{r.get('rport')}"))
        p = self.work / "live/runkeys.json"
        for r in self.jload("live/runkeys.json") or []:
            self.add("runkey", "registry:Run", r.get("last_write") or self.collected_at, r,
                     self.ref(p, f"{r.get('key')}\\{r.get('name')}"))
        p = self.work / "live/startup.json"
        for r in self.jload("live/startup.json") or []:
            self.add("startup", "startup-folder", r.get("mtime"), r, self.ref(p, r.get("name")))
        p = self.work / "live/tasks.json"
        for r in self.jload("live/tasks.json") or []:
            kind = "cron" if r.get("line") else "task"
            self.add(kind, "cron" if kind == "cron" else "scheduled-tasks", r.get("created") or r.get("mtime") or self.collected_at,
                     r, self.ref(p, r.get("name")))
        p = self.work / "live/services.json"
        for r in self.jload("live/services.json") or []:
            self.add("service", "live:services", self.collected_at, r, self.ref(p, r.get("name")))
        p = self.work / "artifacts/entropy.json"
        for r in self.jload("artifacts/entropy.json") or []:
            self.add("entropy", "file-entropy", r.get("mtime"), r, self.ref(p, r.get("path")))
        return len(self.records) - n0

    # -- Linux logs -----------------------------------------------------------
    SYSLOG = re.compile(r"^(?P<ts>(?:\w{3}\s+\d{1,2}\s[\d:]{8})|(?:\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?))\s+(?P<host>\S+)\s+(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
    FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)")
    ACCEPTED = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)")
    USERADD = re.compile(r"new user: name=(?P<user>[^,]+)")
    SUDO = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")

    def linux(self) -> int:
        n0 = len(self.records)
        logs = self.work / "logs"
        if not logs.exists():
            return 0
        year = (parse_ts(self.case.get("created_at")) or datetime.now()).year
        for p in sorted(list(logs.glob("auth.log*")) + list(logs.glob("secure*")) + list(logs.glob("syslog*"))):
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                m = self.SYSLOG.match(line)
                if not m:
                    continue
                raw_ts = m.group("ts")
                if raw_ts[0].isalpha():
                    tz = self.tz
                    ts = datetime.strptime(f"{year} {' '.join(raw_ts.split())}", "%Y %b %d %H:%M:%S").isoformat()
                else:
                    tz, ts = "UTC" if raw_ts.endswith("Z") or "+" in raw_ts[10:] or raw_ts.count("-") > 2 else self.tz, raw_ts
                msg = m.group("msg")
                fields = {"program": m.group("prog"), "pid": m.group("pid"), "message": msg, "line_no": i}
                for rx, result in ((self.FAILED, "failed"), (self.ACCEPTED, "accepted")):
                    mm = rx.search(msg)
                    if mm:
                        fields.update(mm.groupdict(), result=result)
                mm = self.USERADD.search(msg)
                if mm:
                    fields.update(user=mm.group("user").strip(), result="useradd")
                mm = self.SUDO.match(msg) if m.group("prog") == "sudo" else None
                if mm:
                    fields.update(user=mm.group("user"), command=mm.group("cmd"), result="sudo")
                self.add("auth", p.name, ts, fields, self.ref(p, f"L{i}"), original_tz=tz, host=m.group("host"))
        for p in sorted(logs.glob("*_history_*")) + sorted(logs.glob("bash_history_*")) + sorted(logs.glob("zsh_history_*")):
            user = p.name.split("_")[-1]
            ts = None
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if line.startswith("#") and line[1:].isdigit():   # HISTTIMEFORMAT epoch markers
                    ts = int(line[1:])
                    continue
                if line.strip():
                    self.add("shell", p.name, ts or self.collected_at, {"user": user, "command": line.strip(), "line_no": i},
                             self.ref(p, f"L{i}"))
                    ts = None
        cron_dir = logs / "cron"
        for p in sorted(cron_dir.glob("*")) if cron_dir.exists() else []:
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                s = line.strip()
                if s and not s.startswith("#") and not re.match(r"^\w+=", s):
                    mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=__import__("datetime").timezone.utc)
                    self.add("cron", "crontab", mtime, {"file": p.name, "line": s, "line_no": i, "user": _cron_user(p.name)},
                             self.ref(p, f"L{i}"))
        return len(self.records) - n0

    # -- browser downloads ----------------------------------------------------
    def browser(self) -> int:
        n0 = len(self.records)
        d = self.work / "artifacts/browser"
        if not d.exists():
            return 0
        for p in d.iterdir():
            try:
                con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
                if p.name.endswith("History"):
                    q = "SELECT target_path, tab_url, start_time FROM downloads"
                    for target, url, start in con.execute(q):
                        ts = (start / 1e6 - 11644473600) if start else None   # WebKit epoch
                        self.add("download", p.name, ts, {"path": target, "url": url, "browser": "chromium"},
                                 self.ref(p, f"download:{target}"))
                con.close()
            except sqlite3.Error:
                continue
        return len(self.records) - n0


def parse_evtx_xml(xml: str) -> dict:
    root = ET.fromstring(xml)
    sysn = root.find(f"{NS}System")
    out: dict = {"Data": {}}
    if sysn is not None:
        eid = sysn.find(f"{NS}EventID")
        out["EventID"] = int(eid.text) if eid is not None and eid.text else 0
        tc = sysn.find(f"{NS}TimeCreated")
        out["TimeCreated"] = tc.get("SystemTime") if tc is not None else None
        for tag in ("Channel", "Computer", "EventRecordID"):
            n = sysn.find(f"{NS}{tag}")
            out[tag] = n.text if n is not None else None
        prov = sysn.find(f"{NS}Provider")
        out["Provider"] = prov.get("Name") if prov is not None else None
        ex = sysn.find(f"{NS}Execution")
        if ex is not None:
            out["ProcessID"] = ex.get("ProcessID")
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for i, d in enumerate(ed):
            name = d.get("Name") or f"Data{i}"
            out["Data"][name] = d.text
    ud = root.find(f"{NS}UserData")
    if ud is not None:
        for el in ud.iter():
            if len(el) == 0 and el.text:
                out["Data"][el.tag.split("}")[-1]] = el.text
    return out


def _iana(tz: str) -> str | None:
    from zoneinfo import ZoneInfo
    try:
        ZoneInfo(tz)
        return tz
    except Exception:
        return None


def _hexint(v):
    try:
        return int(str(v), 16) if str(v).lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return v


def _alias(f: dict) -> None:
    """Give process / network events the same generic field names as live and memory records,
    so one rule can match all three evidence sources."""
    eid = f.get("EventID")
    base = lambda p: str(p).replace("/", "\\").split("\\")[-1] if p else None  # noqa: E731
    if eid == 4688:      # Security process creation
        f.setdefault("pid", _hexint(f.get("NewProcessId")))
        f.setdefault("ppid", _hexint(f.get("ProcessId")))
        f.setdefault("name", base(f.get("NewProcessName")))
        f.setdefault("parent_name", base(f.get("ParentProcessName")))
        f.setdefault("cmdline", f.get("CommandLine"))
        f.setdefault("path", f.get("NewProcessName"))
        f.setdefault("user", f.get("SubjectUserName"))
    elif eid == 1 and "Image" in f:   # Sysmon process creation
        f.setdefault("pid", _hexint(f.get("ProcessId")))
        f.setdefault("ppid", _hexint(f.get("ParentProcessId")))
        f.setdefault("name", base(f.get("Image")))
        f.setdefault("parent_name", base(f.get("ParentImage")))
        f.setdefault("cmdline", f.get("CommandLine"))
        f.setdefault("path", f.get("Image"))
        f.setdefault("user", f.get("User"))
    elif eid == 3 and "DestinationIp" in f:   # Sysmon network connection
        f.setdefault("pid", _hexint(f.get("ProcessId")))
        f.setdefault("process", base(f.get("Image")))
        f.setdefault("raddr", f.get("DestinationIp"))
        f.setdefault("rport", f.get("DestinationPort"))
        f.setdefault("laddr", f.get("SourceIp"))
        f.setdefault("lport", f.get("SourcePort"))


def _cron_user(name: str) -> str:
    return name.split("_")[-1] if "crontabs" in name else "root"
