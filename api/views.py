"""Derived views that are computed on request: process tree, network table, diff, evidence lookup."""
from __future__ import annotations

import json
from pathlib import Path

from analyzer.correlate import diff_snapshots
from analyzer.intel import Intel
from core import severity as sev

from .casedata import CaseData

PID_KEYS = ("pid", "NewProcessId", "ProcessId", "ProcessID")


def _int(v):
    try:
        return int(str(v), 16) if str(v).lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return None


def _jload(p: Path, default):
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def flagged_pids(cd: CaseData) -> dict[int, dict]:
    """pid -> {severity, reasons[], event_ids[]} from notable timeline events."""
    out: dict[int, dict] = {}
    events, _ = cd.events(limit=20000)
    for e in events:
        if e["severity"] == "Info":
            continue
        raw = e.get("raw_json") or {}
        pid = None
        for k in PID_KEYS:
            if raw.get(k) is not None:
                pid = _int(raw[k])
                if pid:
                    break
        if pid is None:
            continue
        f = out.setdefault(pid, {"severity": "Info", "reasons": [], "event_ids": []})
        f["severity"] = sev.max_sev(f["severity"], e["severity"])
        if e["description"][:120] not in f["reasons"]:
            f["reasons"].append(e["description"][:120])
        f["event_ids"].append(e["id"])
    return out


def processes(cd: CaseData) -> dict:
    live = _jload(cd.dir / "raw/live/processes.json", [])
    vdir = cd.dir / "analysis/volatility"
    pslist = _jload(vdir / "pslist.json", [])
    psscan = _jload(vdir / "psscan.json", [])
    cmd = {r.get("PID"): r.get("Args") for r in _jload(vdir / "cmdline.json", [])}
    hashes = cd.hash_index()
    procs: dict[int, dict] = {}
    for r in live:
        procs[r["pid"]] = {"pid": r["pid"], "ppid": r.get("ppid"), "name": r.get("name"), "path": r.get("path"), "cmdline": r.get("cmdline"),
                           "user": r.get("user"), "start_time": r.get("start_time"), "sha256": r.get("sha256"), "sources": ["live"],
                           "evidence_ref": f"raw/live/processes.json#pid={r['pid']}", "evidence_sha256": hashes.get("raw/live/processes.json")}
    listed = {r.get("PID") for r in pslist}
    for r in pslist + psscan:
        pid = r.get("PID")
        p = procs.get(pid)
        src = "pslist" if pid in listed else "psscan"
        if p is None:
            p = procs[pid] = {"pid": pid, "ppid": r.get("PPID"), "name": r.get("ImageFileName"), "path": None, "cmdline": cmd.get(pid),
                              "user": None, "start_time": r.get("CreateTime"), "sha256": None, "sources": [],
                              "evidence_ref": f"analysis/volatility/{src}.json#PID={pid}", "evidence_sha256": None}
        if src not in p["sources"]:
            p["sources"].append(src)
        if r.get("ExitTime"):
            p["exited"] = r["ExitTime"]
        if not p.get("cmdline") and cmd.get(pid):
            p["cmdline"] = cmd[pid]
    flags = flagged_pids(cd)
    for pid, p in procs.items():
        p["hidden"] = "psscan" in p["sources"] and "pslist" not in p["sources"] and "live" not in p["sources"] and not p.get("exited")
        f = flags.get(pid)
        p["flagged"] = bool(f) or p["hidden"]
        p["severity"] = f["severity"] if f else ("Critical" if p["hidden"] else "Info")
        p["reasons"] = (f or {}).get("reasons", []) + (["Hidden from pslist (DKOM?)"] if p["hidden"] else [])
        p["event_ids"] = (f or {}).get("event_ids", [])
        p["children"] = []
    roots = []
    for pid, p in sorted(procs.items(), key=lambda kv: kv[0] or 0):
        parent = procs.get(p.get("ppid"))
        if parent and parent is not p:
            parent["children"].append(p)
        else:
            roots.append(p)
    return {"roots": roots, "count": len(procs), "flagged": sum(p["flagged"] for p in procs.values())}


def network(cd: CaseData) -> list[dict]:
    live = _jload(cd.dir / "raw/live/netconns.json", [])
    vol = _jload(cd.dir / "analysis/volatility/netscan.json", [])
    intel = Intel(cd.dir, False, lambda *a, **k: None)
    rows: dict[tuple, dict] = {}
    for r in live:
        key = (r.get("laddr"), r.get("lport"), r.get("raddr"), r.get("rport"), r.get("pid"))
        rows[key] = {**r, "sources": ["live"], "evidence_ref": f"raw/live/netconns.json#pid={r.get('pid')}:{r.get('raddr')}:{r.get('rport')}"}
    for r in vol:
        ra = r.get("ForeignAddr")
        ra = None if ra in ("*", "0.0.0.0", "::") else ra
        key = (r.get("LocalAddr"), r.get("LocalPort"), ra, r.get("ForeignPort") if ra else None, r.get("PID"))
        if key in rows:
            rows[key]["sources"].append("memory")
            continue
        rows[key] = {"proto": (r.get("Proto") or "").lower(), "laddr": r.get("LocalAddr"), "lport": r.get("LocalPort"), "raddr": ra,
                     "rport": r.get("ForeignPort") if ra else None, "state": r.get("State"), "pid": r.get("PID"),
                     "process": r.get("Owner"), "created": r.get("Created"), "sources": ["memory"],
                     "evidence_ref": f"analysis/volatility/netscan.json#PID={r.get('PID')}:{ra}:{r.get('ForeignPort')}"}
    flagged = {}
    events, _ = cd.events(limit=20000)
    for e in events:
        raw = e.get("raw_json") or {}
        ra = raw.get("raddr") or raw.get("DestinationIp")
        if ra and e["severity"] != "Info":
            flagged[(ra, str(raw.get("rport") or raw.get("DestinationPort")))] = e
    out = []
    for r in rows.values():
        rep = intel.ip(r.get("raddr")) if r.get("raddr") else {"reputation": None}
        e = flagged.get((r.get("raddr"), str(r.get("rport"))))
        out.append({**r, "reputation": rep.get("reputation"), "reputation_source": rep.get("source"),
                    "severity": e["severity"] if e else "Info", "event_id": e["id"] if e else None})
    out.sort(key=lambda r: (-sev.RANK[r["severity"]], r.get("raddr") is None, str(r.get("raddr"))))
    return out


def diff(cd: CaseData, category: str | None = None) -> dict:
    base = _jload(cd.dir / "raw/baseline/snapshot.json", None)
    inc = _jload(cd.dir / "raw/live/snapshot.json", None)
    if not base or not inc:
        return {"available": False, "items": [], "categories": {},
                "message": "No baseline in this case. Run 'forensight collect --baseline' on the clean machine first."}
    items = diff_snapshots(base, inc)
    cats: dict[str, dict] = {}
    for i in items:
        c = cats.setdefault(i["category"], {"Added": 0, "Removed": 0, "Modified": 0})
        c[i["change"]] += 1
    if category:
        items = [i for i in items if i["category"] == category]
    return {"available": True, "baseline_taken": base.get("taken_at"), "incident_taken": inc.get("taken_at"),
            "categories": cats, "items": items}


def evidence_item(cd: CaseData, ref: str) -> dict:
    path = ref.split("#")[0]
    entry = next((e for e in __import__("core.manifest", fromlist=["load"]).load(cd.dir)["entries"] if e["path"] == path), None)
    ev = cd.conn.execute("SELECT * FROM events WHERE case_id=? AND evidence_ref=? LIMIT 1", (cd.id, ref)).fetchone()
    excerpt = None
    fp = cd.dir / path
    anchor = ref.split("#", 1)[1] if "#" in ref else None
    if fp.exists() and fp.is_file() and fp.stat().st_size < 30 * 2**20:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
            if anchor and anchor.startswith("EventRecordID="):
                rid = anchor.split("=", 1)[1]
                excerpt = next((l for l in text.splitlines() if f'"EventRecordID": {rid},' in l or f'"EventRecordID": "{rid}"' in l), None)
            elif anchor and anchor.startswith("L") and anchor[1:].isdigit():
                lines = text.splitlines()
                n = int(anchor[1:])
                excerpt = "\n".join(lines[max(0, n - 2):n + 1])
            else:
                excerpt = text[:1500]
        except Exception:  # noqa: BLE001
            excerpt = None
    from core import db as dbm
    return {"ref": ref, "path": path, "manifest": entry, "event": dbm.decode(dict(ev)) if ev else None, "excerpt": excerpt,
            "is_original_evidence": path.startswith("raw/")}
