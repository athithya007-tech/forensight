"""Correlation engine: findings -> normalized UTC timeline -> phases -> ATT&CK -> entity graph -> IOCs -> score.
(US-009, US-010, US-015, US-016, FR-21..24, FR-33, FR-34, FR-36)"""
from __future__ import annotations

import json
import re
from datetime import timedelta

from core import severity as sev
from core.timeutil import parse_ts

from .attack import tactic_of
from .intel import is_public
from .rules import describe

PHASE_GAP = timedelta(minutes=10)
IGNORE_USERS = {"-", "", "system", "local service", "network service", "anonymous logon", "dwm-1", "umfd-0", "umfd-1"}


def _user(v) -> str | None:
    if not v:
        return None
    u = str(v).split("\\")[-1].split("@")[0].strip()
    if u.lower() in IGNORE_USERS or u.endswith("$"):
        return None
    return u


def build_events(hits: list[dict], context_hits: list[dict]) -> tuple[list[dict], dict]:
    """Merge rule hits into one event per evidence record. Returns (events, ref->event index)."""
    events: dict[str, dict] = {}

    def upsert(rec, severity, rule, description, event_type, attck, aggregate=False):
        key = rec["evidence_ref"] + ("#agg" if aggregate else "")
        ev = events.get(key)
        if ev is None:
            ev = {"timestamp_utc": rec["ts"], "original_ts": rec.get("original_ts"), "original_tz": rec.get("original_tz"),
                  "host": rec["host"], "source": rec["source"], "event_type": event_type, "description": description,
                  "severity": severity, "attck_id": attck, "evidence_ref": rec["evidence_ref"], "rule_ids": [],
                  "raw": rec["fields"], "kind": rec["kind"]}
            events[key] = ev
        elif sev.RANK[severity] > sev.RANK[ev["severity"]] or (ev["severity"] == "Info" and severity == "Info" and not ev["attck_id"]):
            ev.update(severity=severity, description=description, event_type=event_type, attck_id=attck or ev["attck_id"])
        if rule and rule not in ev["rule_ids"]:
            ev["rule_ids"].append(rule)
        return ev

    for h in context_hits:
        r = h["rule"]
        rec = h["key_record"]
        upsert(rec, "Info", None, h["description"], r.get("event_type", "context"), r.get("attck_id"))
    for h in hits:
        r = h["rule"]
        h["event_keys"] = []
        if h.get("burst") is not None and h.get("aggregate", True):
            b = h["burst"]
            agg = upsert(b[0], sev.lower(h["severity"]) if h.get("followed") else h["severity"], r["id"],
                         f"{len(b)} × {describe(r.get('burst_label') or r['title'], b[0]['fields'])} ({b[0]['ts'][11:19]}–{b[-1]['ts'][11:19]} UTC)",
                         r.get("burst_event_type", r.get("event_type", "detection") + "_attempts"), r.get("attck_id"),
                         aggregate=True)
            agg["burst_refs"] = [x["evidence_ref"] for x in b]
            h["event_keys"].append(b[0]["evidence_ref"] + "#agg")
            if h.get("followed"):
                upsert(h["followed"], h["severity"], r["id"], h["description"], r.get("event_type", "detection"), r.get("attck_id"))
                h["event_keys"].append(h["followed"]["evidence_ref"])
        else:
            for rec in h["records"]:
                upsert(rec, h["severity"], r["id"], h["description"], r.get("event_type", "detection"), r.get("attck_id"))
                h["event_keys"].append(rec["evidence_ref"])
    ordered = sorted(events.items(), key=lambda kv: (kv[1]["timestamp_utc"], kv[0]))
    out, index = [], {}
    for i, (k, ev) in enumerate(ordered, 1):
        ev["id"] = i
        ev["tactic"] = tactic_of(ev["attck_id"])
        index[k] = ev
        out.append(ev)
    return out, index


def assign_phases(events: list[dict]) -> list[dict]:
    """Group events within 10 minutes of each other into phases; name each by its most severe tactic (FR-23)."""
    phases, cur, last = [], [], None
    notable = [e for e in events if e["severity"] != "Info" or e["attck_id"]]
    for e in notable:
        t = parse_ts(e["timestamp_utc"])
        if last is not None and t - last > PHASE_GAP:
            phases.append(cur)
            cur = []
        cur.append(e)
        last = t
    if cur:
        phases.append(cur)
    summary = []
    for n, group in enumerate(phases, 1):
        top = max(group, key=lambda e: (sev.RANK[e["severity"]], bool(e["tactic"])))
        tactics = []
        for e in group:
            if e["tactic"] and e["tactic"] not in tactics:
                tactics.append(e["tactic"])
        label = f"Phase {n}: {top['tactic'] or 'Activity'}"
        for e in group:
            e["phase"] = label
            e["phase_index"] = n
        summary.append({"index": n, "label": label, "start": group[0]["timestamp_utc"], "end": group[-1]["timestamp_utc"],
                        "tactics": tactics, "events": len(group), "severity": sev.max_sev(*[e["severity"] for e in group])})
    # context events take the phase of the closest preceding notable event
    current = None
    for e in events:
        if e.get("phase"):
            current = (e["phase"], e["phase_index"])
        else:
            e["phase"], e["phase_index"] = current if current else ("Pre-incident", 0)
    return summary


# ---- entity graph (FR-34) -------------------------------------------------

def _pid_names(records: list[dict]) -> dict:
    names = {}
    for r in records:
        f = r["fields"]
        if r["kind"] in ("process", "hidden_process") and f.get("pid") is not None:
            names[str(f["pid"])] = f.get("name")
        if r["kind"] == "evtx" and f.get("EventID") in (1, 4688):
            pid = f.get("ProcessId") or f.get("NewProcessId")
            img = f.get("Image") or f.get("NewProcessName")
            if pid and img:
                names[str(_int(pid))] = _base(img)
    return names


def _int(v):
    try:
        return int(str(v), 16) if str(v).lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return v


def _base(path) -> str:
    return re.split(r"[\\/]", str(path))[-1] if path else ""


class Graph:
    def __init__(self, pid_names: dict):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.pid_names = pid_names
        self._seen = set()

    def node(self, typ: str, value, ev: dict, label: str | None = None) -> str | None:
        if value in (None, "", "-"):
            return None
        if typ == "file":
            value = str(value).strip('"').strip()
            label = label.strip('"') if label else label
        nid = f"{typ}:{str(value).lower() if typ not in ('process',) else value}"
        n = self.nodes.get(nid)
        if not n:
            n = self.nodes[nid] = {"id": nid, "type": typ, "value": str(value), "label": label or str(value),
                                   "severity": "Info", "event_ids": []}
        n["severity"] = sev.max_sev(n["severity"], ev["severity"])
        if ev["id"] not in n["event_ids"]:
            n["event_ids"].append(ev["id"])
        return nid

    def proc(self, pid, ev, name=None) -> str | None:
        if pid in (None, ""):
            return None
        pid = _int(pid)
        name = name or self.pid_names.get(str(pid)) or "process"
        return self.node("process", pid, ev, f"{_base(name)} ({pid})")

    def edge(self, a, b, typ, ev):
        if not a or not b or a == b:
            return
        key = (a, b, typ)
        if key in self._seen:
            return
        self._seen.add(key)
        self.edges.append({"source": a, "target": b, "type": typ, "event_id": ev["id"], "ts": ev["timestamp_utc"]})


def build_graph(events: list[dict], records: list[dict]) -> Graph:
    g = Graph(_pid_names(records))
    for ev in events:
        f = ev.get("raw") or {}
        k = ev.get("kind")
        eid = f.get("EventID")
        if k == "evtx":
            if eid in (4624, 4625):
                ipv = f.get("IpAddress")
                ipv = None if ipv in (None, "-", "127.0.0.1", "::1") else ipv
                u = _user(f.get("TargetUserName"))
                if ipv and u:
                    ip, un = g.node("ip", ipv, ev), g.node("user", u, ev)
                    if eid == 4624:
                        g.edge(ip, un, "logged_in_as", ev)
            elif eid in (4688, 1):
                parent = g.proc(f.get("ProcessId") if eid == 4688 else f.get("ParentProcessId"), ev,
                                f.get("ParentProcessName") or f.get("ParentImage"))
                child = g.proc(f.get("NewProcessId") if eid == 4688 else f.get("ProcessId"), ev,
                               f.get("NewProcessName") or f.get("Image"))
                user = g.node("user", _user(f.get("SubjectUserName") or f.get("User")), ev) if ev["severity"] != "Info" or not parent else None
                g.edge(parent, child, "spawned", ev)
                if user and not parent:
                    g.edge(user, child, "spawned", ev)
                elif user:
                    g.edge(user, parent, "spawned", ev)
            elif eid == 11:
                g.edge(g.proc(f.get("ProcessId"), ev, f.get("Image")), g.node("file", f.get("TargetFilename"), ev, _base(f.get("TargetFilename"))), "wrote", ev)
            elif eid == 3:
                g.edge(g.proc(f.get("ProcessId"), ev, f.get("Image")), g.node("ip", f.get("DestinationIp"), ev), "connected_to", ev)
            elif eid == 13:
                g.edge(g.proc(f.get("ProcessId"), ev, f.get("Image")), g.node("registry", f.get("TargetObject"), ev, _base(f.get("TargetObject"))), "persisted_via", ev)
            elif eid == 4720:
                g.edge(g.node("user", _user(f.get("SubjectUserName")), ev), g.node("user", _user(f.get("TargetUserName")), ev), "created", ev)
            elif eid == 4732:
                g.edge(g.node("user", _user(f.get("SubjectUserName")), ev), g.node("user", _user(f.get("MemberName") or f.get("TargetUserName_member") or f.get("MemberSid")), ev), "granted_admin", ev)
            elif eid == 7045:
                svc = g.node("service", f.get("ServiceName"), ev)
                g.edge(g.node("user", _user(f.get("AccountName") or f.get("SubjectUserName")), ev), svc, "created", ev)
                g.edge(svc, g.node("file", f.get("ImagePath"), ev, _base(f.get("ImagePath"))), "persisted_via", ev)
            elif eid in (4698, 106):
                g.edge(g.node("user", _user(f.get("SubjectUserName") or f.get("UserContext")), ev), g.node("task", f.get("TaskName"), ev), "persisted_via", ev)
            elif eid == 4104:
                p = g.proc(f.get("ProcessID"), ev, "powershell.exe")
                for url in re.findall(r"https?://([\w.-]+)", str(f.get("ScriptBlockText", ""))):
                    g.edge(p, g.node("ip", url, ev), "connected_to", ev)
            elif eid == 1102:
                g.node("user", _user(f.get("SubjectUserName")), ev)
            elif eid in (21, 25) and f.get("Address"):
                g.edge(g.node("ip", f.get("Address"), ev), g.node("user", _user(f.get("User")), ev), "logged_in_as", ev)
            elif eid == 140 and f.get("IPString"):
                g.node("ip", f.get("IPString"), ev)
        elif k == "netconn" and f.get("raddr"):
            g.edge(g.proc(f.get("pid"), ev, f.get("process")), g.node("ip", f.get("raddr"), ev), "connected_to", ev)
        elif k in ("process", "hidden_process", "malfind"):
            child = g.proc(f.get("pid"), ev, f.get("name"))
            if f.get("ppid") is not None and f.get("parent_name"):
                g.edge(g.proc(f.get("ppid"), ev, f.get("parent_name")), child, "spawned", ev)
        elif k == "runkey":
            reg = g.node("registry", f"{f.get('key')}\\{f.get('name')}", ev, f.get("name"))
            g.edge(g.node("user", _user(f.get("user")), ev), reg, "persisted_via", ev)
            exe = re.match(r'"?([^"]+?\.(?:exe|ps1|bat|vbs|dll|cmd))', str(f.get("value", "")), re.I)
            if exe:
                g.edge(reg, g.node("file", exe.group(1), ev, _base(exe.group(1))), "persisted_via", ev)
        elif k == "task":
            g.edge(g.node("user", _user(f.get("author") or f.get("run_as")), ev), g.node("task", f.get("name"), ev), "persisted_via", ev)
        elif k in ("yara", "hash_rep"):
            g.node("file", f.get("path"), ev, _base(f.get("path")))
        elif k == "auth":
            if f.get("result") in ("accepted", "failed") and f.get("ip"):
                ip = g.node("ip", f.get("ip"), ev)
                u = g.node("user", f.get("user"), ev)
                if f.get("result") == "accepted":
                    g.edge(ip, u, "logged_in_as", ev)
            elif f.get("result") == "useradd":
                g.node("user", f.get("user"), ev)
        elif k == "cron":
            g.edge(g.node("user", f.get("user"), ev), g.node("task", f.get("line") or f.get("name"), ev, (f.get("line") or "")[:40]), "persisted_via", ev)
        elif k == "shell":
            g.node("user", f.get("user"), ev)
        elif k == "diff" and f.get("category") in ("users", "groups"):
            g.node("user", _user(str(f.get("key")).split(":")[-1]), ev)
    # drop isolated Info-only nodes to keep the graph readable
    linked = {e["source"] for e in g.edges} | {e["target"] for e in g.edges}
    g.nodes = {k: v for k, v in g.nodes.items() if k in linked or v["severity"] != "Info"}
    return g


# ---- IOCs ----------------------------------------------------------------

IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RX = re.compile(r"https?://([a-z0-9.-]+\.[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(/[^\s'\"]*)?", re.I)


def extract_iocs(findings: list[dict], events_by_id: dict[int, dict]) -> list[dict]:
    iocs: dict[tuple, dict] = {}

    def add(t, v, ctx, s, ts):
        if not v or v in ("-", "?"):
            return
        k = (t, str(v).lower())
        cur = iocs.get(k)
        if not cur:
            iocs[k] = {"type": t, "value": str(v), "context": ctx, "severity": s, "first_seen": ts}
        else:
            cur["severity"] = sev.max_sev(cur["severity"], s)
            cur["first_seen"] = min(cur["first_seen"], ts)
    for fd in findings:
        for eid in fd["event_ids"]:
            ev = events_by_id.get(eid)
            if not ev:
                continue
            f = ev.get("raw") or {}
            s, ts, ctx = fd["severity"], ev["timestamp_utc"], fd["title"]
            for key in ("IpAddress", "raddr", "ip", "DestinationIp"):
                v = f.get(key)
                if v and IP_RX.fullmatch(str(v)) and v not in ("127.0.0.1", "0.0.0.0"):
                    add("ip", v, ctx, s, ts)
            text = " ".join(str(f.get(k, "")) for k in ("ScriptBlockText", "CommandLine", "cmdline", "command", "line", "url", "value"))
            for m in DOMAIN_RX.finditer(text):
                host = m.group(1)
                add("ip" if IP_RX.fullmatch(host) else "domain", host, ctx, s, ts)
                add("url", m.group(0), ctx, s, ts)
            for key in ("sha256", "Hashes"):
                v = f.get(key)
                if v:
                    m = re.search(r"[0-9a-fA-F]{64}", str(v))
                    if m:
                        add("sha256", m.group(0).lower(), ctx, s, ts)
            if ev["event_type"] in ("user_created", "admin_added", "brute_force_success", "logon_success", "ssh_brute_force_success", "linux_user_created"):
                add("user", _user(f.get("TargetUserName") or f.get("MemberName") or f.get("user")), ctx, s, ts)
            for key in ("path", "TargetFilename", "ImagePath"):
                if f.get(key):
                    add("file_path", f[key], ctx, s, ts)
            if ev["kind"] == "runkey":
                exe = re.match(r'"?([^"]+?\.(?:exe|ps1|bat|vbs|dll|cmd))', str(f.get("value", "")), re.I)
                if exe:
                    add("file_path", exe.group(1), ctx, s, ts)
                add("registry", f"{f.get('key')}\\{f.get('name')}", ctx, s, ts)
            if ev["kind"] == "task" or f.get("EventID") == 4698:
                add("scheduled_task", f.get("TaskName") or f.get("name"), ctx, s, ts)
    order = {"ip": 0, "domain": 1, "url": 2, "sha256": 3, "user": 4, "file_path": 5, "registry": 6, "scheduled_task": 7}
    return sorted(iocs.values(), key=lambda i: (order.get(i["type"], 9), -sev.RANK[i["severity"]], i["value"]))


# ---- baseline diff (US-015, FR-36) ---------------------------------------

def diff_snapshots(base: dict, inc: dict) -> list[dict]:
    out = []
    bi, ii = base.get("items", {}), inc.get("items", {})
    for cat in sorted(set(bi) | set(ii)):
        b, i = bi.get(cat, {}), ii.get(cat, {})
        for key in sorted(set(b) | set(i)):
            if key not in b:
                out.append({"category": cat, "key": key, "change": "Added", "before": None, "after": i[key]})
            elif key not in i:
                out.append({"category": cat, "key": key, "change": "Removed", "before": b[key], "after": None})
            elif json.dumps(b[key], sort_keys=True, default=str) != json.dumps(i[key], sort_keys=True, default=str):
                out.append({"category": cat, "key": key, "change": "Modified", "before": b[key], "after": i[key]})
    return out


def is_public_ip(ip) -> bool:
    return is_public(ip)
