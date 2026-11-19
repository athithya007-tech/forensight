"""Read-side queries over a case (shared by the API, report and chat)."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from analyzer.attack import TACTICS, technique
from core import db as dbm
from core import severity as sev
from core.case import load_case
from core.manifest import load as load_manifest


class CaseData:
    def __init__(self, case_dir: Path):
        self.dir = Path(case_dir)
        self.case = load_case(self.dir)
        self.id = self.case["id"]
        self.conn = dbm.connect(self.dir)

    def close(self):
        self.conn.close()

    def summary_file(self) -> dict:
        p = self.dir / "analysis/summary.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def findings(self) -> list[dict]:
        rows = [dbm.decode(r) for r in dbm.rows(self.conn, "SELECT * FROM findings WHERE case_id=? ORDER BY id", (self.id,))]
        hashes = self.hash_index()
        for r in rows:
            r["pre_existing"] = bool(r["pre_existing"])
            t = technique(r["attck_id"])
            r["technique"] = t["name"]
            r["evidence"] = [{"ref": ref, "path": ref.split("#")[0], "sha256": hashes.get(ref.split("#")[0])}
                             for ref in dict.fromkeys(r["evidence_refs"] or [])]
        return rows

    def events(self, severity=None, source=None, tactic=None, start=None, end=None, q=None, limit=5000, offset=0,
               include_raw=True) -> tuple[list[dict], int]:
        where, params = ["case_id=?"], [self.id]
        if severity:
            sevs = severity.split(",") if isinstance(severity, str) else severity
            where.append(f"severity IN ({','.join('?' * len(sevs))})")
            params += sevs
        if source:
            srcs = source.split(",") if isinstance(source, str) else source
            where.append(f"source IN ({','.join('?' * len(srcs))})")
            params += srcs
        if tactic:
            tacs = tactic.split(",") if isinstance(tactic, str) else tactic
            where.append(f"tactic IN ({','.join('?' * len(tacs))})")
            params += tacs
        if start:
            where.append("timestamp_utc >= ?")
            params.append(start)
        if end:
            where.append("timestamp_utc <= ?")
            params.append(end)
        if q:
            where.append("(description LIKE ? OR raw_json LIKE ? OR event_type LIKE ? OR attck_id LIKE ?)")
            params += [f"%{q}%"] * 4
        w = " AND ".join(where)
        total = self.conn.execute(f"SELECT COUNT(*) FROM events WHERE {w}", params).fetchone()[0]
        rows = dbm.rows(self.conn, f"SELECT * FROM events WHERE {w} ORDER BY timestamp_utc, id LIMIT ? OFFSET ?",
                        params + [limit, offset])
        hashes = self.hash_index()
        out = []
        for r in rows:
            r = dbm.decode(r)
            r["evidence_sha256"] = hashes.get(r["evidence_ref"].split("#")[0])
            if not include_raw:
                r.pop("raw_json", None)
            out.append(r)
        return out, total

    def hash_index(self) -> dict:
        if not hasattr(self, "_hashes"):
            self._hashes = {e["path"]: e["sha256"] for e in load_manifest(self.dir)["entries"]}
        return self._hashes

    def severity_counts(self, findings=None) -> dict:
        c = {s: 0 for s in sev.LEVELS}
        for f in findings if findings is not None else self.findings():
            c[f["severity"]] += 1
        return c

    def attack_matrix(self, findings=None) -> list[dict]:
        findings = findings if findings is not None else self.findings()
        by = defaultdict(lambda: defaultdict(list))
        for f in findings:
            if f["attck_id"]:
                by[f["tactic"]][f["attck_id"]].append(f)
        out = []
        for t in TACTICS:
            techs = [{"id": tid, "name": technique(tid)["name"], "count": len(fs),
                      "severity": sev.max_sev(*[f["severity"] for f in fs]), "finding_ids": [f["id"] for f in fs]}
                     for tid, fs in sorted(by.get(t, {}).items())]
            out.append({"tactic": t, "techniques": techs, "count": sum(x["count"] for x in techs)})
        return out

    def iocs(self) -> list[dict]:
        return dbm.rows(self.conn, "SELECT type,value,context,severity,first_seen FROM iocs WHERE case_id=? ORDER BY id", (self.id,))

    def graph(self) -> dict:
        nodes = [dbm.decode(r) for r in dbm.rows(self.conn, "SELECT id,type,value,label,severity,event_ids FROM entities WHERE case_id=?", (self.id,))]
        edges = dbm.rows(self.conn, "SELECT id,source_entity AS source,target_entity AS target,type,event_id,ts FROM edges WHERE case_id=? ORDER BY ts", (self.id,))
        return {"nodes": nodes, "edges": edges}

    def phases(self) -> list[dict]:
        return self.summary_file().get("phases", [])

    def exec_summary(self) -> str:
        s = self.summary_file()
        f = self.findings()
        host = self.case.get("host")
        if not f:
            return (f"ForenSight analysed {host} and found no suspicious activity. The verdict is Clean "
                    f"(score {s.get('score', 0)}/100). {s.get('events', 0)} events were reviewed.")
        parts = [f"ForenSight analysed {host} ({self.case.get('os')}) and rates it {s.get('verdict')} "
                 f"with a compromise score of {s.get('score')}/100, based on {len(f)} findings "
                 f"({', '.join(f'{n} {k}' for k, n in self.severity_counts(f).items() if n and k != 'Info')})."]
        if s.get("attack_start"):
            parts.append(f"Malicious activity spans {s['attack_start'][11:16]} to {s['attack_end'][11:16]} UTC on "
                         f"{s['attack_start'][:10]}, across {len(self.phases())} phase(s).")
        events = {e["id"]: e for e in self.events(include_raw=False)[0]}
        for ph in self.phases():
            pf = [x for x in f if any(events.get(i, {}).get("phase_index") == ph["index"] for i in x["event_ids"])]
            pf.sort(key=lambda x: (-sev.RANK[x["severity"]], x["first_seen"]))
            if pf:
                top = "; ".join(dict.fromkeys(x["title"] for x in pf[:3]))
                parts.append(f"{ph['label']} ({ph['start'][11:16]}–{ph['end'][11:16]} UTC): {top}.")
        ips = [i["value"] for i in self.iocs() if i["type"] == "ip"]
        if ips:
            parts.append(f"Activity is linked to {', '.join(ips[:3])}.")
        return " ".join(parts)

    def recommendations(self, findings=None) -> list[str]:
        recs = []
        for f in sorted(findings or self.findings(), key=lambda x: -sev.RANK[x["severity"]]):
            for p in f.get("playbook") or []:
                if p not in recs:
                    recs.append(p)
        return recs
