"""`forensight analyze`: the full analysis pipeline. Works on copies of raw evidence (FR-14)."""
from __future__ import annotations

import json
import shutil
import time
from datetime import timedelta
from pathlib import Path
from typing import Callable

from core import db as dbm
from core import progress
from core import severity as sev
from core.audit import audit
from core.case import load_case, update_case
from core.manifest import load as load_manifest
from core.timeutil import now_iso, parse_ts

from . import correlate, exports, files, rules, sigma, volatility
from .attack import technique
from .intel import Intel
from .records import Loader


def _work_copy(case_dir: Path) -> Path:
    """Copy raw/ (except the RAM image, which Volatility opens read-only) to analysis/work/."""
    work = case_dir / "analysis/work"
    if work.exists():
        shutil.rmtree(work, onerror=lambda f, p, e: (Path(p).chmod(0o700), f(p)))
    raw = case_dir / "raw"
    for p in raw.rglob("*"):
        if p.is_file() and p.name != "memory.raw":
            dest = work / p.relative_to(raw)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
            dest.chmod(0o644)
    return work


def run(case_dir: Path, online: bool = False, listener: Callable[[dict], None] | None = None) -> dict:
    case_dir = Path(case_dir)
    case = load_case(case_dir)
    t0 = time.time()

    def log(msg, level="INFO"):
        audit(case_dir, "analyze", msg, level)

    def emit(module, status, **kw):
        ev = progress.emit(case_dir, f"analyze:{module}", status, **kw)
        if listener:
            listener(ev)

    log(f"analysis started online={online}")
    emit("prepare", "running", pct=0, message="copying evidence to analysis/work")
    work = _work_copy(case_dir)
    loader = Loader(case_dir, work, case, log)
    intel = Intel(case_dir, online, log)

    counts = {}
    emit("logs", "running", pct=10)
    counts["evtx"] = loader.evtx()
    counts["linux"] = loader.linux()
    emit("live", "running", pct=25)
    counts["live"] = loader.live()
    counts["browser"] = loader.browser()
    emit("memory", "running", pct=35)
    vol = volatility.run(case_dir, case.get("os"), log, emit)
    counts["memory"] = volatility.to_records(loader, vol)
    emit("intel", "running", pct=50)
    for r in loader.records:
        if r["fields"].get("raddr"):
            rep = intel.ip(r["fields"]["raddr"])
            r["fields"]["reputation"] = rep.get("reputation")
            r["fields"]["reputation_source"] = rep.get("source")
    emit("files", "running", pct=55)
    counts["files"] = files.scan(loader, intel, log)
    intel.save()
    base_snap = _load_json(case_dir / "raw/baseline/snapshot.json")
    inc_snap = _load_json(case_dir / "raw/live/snapshot.json")
    if base_snap and inc_snap:
        for d in correlate.diff_snapshots(base_snap, inc_snap):
            loader.add("diff", "baseline-diff", inc_snap.get("taken_at"), {**d, "after": json.dumps(d["after"], default=str)},
                       f"raw/live/snapshot.json#{d['category']}:{d['key']}")
    records = loader.records
    log(f"records loaded: {counts} total={len(records)}")

    # ---- detection ----------------------------------------------------------
    emit("rules", "running", pct=65)
    win = case.get("incident_window") or {}
    window = (parse_ts(win.get("start")), parse_ts(win.get("end")) or (parse_ts(case.get("collected_at")) or None))
    if window[1]:
        window = (window[0], window[1] + timedelta(hours=1))
    hits, context_hits = [], []
    custom = rules.load_rules()
    for rule in custom:
        try:
            res = rules.evaluate(rule, records, window)
        except Exception as e:  # noqa: BLE001
            log(f"rule {rule.get('id')} failed: {e}", "ERROR")
            continue
        (context_hits if rule.get("context") else hits).extend(res)
    # Sigma
    chainsaw = sigma.run_chainsaw(case_dir, work, log)
    sigma_rules = sigma.load_sigma()
    if chainsaw is not None:
        hits.extend(_chainsaw_hits(chainsaw, records, loader))
    else:
        for sr in sigma_rules:
            meta = sigma.to_rule(sr)
            try:
                for rec in sigma.evaluate_native(sr, records):
                    detail = rec["fields"].get("cmdline") or rec["fields"].get("ScriptBlockText") or ""
                    hits.append({"rule": meta, "records": [rec], "key_record": rec, "severity": meta["severity"],
                                 "description": f"Sigma: {meta['title']}" + (f" - {str(detail)[:160]}" if detail else "")})
            except Exception as e:  # noqa: BLE001
                log(f"sigma rule {sr.get('title')} failed: {e}", "WARN")
    hits = _apply_fallbacks(_dedupe(hits))
    log(f"detections: {len(hits)} hits from {len(custom)} custom + {len(sigma_rules)} sigma rules")

    # baseline: findings already present before the incident are marked pre-existing and lowered (US-015)
    for h in hits:
        h["pre_existing"] = False
        h["original_severity"] = h["severity"]
        b = h["rule"].get("baseline")
        if base_snap and b:
            key = rules.describe(b.get("key"), h["key_record"]["fields"]).lower()
            items = {k.lower() for k in base_snap.get("items", {}).get(b.get("category"), {})}
            if key in items:
                h["pre_existing"] = True
                h["severity"] = sev.lower(h["severity"])

    # ---- correlation --------------------------------------------------------
    emit("correlate", "running", pct=80)
    events, index = correlate.build_events(hits, context_hits)
    phases = correlate.assign_phases(events)
    by_id = {e["id"]: e for e in events}
    findings = []
    for h in hits:
        r = h["rule"]
        ev_ids = sorted({index[k]["id"] for k in h.get("event_keys", []) if k in index})
        refs = [rec["evidence_ref"] for rec in h["records"]]
        times = [rec["ts"] for rec in h["records"]]
        t = technique(r.get("attck_id"))
        findings.append({
            "rule_id": r["id"], "title": r.get("title"), "description": h["description"], "severity": h["severity"],
            "original_severity": h["original_severity"], "confidence": float(r.get("confidence", 0.7)),
            "attck_id": r.get("attck_id"), "technique": t["name"], "tactic": t["tactic"],
            "playbook": r.get("playbook") or [], "event_ids": ev_ids, "evidence_refs": refs,
            "first_seen": min(times), "last_seen": max(times), "pre_existing": h["pre_existing"],
            "engine": r.get("_engine", "custom"), "rule_file": r.get("_file"),
        })
    findings.sort(key=lambda f: (-sev.RANK[f["severity"]], f["first_seen"]))
    for i, f in enumerate(findings, 1):
        f["id"] = i
    graph = correlate.build_graph(events, records)
    iocs = correlate.extract_iocs(findings, by_id)
    sev_counts = {s: 0 for s in sev.LEVELS}
    for f in findings:
        sev_counts[f["severity"]] += 1
    score = sev.score(sev_counts)
    verdict = sev.verdict(score)
    diff = correlate.diff_snapshots(base_snap, inc_snap) if base_snap and inc_snap else []

    # ---- persist ------------------------------------------------------------
    emit("store", "running", pct=90)
    conn = dbm.connect(case_dir)
    cid = case["id"]
    dbm.reset_analysis(conn, cid)
    conn.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?)",
                 (cid, case.get("name"), case.get("investigator"), case.get("host"), case.get("os"),
                  case.get("created_at"), score, verdict))
    for e in load_manifest(case_dir)["entries"]:
        conn.execute("INSERT INTO artifacts (case_id,path,size,sha256,prev_hash,entry_hash,collected_at,module) VALUES (?,?,?,?,?,?,?,?)",
                     (cid, e["path"], e["size"], e["sha256"], e["prev_hash"], e["entry_hash"], e["collected_at"], e["module"]))
    for e in events:
        raw = dict(e.get("raw") or {})
        if e.get("burst_refs"):
            raw["_burst_refs"] = e["burst_refs"]
        conn.execute("""INSERT INTO events (id,case_id,timestamp_utc,original_ts,original_tz,host,source,event_type,description,
                        severity,attck_id,tactic,phase,phase_index,evidence_ref,rule_ids,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (e["id"], cid, e["timestamp_utc"], e.get("original_ts"), e.get("original_tz"), e["host"], e["source"],
                      e["event_type"], e["description"], e["severity"], e["attck_id"], e.get("tactic"), e.get("phase"),
                      e.get("phase_index"), e["evidence_ref"], json.dumps(e["rule_ids"]), json.dumps(raw, default=str)))
    for f in findings:
        conn.execute("""INSERT INTO findings (id,case_id,rule_id,title,description,severity,original_severity,confidence,attck_id,
                        tactic,playbook,event_ids,evidence_refs,first_seen,last_seen,pre_existing,engine) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (f["id"], cid, f["rule_id"], f["title"], f["description"], f["severity"], f["original_severity"],
                      f["confidence"], f["attck_id"], f["tactic"], json.dumps(f["playbook"]), json.dumps(f["event_ids"]),
                      json.dumps(f["evidence_refs"]), f["first_seen"], f["last_seen"], int(f["pre_existing"]), f["engine"]))
    for n in graph.nodes.values():
        conn.execute("INSERT INTO entities (id,case_id,type,value,label,severity,event_ids) VALUES (?,?,?,?,?,?,?)",
                     (n["id"], cid, n["type"], n["value"], n["label"], n["severity"], json.dumps(n["event_ids"])))
    for ed in graph.edges:
        conn.execute("INSERT INTO edges (case_id,source_entity,target_entity,type,event_id,ts) VALUES (?,?,?,?,?,?)",
                     (cid, ed["source"], ed["target"], ed["type"], ed["event_id"], ed["ts"]))
    for snap_name, snap in (("baseline", base_snap), ("incident", inc_snap)):
        for cat, items in (snap or {}).get("items", {}).items():
            for k, v in items.items():
                conn.execute("INSERT INTO baseline_items (case_id,category,key,value_json,snapshot) VALUES (?,?,?,?,?)",
                             (cid, cat, k, json.dumps(v, default=str), snap_name))
    for i in iocs:
        conn.execute("INSERT INTO iocs (case_id,type,value,context,severity,first_seen) VALUES (?,?,?,?,?,?)",
                     (cid, i["type"], i["value"], i["context"], i["severity"], i["first_seen"]))
    conn.commit()
    conn.close()

    # ---- files ---------------------------------------------------------------
    adir = case_dir / "analysis"
    exports.timeline_csv(events, adir / "timeline.csv")
    exports.timeline_json(events, adir / "timeline.json")
    (adir / "findings.json").write_text(json.dumps(findings, indent=1))
    rdir = case_dir / "report"
    rdir.mkdir(exist_ok=True)
    exports.iocs_csv(iocs, rdir / "iocs.csv")
    exports.iocs_stix(case, iocs, findings, rdir / "iocs.stix.json")
    times = [e["timestamp_utc"] for e in events if e["severity"] != "Info"]
    summary = {
        "score": score, "verdict": verdict, "severity_counts": sev_counts, "findings": len(findings),
        "events": len(events), "records": len(records), "record_counts": counts, "phases": phases,
        "attack_start": min(times) if times else None, "attack_end": max(times) if times else None,
        "techniques": sorted({f["attck_id"] for f in findings if f["attck_id"]}),
        "diff_changes": len(diff), "analyzed_at": now_iso(), "seconds": round(time.time() - t0, 1),
        "engines": {"volatility": bool(vol), "chainsaw": chainsaw is not None, "sigma_rules": len(sigma_rules),
                    "custom_rules": len(custom), "online_intel": online},
    }
    (adir / "summary.json").write_text(json.dumps(summary, indent=1))
    shutil.rmtree(work, ignore_errors=True)
    update_case(case_dir, status="analyzed", score=score, verdict=verdict, analyzed_at=summary["analyzed_at"])
    log(f"analysis finished: {len(findings)} findings, {len(events)} timeline events, score={score} verdict={verdict} in {summary['seconds']}s")
    emit("done", "complete", pct=100, message=f"{len(findings)} findings · score {score} · {verdict}")
    try:
        from .alerts import notify_critical
        notify_critical(case, findings, log)
    except Exception as e:  # noqa: BLE001
        log(f"alerting failed: {e}", "WARN")
    return summary


def _load_json(p: Path):
    return json.loads(p.read_text()) if p.exists() else None


def _dedupe(hits: list[dict]) -> list[dict]:
    """Merge hits of the same rule that describe the same thing (e.g. a connection seen live and in memory)."""
    out, seen = [], {}
    for h in hits:
        tmpl = h["rule"].get("dedupe")
        if not tmpl:
            out.append(h)
            continue
        key = (h["rule"]["id"], rules.describe(tmpl, h["key_record"]["fields"]).lower())
        if key in seen:
            prev = seen[key]
            for r in h["records"]:
                if r not in prev["records"]:
                    prev["records"].append(r)
            continue
        seen[key] = h
        out.append(h)
    return out


def _apply_fallbacks(hits: list[dict]) -> list[dict]:
    """Drop fallback hits whose technique is already covered by a primary rule; keep one fallback rule per technique."""
    base = lambda t: (t or "").split(".")[0]  # noqa: E731
    primary = {base(h["rule"].get("attck_id")) for h in hits if not h["rule"].get("fallback")}
    chosen: dict[str, str] = {}
    out = []
    for h in hits:
        r = h["rule"]
        if not r.get("fallback"):
            out.append(h)
            continue
        t = base(r.get("attck_id"))
        if t in primary:
            continue
        if chosen.setdefault(t, r["id"]) != r["id"]:
            continue
        out.append(h)
    return out


def _chainsaw_hits(data: list, records: list[dict], loader) -> list[dict]:
    by_rid = {}
    for r in records:
        if r["kind"] == "evtx":
            by_rid[(str(r["fields"].get("EventRecordID")), str(r["fields"].get("Channel")).lower())] = r
    hits = []
    for d in data:
        name = d.get("name") or d.get("title") or "Sigma detection"
        meta = sigma.to_rule({"title": name, "id": d.get("id") or name, "level": d.get("level"), "tags": d.get("tags")})
        docs = d.get("documents") or ([d.get("document")] if d.get("document") else [])
        for doc in docs:
            sysd = (((doc or {}).get("data") or {}).get("Event") or {}).get("System") or {}
            key = (str(sysd.get("EventRecordID")), str(sysd.get("Channel")).lower())
            rec = by_rid.get(key)
            if not rec:
                rec = loader.add("evtx", "chainsaw", d.get("timestamp"), {"EventID": sysd.get("EventID"), "Channel": sysd.get("Channel")},
                                 f"raw/logs#EventRecordID={key[0]}")
            hits.append({"rule": meta, "records": [rec], "key_record": rec, "severity": meta["severity"],
                         "description": f"Sigma (Chainsaw): {name}"})
    return hits
