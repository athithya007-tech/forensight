"""Success metrics (PRD section 12): attack steps detected, timeline accuracy, technique coverage."""
from __future__ import annotations

import json
from pathlib import Path

from core import db as dbm
from core.timeutil import parse_ts

from .rules import load_rules
from .sigma import attack_id, load_sigma


def coverage() -> list[str]:
    ids = {r["attck_id"] for r in load_rules() if r.get("attck_id")}
    ids |= {t for t in (attack_id(s.get("tags")) for s in load_sigma()) if t}
    return sorted(ids)


def evaluate(case_dir: Path) -> dict:
    truth = json.loads((Path(case_dir) / "lab_truth.json").read_text())
    conn = dbm.connect(case_dir)
    findings = [dbm.decode(f) for f in dbm.rows(conn, "SELECT * FROM findings WHERE case_id=?", (Path(case_dir).name,))]
    techs = {}
    for f in findings:
        if f["attck_id"]:
            techs.setdefault(f["attck_id"].split(".")[0], []).append(f)
    steps = []
    for t in truth["truth"]:
        matched = [f for tid in t["techniques"] for f in techs.get(tid.split(".")[0], [])]
        delta = None
        if matched:
            truth_ts = parse_ts(t["ts"])
            delta = min(abs((parse_ts(f["first_seen"]) - truth_ts).total_seconds()) for f in matched)
            delta = min(delta, min(abs((parse_ts(f["last_seen"]) - truth_ts).total_seconds()) for f in matched))
        steps.append({"step": t["step"], "techniques": t["techniques"], "detected": bool(matched),
                      "closest_finding_delta_s": delta})
    detected = sum(s["detected"] for s in steps)
    return {"case": Path(case_dir).name, "steps_run": len(steps), "steps_detected": detected,
            "detection_rate": round(detected / len(steps), 3) if steps else None, "steps": steps,
            "findings": len(findings), "rule_technique_coverage": len(coverage())}
