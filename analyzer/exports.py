"""Timeline (CSV/JSON, Timesketch-compatible) and IOC (CSV, STIX 2.1) exports (FR-24, FR-32)."""
from __future__ import annotations

import csv
import json
import uuid
from pathlib import Path

from core.timeutil import now_iso

from .attack import technique

NS = uuid.UUID("6f1c9a3e-2b7d-4c55-9a51-0f0b5e6d7c11")
TL_COLS = ["timestamp_utc", "host", "source", "event_type", "description", "severity", "attck_id", "tactic", "phase",
           "evidence_ref", "original_ts", "original_tz"]


def timeline_csv(events: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # Timesketch needs message, datetime, timestamp_desc
        w.writerow(["message", "datetime", "timestamp_desc"] + TL_COLS)
        for e in events:
            w.writerow([e["description"], e["timestamp_utc"], e["event_type"]] + [e.get(c) or "" for c in TL_COLS])


def timeline_json(events: list[dict], path: Path) -> None:
    rows = [{"message": e["description"], "datetime": e["timestamp_utc"], "timestamp_desc": e["event_type"],
             **{c: e.get(c) for c in TL_COLS}} for e in events]
    # JSONL is what Timesketch imports; a .json array is written alongside for humans/tools
    path.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    path.with_suffix(".jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def iocs_csv(iocs: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "severity", "first_seen", "context"])
        w.writeheader()
        for i in iocs:
            w.writerow({k: i.get(k) for k in w.fieldnames})


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def _pattern(i: dict) -> str | None:
    v = _esc(i["value"])
    return {
        "ip": f"[ipv4-addr:value = '{v}']" if ":" not in i["value"] else f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "user": f"[user-account:account_login = '{v}']",
        "file_path": f"[file:name = '{_esc(i['value'].replace(chr(92), '/').split('/')[-1])}']",
        "registry": f"[windows-registry-key:key = '{v}']",
        "scheduled_task": f"[process:command_line = '{v}']",
    }.get(i["type"])


def iocs_stix(case: dict, iocs: list[dict], findings: list[dict], path: Path) -> dict:
    created = now_iso()
    ident = {"type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid5(NS, 'forensight')}",
             "created": created, "modified": created, "name": "ForenSight", "identity_class": "system"}
    objs = [ident]
    for i in iocs:
        pat = _pattern(i)
        if not pat:
            continue
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(NS, case['id'] + i['type'] + i['value'])}",
            "created": created, "modified": created, "created_by_ref": ident["id"],
            "name": f"{i['type']}: {i['value']}"[:200], "description": i.get("context"),
            "indicator_types": ["malicious-activity"], "pattern": pat, "pattern_type": "stix",
            "valid_from": i.get("first_seen") or created,
            "labels": [i.get("severity", "Info").lower()],
        })
    seen = set()
    for f in findings:
        tid = f.get("attck_id")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        t = technique(tid)
        objs.append({"type": "attack-pattern", "spec_version": "2.1", "id": f"attack-pattern--{uuid.uuid5(NS, tid)}",
                     "created": created, "modified": created, "name": t["name"],
                     "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                              "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}]})
    report = {"type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(NS, case['id'])}",
              "created": created, "modified": created, "created_by_ref": ident["id"],
              "name": f"ForenSight incident report {case['id']}", "published": created,
              "report_types": ["incident"], "object_refs": [o["id"] for o in objs[1:]] or [ident["id"]]}
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS, case['id'] + created)}", "objects": objs + [report]}
    path.write_text(json.dumps(bundle, indent=1), encoding="utf-8")
    return bundle
