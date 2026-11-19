"""Sigma support (FR-18): Chainsaw when its binary is present, otherwise a built-in evaluator
for the common subset of Sigma (selections with modifiers; and/or/not; 1 of / all of)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml

from core.paths import find_tool, rules_dir
from core.severity import normalize

LEVEL = {"informational": "Info", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
SERVICE_CHANNEL = {
    "security": "security", "system": "system", "powershell": "microsoft-windows-powershell/operational",
    "sysmon": "microsoft-windows-sysmon/operational", "taskscheduler": "microsoft-windows-taskscheduler/operational",
}
CATEGORY = {"process_creation": [("microsoft-windows-sysmon/operational", 1), ("security", 4688)],
            "ps_script": [("microsoft-windows-powershell/operational", 4104)],
            "network_connection": [("microsoft-windows-sysmon/operational", 3)],
            "file_event": [("microsoft-windows-sysmon/operational", 11)],
            "registry_set": [("microsoft-windows-sysmon/operational", 13)]}
FIELD_ALIASES = {"Image": ["Image", "NewProcessName"], "ParentImage": ["ParentImage", "ParentProcessName"],
                 "CommandLine": ["CommandLine", "ProcessCommandLine"]}


def attack_id(tags: list[str]) -> str | None:
    for t in tags or []:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", t, re.I)
        if m:
            return m.group(1).upper()
    return None


def load_sigma(base: Path | None = None) -> list[dict]:
    base = base or rules_dir() / "sigma"
    out = []
    for p in sorted(base.rglob("*.yml")) + sorted(base.rglob("*.yaml")):
        try:
            for doc in yaml.safe_load_all(p.read_text(encoding="utf-8")):
                if doc and "detection" in doc:
                    doc["_file"] = p.name
                    out.append(doc)
        except yaml.YAMLError:
            continue
    return out


def _field_values(fields: dict, name: str):
    for n in FIELD_ALIASES.get(name, [name]):
        for k, v in fields.items():
            if k.lower() == n.lower():
                yield v


def _match_value(actual, mods: list[str], expected) -> bool:
    if actual is None:
        return expected is None
    a = str(actual).lower()
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    if "base64offset" in mods or "base64" in mods:
        return False
    e = str(expected).lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return re.fullmatch(re.escape(e).replace(r"\*", ".*").replace(r"\?", "."), a, re.S) is not None
    return a == e


def _selection(fields: dict, sel) -> bool:
    if isinstance(sel, list):
        return any(_selection(fields, s) if isinstance(s, dict) else
                   any(str(s).lower() in str(v).lower() for v in fields.values()) for s in sel)
    for key, expected in sel.items():
        name, *mods = key.split("|")
        values = expected if isinstance(expected, list) else [expected]
        actuals = list(_field_values(fields, name))
        if not actuals:
            return False
        test = all if "all" in mods else any
        if not test(any(_match_value(a, mods, v) for a in actuals) for v in values):
            return False
    return True


def _condition(cond: str, results: dict[str, bool]) -> bool:
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|(?:1|all) of [\w*]+|all of them|1 of them|[\w*]+", cond)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def atom():
        t = take()
        if t == "(":
            v = expr()
            take()
            return v
        if t == "not":
            return not atom()
        m = re.match(r"(1|all) of (.+)", t)
        if m:
            pat = m.group(2)
            names = [n for n in results if pat == "them" or re.fullmatch(pat.replace("*", ".*"), n)]
            vals = [results[n] for n in names]
            return any(vals) if m.group(1) == "1" else (bool(vals) and all(vals))
        return results.get(t, False)

    def conj():
        v = atom()
        while peek() == "and":
            take()
            v = atom() and v
        return v

    def expr():
        v = conj()
        while peek() == "or":
            take()
            v = conj() or v
        return v

    return expr()


def evaluate_native(rule: dict, records: list[dict]) -> list[dict]:
    ls = rule.get("logsource") or {}
    det = dict(rule["detection"])
    cond = det.pop("condition", "selection")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    det.pop("timeframe", None)
    channels = None
    if ls.get("service") in SERVICE_CHANNEL:
        channels = [(SERVICE_CHANNEL[ls["service"]], None)]
    elif ls.get("category") in CATEGORY:
        channels = CATEGORY[ls["category"]]
    hits = []
    for r in records:
        if r["kind"] != "evtx":
            continue
        f = r["fields"]
        if channels and not any(str(f.get("Channel", "")).lower() == ch and (eid is None or f.get("EventID") == eid)
                                for ch, eid in channels):
            continue
        res = {name: _selection(f, sel) for name, sel in det.items()}
        if _condition(cond, res):
            hits.append(r)
    return hits


def run_chainsaw(case_dir: Path, work: Path, log) -> list[dict] | None:
    tool = find_tool("chainsaw")
    if not tool:
        return None
    mapping = next(iter(Path(tool).parent.rglob("sigma-event-logs-all.yml")), None)
    if not mapping:
        log("chainsaw found but mappings/sigma-event-logs-all.yml missing; using built-in Sigma engine", "WARN")
        return None
    out = case_dir / "analysis/chainsaw.json"
    try:
        subprocess.run([tool, "hunt", str(work / "logs"), "-s", str(rules_dir() / "sigma"), "--mapping", str(mapping),
                        "--json", "-o", str(out), "-q"], capture_output=True, timeout=1800, check=False)
        data = json.loads(out.read_text()) if out.exists() else []
        log(f"chainsaw: {len(data)} detections")
        return data
    except Exception as e:  # noqa: BLE001
        log(f"chainsaw failed: {e}; using built-in Sigma engine", "WARN")
        return None


def to_rule(sig: dict) -> dict:
    """Convert a Sigma rule's metadata to ForenSight rule metadata."""
    tags = sig.get("tags") or []
    return {"id": f"SIGMA-{(sig.get('id') or sig.get('title'))[:36]}", "title": sig.get("title"),
            "attck_id": attack_id(tags), "severity": normalize(LEVEL.get(str(sig.get("level", "medium")).lower(), "Medium")),
            "confidence": 0.75, "event_type": "sigma_" + re.sub(r"\W+", "_", sig.get("title", "match").lower())[:40],
            "description": sig.get("title"), "playbook": sig.get("x_playbook") or [], "_engine": "sigma",
            "dedupe": "{pid}|{cmdline}|{ScriptBlockText}",
            "_file": sig.get("_file")}
