"""Detection rule engine. A new detection is a new YAML file in rules/custom/ (no code change).

Rule keys:
  id, title, kind (record kind), attck_id, severity, confidence, event_type, description (format string),
  match (all-of conditions), filter (exclusions), threshold {count, window, group_by, aggregate},
  followed_by {match, within, same, kind}, unfollowed_severity, in_window, context, playbook, baseline.

Condition syntax (Sigma-like): `Field: value` (list = any of), `Field|contains`, `|startswith`, `|endswith`,
`|re`, `|gte`, `|lte`, `|in_file` (list under rules/intel/), `|exists`; nest with any: [...], all: [...], not: {...}.
"""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import yaml

from core.paths import rules_dir
from core.severity import normalize
from core.timeutil import parse_duration, parse_ts

_file_cache: dict[str, set[str]] = {}


def load_rules(base: Path | None = None) -> list[dict]:
    base = base or rules_dir() / "custom"
    rules = []
    for p in sorted(base.glob("*.y*ml")):
        for doc in yaml.safe_load_all(p.read_text(encoding="utf-8")):
            if not doc:
                continue
            for r in doc if isinstance(doc, list) else [doc]:
                r.setdefault("severity", "Medium")
                r["severity"] = normalize(r["severity"])
                r.setdefault("confidence", 0.7)
                r.setdefault("playbook", [])
                r["_file"] = p.name
                rules.append(r)
    return rules


def _get(fields: dict, name: str):
    if name in fields:
        return fields[name]
    low = name.lower()
    for k, v in fields.items():
        if k.lower() == low:
            return v
    return None


def _in_file(name: str) -> set[str]:
    if name not in _file_cache:
        p = rules_dir() / "intel" / name
        _file_cache[name] = {l.split("#")[0].strip().lower() for l in p.read_text().splitlines()
                             if l.split("#")[0].strip()} if p.exists() else set()
    return _file_cache[name]


def _cmp(actual, op: str, expected) -> bool:
    if op == "exists":
        return (actual not in (None, "", "-")) == bool(expected)
    if actual is None:
        return False
    if op in ("gte", "lte", "gt", "lt"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gte": a >= e, "lte": a <= e, "gt": a > e, "lt": a < e}[op]
    a = str(actual).lower()
    e = str(expected).lower()
    if op == "eq":
        if isinstance(expected, (int, float)) and not isinstance(expected, bool):
            try:
                return float(actual) == float(expected)
            except (TypeError, ValueError):
                return False
        return a == e
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    if op == "re":
        return re.search(str(expected), str(actual), re.I) is not None
    if op == "in_file":
        return a in _in_file(str(expected))
    raise ValueError(f"unknown operator {op}")


def matches(fields: dict, cond) -> bool:
    if cond is None:
        return True
    if isinstance(cond, list):          # list of condition dicts = any of
        return any(matches(fields, c) for c in cond)
    for key, expected in cond.items():
        if key == "any":
            if not any(matches(fields, c) for c in expected):
                return False
            continue
        if key == "all":
            if not all(matches(fields, c) for c in expected):
                return False
            continue
        if key == "not":
            if matches(fields, expected):
                return False
            continue
        name, _, op = key.partition("|")
        op = op or "eq"
        actual = _get(fields, name)
        values = expected if isinstance(expected, list) else [expected]
        if not any(_cmp(actual, op, v) for v in values):
            return False
    return True


class _SafeDict(dict):
    def __missing__(self, key):
        return ""


def describe(template: str | None, fields: dict, extra: dict | None = None) -> str:
    if not template:
        return ""
    data = _SafeDict({k: ("" if v is None else v) for k, v in fields.items()})
    data.update(extra or {})
    try:
        return template.format_map(data)
    except (ValueError, IndexError, KeyError, AttributeError):
        return template


def evaluate(rule: dict, records: list[dict], window: tuple | None = None) -> list[dict]:
    """Return hits: {rule, records: [...], key_record, description, severity}."""
    kinds = rule.get("kind")
    kinds = set(kinds if isinstance(kinds, list) else [kinds]) if kinds else None
    cand = [r for r in records if (kinds is None or r["kind"] in kinds)
            and matches(r["fields"], rule.get("match")) and not (rule.get("filter") and matches(r["fields"], rule["filter"]))]
    if rule.get("in_window") and window:
        start, end = window
        cand = [r for r in cand if (not start or parse_ts(r["ts"]) >= start) and (not end or parse_ts(r["ts"]) <= end)]
    if not cand:
        return []
    th = rule.get("threshold")
    if not th:
        return [{"rule": rule, "records": [r], "key_record": r, "severity": rule["severity"],
                 "description": describe(rule.get("description") or rule.get("title"), r["fields"], {"count": 1})}
                for r in cand]
    return _threshold(rule, cand, records)


def _threshold(rule: dict, cand: list[dict], all_records: list[dict]) -> list[dict]:
    th = rule["threshold"]
    need = int(th.get("count", 5))
    win = parse_duration(th.get("window", "5m"))
    group_by = th.get("group_by")
    groups: dict = {}
    for r in cand:
        key = _get(r["fields"], group_by) if group_by else "*"
        groups.setdefault(str(key).lower(), []).append(r)
    hits = []
    fb = rule.get("followed_by")
    for key, rs in groups.items():
        rs.sort(key=lambda r: r["ts"])
        times = [parse_ts(r["ts"]) for r in rs]
        burst = None
        j = 0
        for i in range(len(rs)):
            while times[i] - times[j] > win:
                j += 1
            if i - j + 1 >= need:
                # extend burst to include every candidate in this group within the window chain
                burst = (j, i)
                break
        if burst is None:
            continue
        b0 = burst[0]
        members = [r for r, t in zip(rs[b0:], times[b0:]) if True]
        # trim members: keep chain where consecutive gaps <= window
        chain = [members[0]]
        for r in members[1:]:
            if parse_ts(r["ts"]) - parse_ts(chain[-1]["ts"]) <= win:
                chain.append(r)
            else:
                break
        first, last = parse_ts(chain[0]["ts"]), parse_ts(chain[-1]["ts"])
        key_rec = chain[-1]
        severity = rule["severity"]
        followed = None
        if fb:
            within = parse_duration(fb.get("within", "10m"))
            fkinds = fb.get("kind")
            same = fb.get("same", [group_by] if group_by else [])
            for r in sorted(all_records, key=lambda r: r["ts"]):
                if fkinds and r["kind"] not in (fkinds if isinstance(fkinds, list) else [fkinds]):
                    continue
                t = parse_ts(r["ts"])
                if t < first or t > last + within:
                    continue
                if not matches(r["fields"], fb.get("match")):
                    continue
                if all(str(_get(r["fields"], s)).lower() == str(_get(key_rec["fields"], s)).lower() for s in same):
                    followed = r
                    break
            if followed is None:
                if not rule.get("unfollowed_severity"):
                    continue
                severity = normalize(rule["unfollowed_severity"])
        extra = {"count": len(chain), "first": chain[0]["ts"][11:19], "last": chain[-1]["ts"][11:19],
                 "window": th.get("window", "5m"), "group": key}
        base_fields = dict(key_rec["fields"])
        if followed:
            base_fields.update({f"success_{k}": v for k, v in followed["fields"].items()})
        tmpl = rule.get("description") if followed or not fb else rule.get("unfollowed_description", rule.get("description"))
        recs = chain + ([followed] if followed else [])
        hits.append({"rule": rule, "records": recs, "key_record": followed or key_rec, "severity": severity,
                     "aggregate": th.get("aggregate", True), "burst": chain, "followed": followed,
                     "description": describe(tmpl or rule.get("title"), base_fields, extra)})
    return hits
