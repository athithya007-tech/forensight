"""AI investigator chat (US-017, FR-37): retrieval over the case's own timeline + findings, answered by a local
Ollama model that must cite evidence IDs. Without a model, an extractive answer is built from the evidence."""
from __future__ import annotations

import json
import math
import re
from collections import Counter

from core import severity as sev
from core.timeutil import now_iso

from . import llm
from .casedata import CaseData

SUGGESTED = [
    "How did the attacker get in?",
    "What did the attacker do after logging in?",
    "Did the attacker set up persistence?",
    "Which IP addresses and accounts are involved?",
    "Did the attacker try to hide their tracks?",
]
NOT_FOUND = "Not found in this case's evidence."
INTENTS = {
    r"get in|initial|access|entry|break in|login|logon|brute": ["Initial Access", "Credential Access", "Lateral Movement"],
    r"after|do|execut|run|command|powershell|payload": ["Execution", "Command and Control", "Defense Evasion"],
    r"persist|surviv|reboot|backdoor|startup|task|service|run key|account": ["Persistence", "Privilege Escalation"],
    r"ip|address|account|user|who|ioc|indicator": ["Initial Access", "Credential Access", "Command and Control", "Persistence"],
    r"hide|track|cover|clear|log|evasion|delete": ["Defense Evasion"],
    r"c2|command and control|connect|outbound|network|exfil": ["Command and Control", "Exfiltration"],
    r"ransom|encrypt|impact|damage": ["Impact"],
}
STOP = set("the a an of to in on and or did was were is are what which who how when why does do has have any this that it with for by from as at be".split())


def _tok(s: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_.\-]{2,}", s.lower()) if t not in STOP]


def retrieve(cd: CaseData, question: str, k: int = 20) -> list[dict]:
    events, _ = cd.events(limit=5000)
    q = _tok(question)
    tactics = [t for rx, ts in INTENTS.items() if re.search(rx, question.lower()) for t in ts]
    docs = []
    for e in events:
        raw = json.dumps(e.get("raw_json") or {}, default=str)[:2000]
        text = f"{e['description']} {e['event_type']} {e.get('attck_id') or ''} {e.get('tactic') or ''} {e['source']} {raw}"
        docs.append((e, _tok(text)))
    n = len(docs) or 1
    df = Counter(t for _, toks in docs for t in set(toks))
    avg = sum(len(t) for _, t in docs) / n
    scored = []
    for e, toks in docs:
        tf = Counter(toks)
        bm25 = sum(math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5)) * tf[t] * 2.2 / (tf[t] + 1.2 * (0.25 + 0.75 * len(toks) / (avg or 1)))
                   for t in q if t in tf)
        score = bm25 + (3.0 if e.get("tactic") in tactics else 0) + sev.RANK[e["severity"]] * 0.6
        if e["severity"] == "Info" and not bm25:
            score -= 2
        scored.append((score, e))
    scored.sort(key=lambda x: -x[0])
    top = [e for s, e in scored[:k] if s > 0.5]
    return sorted(top, key=lambda e: e["timestamp_utc"])


def _cite(e: dict) -> dict:
    return {"id": e["id"], "evidence_ref": e["evidence_ref"], "ts": e["timestamp_utc"], "description": e["description"][:200],
            "severity": e["severity"], "attck_id": e.get("attck_id"), "sha256": e.get("evidence_sha256")}


def extractive(question: str, evs: list[dict]) -> tuple[str, list[dict]]:
    tactics = [t for rx, ts in INTENTS.items() if re.search(rx, question.lower()) for t in ts]
    seen, uniq = set(), []
    for e in evs:
        key = e["description"][:90]
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    notable = [e for e in uniq if e["severity"] != "Info"]
    focused = [e for e in notable if e.get("tactic") in tactics[:3]] if tactics else []
    notable = (focused or notable)[:8] or uniq[:5]
    if not notable:
        return NOT_FOUND, []
    lines = [f"Based on the case evidence (no local AI model is running, so this is a direct evidence summary):"]
    for e in notable:
        lines.append(f"- {e['timestamp_utc'][11:19]} UTC: {e['description'][:180]} [E{e['id']}]")
    return "\n".join(lines), [_cite(e) for e in notable]


SYSTEM = ("You are a digital forensics assistant. Answer ONLY from the numbered evidence provided. "
          "Cite every claim with its evidence ID in square brackets, like [E12]. If the evidence does not answer the "
          f"question, reply exactly: {NOT_FOUND} Be concise (max 6 sentences). Times are UTC.")


def answer_stream(cd: CaseData, question: str):
    """Yields NDJSON-able dicts: {type: token|done, ...}"""
    evs = retrieve(cd, question)
    by_id = {e["id"]: e for e in evs}
    if not evs:
        yield {"type": "done", "answer": NOT_FOUND, "citations": [], "model": None}
        _save(cd, question, NOT_FOUND, [])
        return
    if llm.available():
        ctx = "\n".join(f"[E{e['id']}] {e['timestamp_utc']} {e['severity']} {e.get('attck_id') or ''} {e['description'][:300]} "
                        f"(source {e['source']})" for e in evs)
        prompt = f"Evidence:\n{ctx}\n\nQuestion: {question}\nAnswer with citations:"
        buf = ""
        try:
            for tok in llm.stream(prompt, SYSTEM):
                buf += tok
                yield {"type": "token", "text": tok}
        except Exception as e:  # noqa: BLE001
            buf = ""
            yield {"type": "error", "message": f"Local model failed ({e}); falling back to evidence summary"}
        ids = [int(x) for x in re.findall(r"\[E(\d+)\]", buf)]
        cites = [_cite(by_id[i]) for i in dict.fromkeys(ids) if i in by_id]
        if buf and (cites or NOT_FOUND.lower() in buf.lower()):
            ans = buf.strip() if cites else NOT_FOUND
            yield {"type": "done", "answer": ans, "citations": cites, "model": llm.MODEL}
            _save(cd, question, ans, cites)
            return
        if buf:
            yield {"type": "reset", "message": "Model answer had no evidence citations and was discarded (FR-37)."}
    ans, cites = extractive(question, evs)
    for chunk in re.findall(r".{1,40}(?:\s|$)", ans, re.S):
        yield {"type": "token", "text": chunk}
    yield {"type": "done", "answer": ans, "citations": cites, "model": None}
    _save(cd, question, ans, cites)


def _save(cd: CaseData, q: str, a: str, cites: list[dict]) -> None:
    now = now_iso()
    cd.conn.execute("INSERT INTO chat_messages (case_id,role,content,citations,created_at) VALUES (?,?,?,?,?)", (cd.id, "user", q, "[]", now))
    cd.conn.execute("INSERT INTO chat_messages (case_id,role,content,citations,created_at) VALUES (?,?,?,?,?)",
                    (cd.id, "assistant", a, json.dumps(cites), now))
    cd.conn.commit()
