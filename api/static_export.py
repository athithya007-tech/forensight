"""Export a read-only copy of the dashboard's data for static hosting (GitHub Pages).

Fresh demo cases are generated, analyzed and reported in a throwaway folder; every GET endpoint the dashboard
uses is then called through the real FastAPI app, so the online demo shows exactly what the local tool shows.
Layout: <out>/demo-data/<api path without /api/>.json, plus the report files. Write actions (collect, analyze,
report, new case) are disabled in the static build; verify and the suggested chat questions are pre-computed."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path


def _dump(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, separators=(",", ":"), default=str), encoding="utf-8")


def export_site(out: Path) -> list[str]:
    out = Path(out)
    data = out / "demo-data"
    if data.exists():
        shutil.rmtree(data)
    old = {k: os.environ.get(k) for k in ("FORENSIGHT_CASES", "FORENSIGHT_HOME", "OLLAMA_HOST")}
    with tempfile.TemporaryDirectory() as td:
        os.environ.update(FORENSIGHT_CASES=str(Path(td) / "cases"), FORENSIGHT_HOME=str(Path(td) / "home"),
                          OLLAMA_HOST="http://127.0.0.1:9")  # deterministic extractive chat answers, no model needed
        try:
            from fastapi.testclient import TestClient

            from analyzer.runner import run
            from demo.generator import generate, generate_linux

            from . import llm
            from .main import app
            from .report import generate as make_report
            llm.HOST = "http://127.0.0.1:9"
            dirs = [generate(name="Lab-Breach-01"), generate(steps=[1, 2, 5, 7], name="Partial-Breach"),
                    generate_linux(), generate(steps=[], name="Clean-Baseline")]
            for d in dirs:
                run(d)
                make_report(d, formats=["pdf", "html"])
            api = TestClient(app)
            get = lambda p: api.get(p).raise_for_status().json()  # noqa: E731
            _dump(data / "health.json", get("/api/health") | {"ollama": False, "static": True})
            cases = get("/api/cases")
            _dump(data / "cases.json", cases)
            ids = []
            for c in cases:
                cid = c["id"]
                ids.append(cid)
                base, dst = f"/api/cases/{cid}", data / "cases" / cid
                for ep in ["summary", "graph", "processes", "network", "findings", "attack", "iocs", "diff", "evidence", "report", "chat"]:
                    _dump(dst / f"{ep}.json", get(f"{base}/{ep}"))
                _dump(dst / "attack" / "layer.json", get(f"{base}/attack/layer"))
                ev = get(f"{base}/events?limit=10000")
                _dump(dst / "events.json", ev)
                refs = {e["evidence_ref"] for e in ev["items"] if e.get("evidence_ref")}
                refs |= {f.get("evidence_ref") for f in get(f"{base}/findings") if f.get("evidence_ref")}
                items = {}
                for r in sorted(x for x in refs if x):
                    resp = api.get(f"{base}/evidence/item", params={"ref": r})
                    if resp.status_code == 200:
                        items[r] = resp.json()
                _dump(dst / "evidence-items.json", items)
                _dump(dst / "verify.json", api.post(f"{base}/verify").raise_for_status().json())
                _dump(data / "verify" / f"{cid}.json", get(f"/api/verify/{cid}"))
                answers = {}
                for q in get(f"{base}/chat")["suggested"]:
                    lines = [json.loads(x) for x in api.post(f"{base}/chat", json={"question": q}).text.splitlines() if x.strip()]
                    done = next((x for x in lines if x.get("type") == "done"), None)
                    if done:
                        answers[q] = done
                _dump(dst / "chat-answers.json", answers)
                rdir = next(d for d in dirs if d.name == cid) / "report"
                for f in rdir.iterdir():
                    if f.is_file() and f.suffix in {".pdf", ".html", ".sig", ".csv", ".json"} and not f.name.endswith(".tmp"):
                        (dst / "report" / "file").mkdir(parents=True, exist_ok=True)
                        shutil.copy2(f, dst / "report" / "file" / f.name)
                for f in ("timeline.csv", "timeline.json", "timeline.jsonl"):
                    src = rdir.parent / "analysis" / f
                    if src.exists() and not (dst / "report" / "file" / f).exists():
                        shutil.copy2(src, dst / "report" / "file" / f)
            return ids
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
