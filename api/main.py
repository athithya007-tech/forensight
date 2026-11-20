"""FastAPI backend for the dashboard (section 15.5). Bound to localhost by default."""
from __future__ import annotations

import asyncio
import json
import threading
import traceback
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from analyzer.attack import navigator_layer
from core import severity as sev
from core.case import create_case, list_cases, load_case
from core.manifest import verify as verify_manifest
from core.paths import case_dir as resolve_case
from core.paths import cases_root, project_root
from core.signing import fingerprint, verify_file

from . import chat as chatmod
from . import views
from .casedata import CaseData

from core.version import __version__ as _VERSION

app = FastAPI(title="ForenSight API", version=_VERSION)
JOBS: dict[str, dict] = {}


def _cd(case_id: str) -> CaseData:
    try:
        return CaseData(resolve_case(case_id))
    except FileNotFoundError:
        raise HTTPException(404, f"Case {case_id} not found")


class NewCase(BaseModel):
    name: str
    investigator: str
    notes: str = ""


class CollectReq(BaseModel):
    mode: str = "demo"            # demo | local
    profile: str = "quick"
    steps: list[int] | None = None
    analyze: bool = True


class ReportReq(BaseModel):
    formats: list[str] = ["pdf", "html"]
    ai: bool = False
    base_url: str | None = None


class ChatReq(BaseModel):
    question: str


# ---------------------------------------------------------------- cases
@app.get("/api/cases")
def get_cases():
    return [{"id": c["id"], "name": c.get("name"), "host": c.get("host"), "os": c.get("os"), "verdict": c.get("verdict"),
             "score": c.get("score"), "created_at": c.get("created_at"), "status": c.get("status"),
             "investigator": c.get("investigator")} for c in list_cases()]


@app.post("/api/cases")
def post_case(body: NewCase):
    d = create_case(body.name, body.investigator, body.notes)
    return load_case(d)


@app.get("/api/health")
def health():
    from core.version import __version__
    from . import llm
    return {"ok": True, "version": __version__, "cases_root": str(cases_root()), "ollama": llm.available()}


def _job(fn, *args) -> str:
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = {"id": jid, "status": "running"}

    def run():
        try:
            JOBS[jid]["result"] = fn(*args)
            JOBS[jid]["status"] = "done"
        except Exception as e:  # noqa: BLE001
            msg = str(e) if type(e).__name__ == "ReportError" else f"{type(e).__name__}: {e}. Run 'forensight doctor' to check your setup."
            JOBS[jid].update(status="failed", error=msg, trace=traceback.format_exc(limit=6))
    threading.Thread(target=run, daemon=True).start()
    return jid


@app.post("/api/demo")
def start_demo(body: CollectReq):
    """Create a demo case and stream its (slowed-down) collection to the live page (US-019)."""
    from demo.generator import STEPS, generate
    steps = body.steps if body.steps is not None else list(STEPS)
    created: dict = {}
    ready = threading.Event()

    def work():
        from analyzer.runner import run as run_analyze
        from core import progress
        try:
            d = generate(steps=steps, name="Lab-Breach-Live" if steps else "Clean-Baseline", delay=0.3,
                         on_created=lambda cd: (created.update(d=cd), ready.set()))
            if body.analyze:
                run_analyze(d)
        except Exception as e:
            # surface the failure on the live page instead of leaving modules spinning forever
            if "d" in created:
                progress.emit(created["d"], "collect", "failed", message=f"{type(e).__name__}: {e}"[:300])
            raise
        return d.name

    jid = _job(work)
    ready.wait(10)
    if "d" not in created:
        raise HTTPException(500, JOBS[jid].get("error", "demo case could not be created"))
    return {"case_id": created["d"].name, "steps": steps, "job": jid}


def _safe(fn):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


@app.post("/api/cases/{case_id}/collect")
def collect(case_id: str, body: CollectReq):
    """Collect from THIS machine (lab use) in the background; progress streams over the WebSocket."""
    d = resolve_case(case_id)

    def work():
        from analyzer.runner import run as analyze
        from collector.runner import run as run_collect
        r = run_collect(d, profile=body.profile)
        if body.analyze:
            analyze(d)
        return r
    return {"job": _job(work)}


@app.post("/api/cases/{case_id}/analyze")
def analyze(case_id: str, online: bool = False):
    from analyzer.runner import run
    d = resolve_case(case_id)
    return {"job": _job(run, d, online)}


@app.get("/api/jobs/{jid}")
def job(jid: str):
    if jid not in JOBS:
        raise HTTPException(404, "job not found")
    j = dict(JOBS[jid])
    if isinstance(j.get("result"), Path):
        j["result"] = str(j["result"])
    return j


# ---------------------------------------------------------------- case views
@app.get("/api/cases/{case_id}/summary")
def summary(case_id: str):
    cd = _cd(case_id)
    try:
        s = cd.summary_file()
        f = cd.findings()
        dur = None
        if s.get("attack_start") and s.get("attack_end"):
            from core.timeutil import parse_ts
            dur = (parse_ts(s["attack_end"]) - parse_ts(s["attack_start"])).total_seconds()
        top = sorted(f, key=lambda x: (-sev.RANK[x["severity"]], -x["confidence"], x["first_seen"]))[:5]
        return {"case": cd.case, "score": s.get("score", cd.case.get("score")), "verdict": s.get("verdict", cd.case.get("verdict")),
                "severity_counts": cd.severity_counts(f), "findings": len(f), "events": s.get("events"),
                "attack_start": s.get("attack_start"), "attack_end": s.get("attack_end"), "duration_seconds": dur,
                "top_findings": top, "host": cd.case.get("host_info") or {"hostname": cd.case.get("host"), "os": cd.case.get("os")},
                "phases": s.get("phases", []), "tactics": [m for m in cd.attack_matrix(f) if m["count"]],
                "techniques": s.get("techniques", []), "analyzed": bool(s), "engines": s.get("engines"),
                "exec_summary": cd.exec_summary() if s else None, "collection": cd.case.get("collection"),
                "artifacts": len(cd.hash_index())}
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/events")
def events(case_id: str, severity: str | None = None, source: str | None = None, tactic: str | None = None,
           from_: str | None = Query(None, alias="from"), to: str | None = None, q: str | None = None,
           limit: int = 2000, offset: int = 0):
    cd = _cd(case_id)
    try:
        items, total = cd.events(severity, source, tactic, from_, to, q, min(limit, 10000), offset)
        facets = {
            "sources": [r[0] for r in cd.conn.execute("SELECT DISTINCT source FROM events WHERE case_id=? ORDER BY source", (cd.id,))],
            "tactics": [r[0] for r in cd.conn.execute("SELECT DISTINCT tactic FROM events WHERE case_id=? AND tactic IS NOT NULL", (cd.id,))],
        }
        return {"items": items, "total": total, "limit": limit, "offset": offset, **facets}
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/graph")
def graph(case_id: str):
    cd = _cd(case_id)
    try:
        return cd.graph()
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/processes")
def processes(case_id: str):
    cd = _cd(case_id)
    try:
        return views.processes(cd)
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/network")
def network(case_id: str):
    cd = _cd(case_id)
    try:
        return views.network(cd)
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/findings")
def findings(case_id: str):
    cd = _cd(case_id)
    try:
        return cd.findings()
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/attack")
def attack(case_id: str):
    cd = _cd(case_id)
    try:
        return cd.attack_matrix()
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/attack/layer")
def attack_layer(case_id: str):
    cd = _cd(case_id)
    try:
        counts: dict[str, int] = {}
        for f in cd.findings():
            if f["attck_id"]:
                counts[f["attck_id"]] = counts.get(f["attck_id"], 0) + 1
        layer = navigator_layer(cd.case, counts)
        return JSONResponse(layer, headers={"Content-Disposition": f'attachment; filename="{cd.id}_attack_layer.json"'})
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/diff")
def diff(case_id: str, category: str | None = None):
    cd = _cd(case_id)
    try:
        return views.diff(cd, category)
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/iocs")
def iocs(case_id: str):
    cd = _cd(case_id)
    try:
        return cd.iocs()
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/evidence")
def evidence(case_id: str):
    cd = _cd(case_id)
    try:
        from core.manifest import load
        m = load(cd.dir)
        sig = cd.dir / "manifest.sig"
        return {"entries": m["entries"], "root_hash": m["entries"][-1]["entry_hash"] if m["entries"] else None,
                "signed": sig.exists(), "audit": (cd.dir / "audit.log").read_text().splitlines()[-200:] if (cd.dir / "audit.log").exists() else []}
    finally:
        cd.close()


@app.get("/api/cases/{case_id}/evidence/item")
def evidence_item(case_id: str, ref: str):
    cd = _cd(case_id)
    try:
        return views.evidence_item(cd, ref)
    finally:
        cd.close()


@app.post("/api/cases/{case_id}/verify")
def verify(case_id: str):
    d = resolve_case(case_id)
    r = verify_manifest(d)
    pdf = d / "report/report.pdf"
    r["report_signature"] = verify_file(pdf, d / "report/report.sig") if pdf.exists() else None
    from core.audit import audit
    audit(d, "verify", f"verification from dashboard: ok={r['ok']} mismatches={r['mismatches']}")
    return r


# ---------------------------------------------------------------- report
@app.post("/api/cases/{case_id}/report")
def make_report(case_id: str, body: ReportReq):
    from .report import generate
    d = resolve_case(case_id)
    return {"job": _job(generate, d, body.formats, body.ai, body.base_url or "http://localhost:8080")}


@app.get("/api/cases/{case_id}/report")
def report_status(case_id: str):
    d = resolve_case(case_id)
    meta = d / "report/report.json"
    files = {n: (d / "report" / n).exists() for n in ("report.pdf", "report.html", "report.sig", "iocs.csv", "iocs.stix.json", "timeline.csv", "timeline.json")}
    return {"meta": json.loads(meta.read_text()) if meta.exists() else None, "files": files}


_MEDIA = {".pdf": "application/pdf", ".html": "text/html", ".csv": "text/csv", ".json": "application/json", ".sig": "application/json",
          ".jsonl": "application/x-ndjson"}


@app.get("/api/cases/{case_id}/report/pdf")
def report_pdf(case_id: str, download: bool = False):
    d = resolve_case(case_id)
    p = d / "report/report.pdf"
    if not p.exists():
        raise HTTPException(404, "Report not generated yet. POST /report first.")
    return FileResponse(p, media_type="application/pdf", filename=f"{case_id}_report.pdf" if download else None)


@app.get("/api/cases/{case_id}/report/file/{name}")
def report_file(case_id: str, name: str, inline: bool = False):
    d = resolve_case(case_id)
    if "/" in name or ".." in name:
        raise HTTPException(400, "bad name")
    p = d / "report" / name
    if not p.exists() and name.startswith("timeline."):
        p = d / "analysis" / name  # timeline exports exist as soon as the case is analyzed
    if not p.exists():
        raise HTTPException(404, f"{name} is not available yet. Analyze the case or generate the report first.")
    return FileResponse(p, media_type=_MEDIA.get(p.suffix, "application/octet-stream"), filename=f"{case_id}_{name}",
                        content_disposition_type="inline" if inline else "attachment")


@app.get("/api/verify/{case_id}")
def public_verify(case_id: str):
    """Target of the QR code on the PDF cover (US-018)."""
    d = resolve_case(case_id)
    c = load_case(d)
    pdf = d / "report/report.pdf"
    sig = verify_file(pdf, d / "report/report.sig") if pdf.exists() else {"valid": False, "reason": "No report generated"}
    m = verify_manifest(d)
    return {"case_id": c["id"], "case_name": c.get("name"), "host": c.get("host"), "verdict": c.get("verdict"), "score": c.get("score"),
            "report_signature": sig, "manifest": {"ok": m["ok"], "chain_ok": m["chain_ok"], "total": m["total"],
                                                   "mismatches": m["mismatches"], "root_hash": m["root_hash"],
                                                   "signature": m["manifest_signature"]},
            "key_fingerprint": fingerprint(sig["public_key"]) if sig.get("public_key") else None}


# ---------------------------------------------------------------- chat
@app.get("/api/cases/{case_id}/chat")
def chat_history(case_id: str):
    cd = _cd(case_id)
    try:
        from core import db as dbm
        msgs = [dbm.decode(r) for r in dbm.rows(cd.conn, "SELECT role,content,citations,created_at FROM chat_messages WHERE case_id=? ORDER BY id", (cd.id,))]
        from . import llm
        return {"messages": msgs, "suggested": chatmod.SUGGESTED, "model": llm.MODEL if llm.available() else None}
    finally:
        cd.close()


@app.post("/api/cases/{case_id}/chat")
def chat(case_id: str, body: ChatReq):
    cd = _cd(case_id)

    def gen():
        try:
            for part in chatmod.answer_stream(cd, body.question.strip()[:500]):
                yield json.dumps(part) + "\n"
        finally:
            cd.close()
    return StreamingResponse(gen(), media_type="application/x-ndjson")


# ---------------------------------------------------------------- live progress
@app.websocket("/ws/cases/{case_id}/progress")
async def progress_ws(ws: WebSocket, case_id: str):
    await ws.accept()
    try:
        d = resolve_case(case_id)
    except FileNotFoundError:
        await ws.send_json({"module": "error", "status": "failed", "message": "case not found"})
        await ws.close()
        return
    p = d / "progress.jsonl"
    pos = 0
    try:
        while True:
            if p.exists():
                with open(p, encoding="utf-8") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    if line.strip():
                        await ws.send_text(line)
            elif pos:
                pos = 0
            await asyncio.sleep(0.15)
    except (WebSocketDisconnect, RuntimeError):
        return


# ---------------------------------------------------------------- web app
DIST = project_root() / "web" / "dist"
if (DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    if path.startswith(("api/", "ws/")):
        raise HTTPException(404)
    f = DIST / path
    if path and f.is_file() and DIST in f.resolve().parents:
        return FileResponse(f)
    index = DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    return HTMLResponse("<h1>ForenSight API is running</h1><p>The web dashboard is not built. Run <code>cd web && npm install && npm run build</code>.</p>"
                        "<p>API docs: <a href='/docs'>/docs</a></p>")
