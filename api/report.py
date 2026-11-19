"""PDF + HTML incident report (US-012, FR-30..32, US-018 signing + QR)."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
from html import escape
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core import severity as sev
from core.audit import audit
from core.manifest import load as load_manifest
from core.manifest import verify as verify_manifest
from core.signing import fingerprint, public_key_b64, sign_file
from core.timeutil import now_iso, parse_ts

from .casedata import CaseData

COLORS = {"Critical": "#EF4444", "High": "#F97316", "Medium": "#EAB308", "Low": "#3B82F6", "Info": "#6B7280"}
AI_LABEL = "AI-generated, verify before use"


def _qr_data_uri(url: str) -> str:
    import qrcode
    img = qrcode.make(url, box_size=6, border=1)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def timeline_svg(events: list[dict], phases: list[dict], width: int = 720, height: int = 190) -> str:
    notable = [e for e in events if e["severity"] != "Info"]
    if not notable:
        return ""
    t = [parse_ts(e["timestamp_utc"]).timestamp() for e in notable]
    t0, t1 = min(t) - 60, max(t) + 60
    pad = 30

    def x(ts):
        return pad + (ts - t0) / (t1 - t0) * (width - 2 * pad)

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="Inter, sans-serif">']
    for ph in phases:
        a, b = x(parse_ts(ph["start"]).timestamp()), x(parse_ts(ph["end"]).timestamp())
        parts.append(f'<rect x="{a - 4:.1f}" y="20" width="{max(8, b - a + 8):.1f}" height="{height - 60}" fill="#22D3EE" opacity="0.08" rx="4"/>')
        parts.append(f'<text x="{a - 2:.1f}" y="14" font-size="9" fill="#475569">{escape(ph["label"].split(": ")[0])}</text>')
    axis_y = height - 40
    parts.append(f'<line x1="{pad}" y1="{axis_y}" x2="{width - pad}" y2="{axis_y}" stroke="#94A3B8" stroke-width="1"/>')
    span = t1 - t0
    step = 60 if span < 1200 else 300 if span < 7200 else 1800
    tick = (int(t0 // step) + 1) * step
    from datetime import datetime, timezone
    while tick < t1:
        xx = x(tick)
        parts.append(f'<line x1="{xx:.1f}" y1="{axis_y}" x2="{xx:.1f}" y2="{axis_y + 4}" stroke="#94A3B8"/>')
        parts.append(f'<text x="{xx:.1f}" y="{axis_y + 15}" font-size="8" text-anchor="middle" fill="#64748B">'
                     f'{datetime.fromtimestamp(tick, timezone.utc):%H:%M}</text>')
        tick += step * max(1, int(span / step / 10))
    rows = {"Critical": 30, "High": 55, "Medium": 80, "Low": 105}
    for e, ts in zip(notable, t):
        yy = rows.get(e["severity"], 120)
        parts.append(f'<circle cx="{x(ts):.1f}" cy="{yy}" r="4.5" fill="{COLORS[e["severity"]]}" stroke="white" stroke-width="1"/>')
    for s_, yy in rows.items():
        parts.append(f'<text x="2" y="{yy + 3}" font-size="7" fill="#64748B">{s_[:4]}</text>')
    parts.append(f'<text x="{width - pad}" y="{height - 6}" font-size="8" text-anchor="end" fill="#64748B">UTC</text>')
    parts.append("</svg>")
    return "".join(parts)


def ai_summary(cd: CaseData, findings: list[dict]) -> str | None:
    from . import llm
    if not llm.available():
        return None
    facts = "\n".join(f"- [{f['severity']}] {f['first_seen'][11:19]} UTC {f['title']} ({f['attck_id']}): {f['description']}"
                      for f in findings[:30])
    prompt = (f"Write a 5-sentence plain-English incident summary for a non-technical manager about host "
              f"{cd.case.get('host')}. Use ONLY these findings; do not invent facts. Say what happened, the impact, "
              f"and what to do next.\n\nFindings:\n{facts}")
    return llm.generate(prompt, system="You are a careful incident responder. Never speculate beyond the evidence.")


def build_context(case_dir: Path, base_url: str = "http://localhost:8080", ai: bool = False) -> dict:
    cd = CaseData(case_dir)
    s = cd.summary_file()
    findings = cd.findings()
    events, _ = cd.events(include_raw=False)
    notable = [e for e in events if e["severity"] != "Info"]
    by_tactic: dict[str, list] = {}
    for f in findings:
        by_tactic.setdefault(f["tactic"] or "Other", []).append(f)
    from analyzer.attack import TACTICS
    order = {t: i for i, t in enumerate(TACTICS)}
    grouped = sorted(by_tactic.items(), key=lambda kv: order.get(kv[0], 99))
    v = verify_manifest(case_dir)
    pub = public_key_b64()
    ctx = {
        "case": cd.case, "summary": s, "findings": findings, "grouped": grouped, "events": notable[:150],
        "events_total": len(notable), "all_events": len(events), "iocs": cd.iocs(), "matrix": [m for m in cd.attack_matrix(findings) if m["count"]],
        "recommendations": cd.recommendations(findings), "manifest": load_manifest(case_dir)["entries"], "verify": v,
        "exec_summary": cd.exec_summary(), "ai_summary": ai_summary(cd, findings) if ai else None, "ai_label": AI_LABEL,
        "phases": cd.phases(), "timeline_svg": timeline_svg(events, cd.phases()), "colors": COLORS,
        "qr": _qr_data_uri(f"{base_url.rstrip('/')}/verify/{cd.id}"), "verify_url": f"{base_url.rstrip('/')}/verify/{cd.id}",
        "public_key": pub, "key_fingerprint": fingerprint(pub), "generated_at": now_iso(),
        "sev_counts": cd.severity_counts(findings), "collection": cd.case.get("collection") or {},
    }
    cd.close()
    return ctx


def render_html(ctx: dict) -> str:
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(**ctx)


def generate(case_dir: Path, formats=("pdf", "html"), ai: bool = False, base_url: str = "http://localhost:8080") -> dict:
    case_dir = Path(case_dir)
    rdir = case_dir / "report"
    rdir.mkdir(exist_ok=True)
    ctx = build_context(case_dir, base_url, ai)
    # The content hash covers everything except itself; it is printed in every page footer.
    html0 = render_html({**ctx, "report_hash": "{{REPORT_HASH}}"})
    content_hash = hashlib.sha256(html0.encode()).hexdigest()
    html = html0.replace("{{REPORT_HASH}}", content_hash[:16])
    out = {}
    for name in ("timeline.csv", "timeline.json", "timeline.jsonl"):
        src = case_dir / "analysis" / name
        if src.exists():
            shutil.copyfile(src, rdir / name)
    if "html" in formats:
        (rdir / "report.html").write_text(html, encoding="utf-8")
        out["html"] = str(rdir / "report.html")
    if "pdf" in formats:
        try:
            from weasyprint import HTML
        except ImportError as e:
            raise RuntimeError("WeasyPrint is not installed: pip install weasyprint") from e
        HTML(string=html, base_url=str(rdir)).write_pdf(rdir / "report.pdf")
        sig = sign_file(rdir / "report.pdf", rdir / "report.sig", {"case_id": ctx["case"]["id"], "signed_at": now_iso(),
                                                                    "content_hash": content_hash})
        out["pdf"] = str(rdir / "report.pdf")
        out["signature"] = f"{rdir / 'report.sig'} (Ed25519, sha256 {sig['sha256'][:16]}…)"
    out["iocs"] = f"{rdir / 'iocs.csv'}, {rdir / 'iocs.stix.json'}"
    meta = {"generated_at": ctx["generated_at"], "content_hash": content_hash, "formats": list(formats), "ai": bool(ctx["ai_summary"])}
    (rdir / "report.json").write_text(json.dumps(meta, indent=1))
    audit(case_dir, "report", f"report generated formats={list(formats)} content_hash={content_hash[:16]} ai={bool(ctx['ai_summary'])}")
    return out
