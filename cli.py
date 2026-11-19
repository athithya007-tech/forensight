"""ForenSight command-line interface (section 8.1). Every command has --help."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

app = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich",
                  help="[bold cyan]ForenSight[/] - collect, analyze, correlate and report on a compromised host.")
console = Console()
SEV_STYLE = {"Critical": "bold red", "High": "dark_orange", "Medium": "yellow", "Low": "blue", "Info": "grey50"}
VERDICT_STYLE = {"Compromised": "bold white on red", "Suspicious": "bold black on yellow", "Clean": "bold white on green"}


def _fail(msg: str, fix: str) -> None:
    console.print(f"[bold red]Error:[/] {msg}\n[cyan]Fix:[/] {fix}")
    raise typer.Exit(1)


def _case(case: str) -> Path:
    from core.paths import case_dir
    try:
        return case_dir(case)
    except FileNotFoundError as e:
        _fail(str(e), "check the case ID with 'forensight cases' (or pass --cases-dir / set FORENSIGHT_CASES)")


@app.callback()
def main(cases_dir: Optional[Path] = typer.Option(None, "--cases-dir", envvar="FORENSIGHT_CASES",
                                                   help="Folder holding case folders (default ./cases).")):
    if cases_dir:
        os.environ["FORENSIGHT_CASES"] = str(cases_dir)


@app.command("new-case")
def new_case(name: str = typer.Option(..., "--name", help="Short case name, e.g. Lab-Breach-01"),
             investigator: str = typer.Option(..., "--investigator", help="Who is running the investigation"),
             notes: str = typer.Option("", "--notes", help="Free-text notes stored in case.json"),
             out: Optional[Path] = typer.Option(None, "--out", help="Create the case on an external drive (e.g. E:\\evidence)")):
    """Create a case folder cases/CASE-YYYYMMDD-NNN with case.json and audit.log (US-001)."""
    from core.case import create_case, load_case
    d = create_case(name, investigator, notes, root=out)
    c = load_case(d)
    console.print(Panel.fit(f"[bold]{c['id']}[/]\nHost: {c['host']} ({c['os']})\nInvestigator: {investigator}\nFolder: {d}",
                            title="Case created", border_style="cyan"))
    console.print(f"Next: [cyan]forensight collect --case {c['id']}" + (f" --out {out}" if out else "") + "[/]")


@app.command()
def cases():
    """List cases with their verdict and score."""
    from core.case import list_cases
    t = Table(title="Cases")
    for col in ("ID", "Name", "Host", "Status", "Score", "Verdict"):
        t.add_column(col)
    for c in list_cases():
        v = c.get("verdict") or "-"
        t.add_row(c["id"], c.get("name", ""), c.get("host", ""), c.get("status", ""), str(c.get("score", "-")),
                  f"[{VERDICT_STYLE.get(v, '')}] {v} [/]")
    console.print(t)


class _RichListener:
    def __init__(self, progress: Progress):
        self.p = progress
        self.tasks = {}
        self.overall = progress.add_task("[bold]overall", total=100)
        self.hashes = 0

    def __call__(self, ev: dict):
        m = ev["module"]
        if ev.get("pct") is not None:
            self.p.update(self.overall, completed=ev["pct"])
        if m == "collect" or m.startswith("analyze:done"):
            if ev["status"] == "complete":
                for name, tid in self.tasks.items():
                    if not self.p.tasks[tid].finished:
                        self.p.update(tid, total=1, completed=1, description=f"[green]✔ {name.split(':', 1)[-1]}")
            return
        if st_new := (m not in self.tasks):
            # a new stage starting means earlier still-open stages are finished
            for name, tid in self.tasks.items():
                if not self.p.tasks[tid].finished and name.startswith("analyze:") and m.startswith("analyze:"):
                    self.p.update(tid, total=1, completed=1, description=f"[green]✔ {name.split(':', 1)[1]}")
            self.tasks[m] = self.p.add_task(m.split(":", 1)[-1], total=None)
        t = self.tasks[m]
        st = ev["status"]
        if st == "file":
            self.hashes += 1
            self.p.console.print(f"  [grey50]{ev['file']}[/] → [green]{ev['sha256'][:16]}…[/]")
        elif st == "done" or st == "complete":
            self.p.update(t, total=1, completed=1, description=f"[green]✔ {m.split(':', 1)[-1]}")
        elif st == "failed":
            self.p.update(t, total=1, completed=1, description=f"[red]✘ {m}: {ev.get('message', '')}")
        elif st == "skipped":
            self.p.update(t, total=1, completed=1, description=f"[yellow]⏭ {m}: {ev.get('message', '')}")
        elif ev.get("message"):
            self.p.update(t, description=f"{m}: {ev['message']}")


def _progress() -> Progress:
    return Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(), console=console)


@app.command()
def collect(case: Optional[str] = typer.Option(None, "--case", help="Case ID; a new case is created if omitted"),
            out: Optional[Path] = typer.Option(None, "--out", help="Write evidence to this folder (external USB) instead of ./cases"),
            profile: str = typer.Option("full", "--profile", help="quick (no RAM, ~2 min) | full | custom"),
            modules: Optional[str] = typer.Option(None, "--modules", help="Comma list for --profile custom, e.g. network,processes,logs"),
            baseline: bool = typer.Option(False, "--baseline", help="Save a clean baseline snapshot into the case (US-015)"),
            investigator: str = typer.Option("first-responder", "--investigator", help="Used when a new case is created"),
            name: str = typer.Option("Incident", "--name", help="Used when a new case is created")):
    """Collect evidence in order of volatility, hashing every file into manifest.json (US-002..005)."""
    from collector.runner import run
    from core.case import create_case
    from core.paths import cases_root
    if out:
        out.mkdir(parents=True, exist_ok=True)
    root = out or cases_root()
    if case:
        d = root / case
        if not d.exists():
            src = cases_root() / case
            if out and src.exists():
                shutil.move(str(src), str(d))
                console.print(f"[cyan]Moved case folder to {d}[/]")
            else:
                _fail(f"case {case} not found in {root}", "create it with 'forensight new-case' or omit --case")
    else:
        d = create_case(name, investigator, root=root)
        console.print(f"Created case [bold]{d.name}[/] in {d.parent}")
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print("[yellow]Note:[/] not running as root - RAM, some logs and other users' files will be skipped.")
    with _progress() as p:
        try:
            res = run(d, profile=profile, modules=modules.split(",") if modules else None, baseline=baseline, listener=_RichListener(p))
        except ValueError as e:
            _fail(str(e), "see 'forensight collect --help'")
    t = Table(title=f"Collection summary - {d.name}")
    t.add_column("Module")
    t.add_column("Result")
    for m, r in res["modules"].items():
        t.add_row(m, "[green]ok[/]" if r == "ok" else "[yellow]skipped[/] (no RAM tool in tools/)" if r == "skipped" else f"[red]{r}[/]")
    console.print(t)
    console.print(f"[bold]{res['artifacts']}[/] artifacts, {res['bytes'] / 2**20:.1f} MB, SHA-256 chained in manifest.json "
                  f"({res['seconds']:.0f}s). Next: [cyan]forensight analyze --case {d.name}[/]")


@app.command()
def analyze(case: str = typer.Option(..., "--case", help="Case ID"),
            online: bool = typer.Option(False, "--online", help="Query VirusTotal/AbuseIPDB by hash/IP (needs VT_API_KEY / ABUSEIPDB_API_KEY)")):
    """Run Volatility, event-log rules, Sigma, YARA and intel, then build the timeline (US-006..010)."""
    from analyzer.runner import run
    d = _case(case)
    with _progress() as p:
        listener = _RichListener(p)
        s = run(d, online=online, listener=listener)
    _print_summary(d, s)


def _print_summary(d: Path, s: dict) -> None:
    from core import db as dbm
    v = s["verdict"]
    console.print(Panel.fit(f"[{VERDICT_STYLE[v]}] {v} [/]  score [bold]{s['score']}[/]/100\n"
                            + "  ".join(f"[{SEV_STYLE[k]}]{k}: {n}[/]" for k, n in s["severity_counts"].items())
                            + f"\n{s['events']} timeline events · {len(s['techniques'])} ATT&CK techniques · {s['seconds']}s",
                            title=f"{d.name} analysis", border_style="cyan"))
    conn = dbm.connect(d)
    t = Table(title="Findings")
    for col in ("Sev", "First seen (UTC)", "ATT&CK", "Finding"):
        t.add_column(col)
    for f in dbm.rows(conn, "SELECT * FROM findings WHERE case_id=? ORDER BY id LIMIT 25", (d.name,)):
        t.add_row(f"[{SEV_STYLE[f['severity']]}]{f['severity']}[/]", f["first_seen"][11:19], f["attck_id"] or "",
                  (f["description"] or f["title"])[:110] + (" [grey50](pre-existing)[/]" if f["pre_existing"] else ""))
    console.print(t)
    console.print(f"Next: [cyan]forensight report --case {d.name}[/] or [cyan]forensight serve --case {d.name}[/]")


@app.command()
def report(case: str = typer.Option(..., "--case", help="Case ID"),
           format: str = typer.Option("pdf,html", "--format", help="Comma list: pdf,html"),
           ai: bool = typer.Option(False, "--ai", help="Add an AI-written plain-English summary via local Ollama (labelled AI-generated)"),
           base_url: str = typer.Option("http://localhost:8080", "--base-url", help="URL encoded in the cover QR code")):
    """Generate the signed PDF/HTML report, IOCs (CSV + STIX 2.1) and timeline exports (US-012, US-018)."""
    from api.report import generate
    d = _case(case)
    if not (d / "analysis/summary.json").exists():
        _fail("case has not been analyzed", f"run 'forensight analyze --case {case}' first")
    with console.status("Rendering report…"):
        out = generate(d, formats=[f.strip() for f in format.split(",")], ai=ai, base_url=base_url)
    for k, v in out.items():
        console.print(f"[green]✔[/] {k}: {v}")


@app.command()
def verify(case: str = typer.Option(..., "--case", help="Case ID")):
    """Re-hash every artifact, walk the hash chain and check signatures (US-005, US-018)."""
    from core.manifest import verify as do_verify
    from core.signing import verify_file
    d = _case(case)
    with console.status("Re-hashing evidence…"):
        r = do_verify(d)
    t = Table(title=f"Chain of custody - {d.name}")
    for col in ("#", "Path", "SHA-256", "Status"):
        t.add_column(col)
    for e in r["entries"]:
        ok = e["status"] == "ok"
        t.add_row(str(e["seq"]), e["path"], (e["expected"] or "")[:16] + "…",
                  "[green]✔ ok[/]" if ok else f"[bold red]✘ {'; '.join(e['problems'])}[/]")
    console.print(t)
    for f in r["unlisted_files"]:
        console.print(f"[bold red]✘ file not in manifest:[/] {f}")
    ms = r["manifest_signature"]
    console.print(("[green]✔" if ms.get("valid") else "[bold red]✘") + f" manifest signature: {ms.get('reason')}[/]")
    pdf = d / "report/report.pdf"
    if pdf.exists():
        rs = verify_file(pdf, d / "report/report.sig")
        console.print(("[green]✔" if rs["valid"] else "[bold red]✘") + f" report signature: {rs['reason']}[/]")
    if r["ok"]:
        console.print(f"[bold green]VERIFIED[/] {r['total']} artifacts, hash chain intact, root {r['root_hash'][:16]}…")
    else:
        console.print(f"[bold red]VERIFICATION FAILED[/] {r['mismatches']} mismatches"
                      + (f", chain broken at entry {r['first_break']}" if r['first_break'] else ""))
        raise typer.Exit(2)


@app.command()
def serve(case: Optional[str] = typer.Option(None, "--case", help="Open this case's dashboard"),
          host: str = typer.Option("127.0.0.1", "--host", help="Bind address (localhost only by default)"),
          port: int = typer.Option(8080, "--port")):
    """Start the dashboard on http://localhost:8080 (US-011)."""
    import uvicorn
    if host not in ("127.0.0.1", "localhost"):
        console.print(f"[yellow]Warning:[/] dashboard exposed on {host}; evidence may contain personal data.")
    url = f"http://localhost:{port}" + (f"/cases/{case}" if case else "")
    console.print(f"Dashboard: [link={url}]{url}[/link]  (Ctrl+C to stop)")
    uvicorn.run("api.main:app", host=host, port=port, log_level="warning")


@app.command()
def demo(steps: str = typer.Option("1,2,3,4,5,6,7,8", "--steps", help="Attack steps to simulate, e.g. 1,2,5,7 (or 'none' for a clean host)"),
         linux: bool = typer.Option(False, "--linux", help="Generate the Linux SSH brute-force scenario instead"),
         run_all: bool = typer.Option(True, "--analyze/--no-analyze", help="Also run analyze + report"),
         name: str = typer.Option("Lab-Breach-01", "--name")):
    """Build a demo case from the PRD's scripted lab attack - no VM needed (US-014)."""
    from demo.generator import generate, generate_linux
    if linux:
        d = generate_linux()
    else:
        chosen = [] if steps.strip().lower() == "none" else [int(s) for s in steps.split(",") if s.strip()]
        if any(s < 1 or s > 8 for s in chosen):
            _fail("steps must be between 1 and 8", "use e.g. --steps 1,2,5,7")
        d = generate(steps=chosen, name=name if chosen else "Clean-Baseline")
    console.print(f"Demo case [bold]{d.name}[/] collected at {d}")
    if run_all:
        from analyzer.runner import run
        from api.report import generate as rep
        s = run(d)
        _print_summary(d, s)
        rep(d, formats=["pdf", "html"])
        console.print(f"[green]✔[/] report: {d / 'report/report.pdf'}")


@app.command()
def metrics(case: str = typer.Option(..., "--case", help="Demo case ID (needs lab_truth.json)")):
    """Score detection against the lab ground truth: steps detected, timeline accuracy (section 12)."""
    from analyzer.metrics import evaluate
    d = _case(case)
    m = evaluate(d)
    console.print_json(json.dumps(m))


if __name__ == "__main__":
    sys.exit(app())
