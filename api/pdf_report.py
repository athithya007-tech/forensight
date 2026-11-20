"""The ForenSight PDF report, drawn with fpdf2 (pure Python, identical on Windows, macOS and Linux).

Designed for two readers at once:
  * the manager or lawyer, who reads page 1 and 2 only: a plain-language verdict, the attack measured on the
    forensic scale, what happened step by step, and what to do now;
  * the investigator, who uses the appendices: timeline, findings with evidence, ATT&CK map, IOCs, custody.

Visual language follows the dashboard's "Evidence Room": warm paper, ink, evidence-tape red, the forensic
photo scale. Fonts (OFL) are bundled in api/fonts so the PDF looks the same everywhere.
"""
from __future__ import annotations

import base64
import io
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

FONTS = Path(__file__).parent / "fonts"

PAPER = (243, 240, 233)
SHEET = (250, 248, 243)
INK = (28, 27, 24)
INK2 = (95, 89, 78)
RULE = (217, 211, 197)
TAPE = (194, 40, 29)
AMBER = (214, 150, 20)
OK = (38, 120, 74)
SEV = {"Critical": (179, 38, 30), "High": (201, 91, 12), "Medium": (156, 115, 0), "Low": (52, 96, 145), "Info": (125, 119, 108)}
VERDICT = {"Compromised": SEV["Critical"], "Suspicious": SEV["Medium"], "Clean": OK}

HEADLINE = {"Compromised": "{h} was compromised.", "Suspicious": "{h} shows suspicious activity.", "Clean": "{h} looks clean."}
VERDICT_MEANS = {
    "Compromised": "There is strong evidence that an attacker got in and acted on this machine. Treat it as breached.",
    "Suspicious": "Some activity matches known attacker behaviour. Investigate before trusting this machine again.",
    "Clean": "Nothing in the collected evidence matched known attacker behaviour.",
}
TACTIC_PLAIN = {
    "Reconnaissance": "Scouted the target", "Resource Development": "Prepared their tools", "Initial Access": "Got in",
    "Execution": "Ran their own commands", "Persistence": "Set up a way back in", "Privilege Escalation": "Gained more power",
    "Defense Evasion": "Covered their tracks", "Credential Access": "Went after passwords", "Discovery": "Looked around",
    "Lateral Movement": "Moved to other machines", "Collection": "Gathered data", "Command and Control": "Talked to their own server",
    "Exfiltration": "Took data out", "Impact": "Caused damage",
}
TECH_PLAIN = {
    "T1110": "Guessed passwords", "T1078": "Logged in with a real account", "T1059.001": "Ran PowerShell commands",
    "T1059.004": "Ran shell commands", "T1027": "Disguised their commands", "T1105": "Brought a file onto the machine",
    "T1136": "Created a new account", "T1136.001": "Created a new account", "T1098": "Gave an account admin rights",
    "T1547.001": "Made a program start at every login", "T1053.005": "Scheduled a task to run later", "T1053.003": "Scheduled a cron job",
    "T1543.003": "Installed a service", "T1071": "Talked to their own server", "T1070.001": "Wiped the event log",
    "T1070.003": "Cleared the command history", "T1055": "Hid code inside another program", "T1014": "Hid a running program",
    "T1562.001": "Switched off antivirus", "T1003.001": "Stole passwords from memory", "T1486": "Encrypted files",
    "T1204.002": "Got a user to open a booby-trapped file",
}


def plain(f: dict) -> str:
    return TECH_PLAIN.get(f.get("attck_id") or "") or TACTIC_PLAIN.get(f.get("tactic") or "", "Suspicious activity")


SEV_MEANS = {"Critical": "act now", "High": "confirmed attacker behaviour", "Medium": "suspicious, needs a look",
             "Low": "worth noting", "Info": "background context"}
GLOSSARY = [
    ("Finding", "Something on the machine that matched a known attacker behaviour."),
    ("Severity", "How serious a finding is, from Info (context) to Critical (act now)."),
    ("MITRE ATT&CK", "A public catalogue of attacker techniques. Each finding is labelled with one, e.g. T1110 = password guessing."),
    ("IOC (indicator of compromise)", "A concrete clue other systems can search for: an IP address, a file fingerprint, an account name."),
    ("SHA-256 hash", "A file's unique fingerprint. Changing a single letter of the file changes the fingerprint completely."),
    ("Chain of custody", "The record proving the evidence was not altered: every file's fingerprint, linked in order."),
    ("Signature (Ed25519)", "A digital seal on this PDF. The QR code on page 1 checks it; any edit breaks it."),
    ("Baseline", "A snapshot of the machine taken while it was still clean, used to see exactly what changed."),
]

# Fallback when the bundled fonts are missing: system Unicode fonts, else Latin-1 core fonts.
FONT_CANDIDATES = [
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\consola.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
     "/System/Library/Fonts/Supplemental/Courier New.ttf"),
]
LATIN1 = str.maketrans({"→": "->", "–": "-", "—": "-", "×": "x", "✔": "OK", "✘": "X", "…": "...", "·": "-", "“": '"', "”": '"',
                        "‘": "'", "’": "'", "−": "-", "≥": ">=", "≤": "<="})


class ReportPDF(FPDF):
    def __init__(self, case: dict, report_hash: str, use_bundled: bool = True):
        super().__init__(format="A4", unit="mm")
        self.case, self.report_hash = case, report_hash
        self.unicode = True
        bundled = {k: FONTS / v for k, v in {"sans": "InstrumentSans-Regular.ttf", "sansB": "InstrumentSans-SemiBold.ttf",
                                             "serif": "Newsreader-Regular.ttf", "serifB": "Newsreader-Medium.ttf",
                                             "mono": "IBMPlexMono-Regular.ttf", "monoB": "IBMPlexMono-Medium.ttf"}.items()}
        if use_bundled and all(p.exists() for p in bundled.values()):
            for fam in ("sans", "serif", "mono"):
                self.add_font(fam, "", str(bundled[fam]))
                self.add_font(fam, "B", str(bundled[fam + "B"]))
            self.sans, self.serif, self.mono = "sans", "serif", "mono"
        else:
            for regular, bold, mono in FONT_CANDIDATES:
                if all(Path(p).exists() for p in (regular, bold, mono)):
                    self.add_font("sys", "", regular)
                    self.add_font("sys", "B", bold)
                    self.add_font("sysmono", "", mono)
                    self.add_font("sysmono", "B", mono)
                    self.sans = self.serif = "sys"
                    self.mono = "sysmono"
                    break
            else:
                self.unicode = False
                self.sans, self.serif, self.mono = "helvetica", "times", "courier"
        self.set_margins(18, 22, 18)
        self.set_auto_page_break(True, margin=20)
        self.alias_nb_pages()
        self.set_title(f"ForenSight incident report {case['id']}")
        self.set_author(case.get("investigator") or "ForenSight")
        self.set_creator("ForenSight")

    def multi_cell(self, *args, **kwargs):  # left-aligned: justified text spaces badly
        kwargs.setdefault("align", "L")
        return super().multi_cell(*args, **kwargs)

    def t(self, text) -> str:
        s = "" if text is None else str(text)
        return s if self.unicode else s.translate(LATIN1).encode("latin-1", "replace").decode("latin-1")

    def font(self, family: str, size: float, bold: bool = False, color=INK):
        self.set_font(family, "B" if bold else "", size)
        self.set_text_color(*color)

    # ---- page furniture -------------------------------------------------
    def mark(self, x: float, y: float, s: float, ink=INK):
        """The ForenSight mark: a measured box with an evidence-tape band (same as the dashboard)."""
        k = s / 22
        self.set_draw_color(*ink)
        self.set_line_width(1.5 * k)
        self.rect(x + 1 * k, y + 1 * k, 20 * k, 20 * k, round_corners=True, corner_radius=3 * k)
        self.set_fill_color(*TAPE)
        self.rect(x + 1 * k, y + 14 * k, 20 * k, 4 * k, style="F")
        for i, tick in enumerate((5, 9, 13, 17)):
            self.line(x + tick * k, y + 1 * k, x + tick * k, y + (6 if i % 2 == 0 else 4) * k)

    def header(self):
        if self.page_no() == 1:
            return
        self.mark(self.l_margin, 9, 5.2)
        self.set_xy(self.l_margin + 7, 9.2)
        self.font(self.serif, 11, True)
        self.cell(40, 5, "ForenSight")
        self.font(self.sans, 8, color=INK2)
        self.set_xy(self.l_margin, 9.6)
        self.cell(self.epw, 5, self.t(f"{self.case['id']}  ·  {self.case.get('name', '')}"), align="R")
        self.set_draw_color(*RULE)
        self.set_line_width(0.3)
        self.line(self.l_margin, 16.5, self.w - self.r_margin, 16.5)
        self.set_y(self.t_margin)

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(*RULE)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y() - 1.5, self.w - self.r_margin, self.get_y() - 1.5)
        w = self.epw / 3
        self.font(self.sans, 7.5, color=INK2)
        self.cell(w, 5, self.t("Incident report · confidential"))
        self.cell(w, 5, f"Page {self.page_no()} of {{nb}}", align="C")
        self.font(self.mono, 7, color=INK2)
        self.cell(w, 5, self.t(f"report hash {self.report_hash}"), align="R")

    # ---- building blocks --------------------------------------------------
    def need(self, mm: float):
        if self.get_y() + mm > self.h - self.b_margin:
            self.add_page()

    def section(self, title: str, lead: str | None = None, keep: float = 48):
        self.need(keep)  # never strand a heading at the bottom of a page
        self.ln(4)
        self.font(self.serif, 18, True)
        self.cell(0, 9, self.t(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if lead:
            self.font(self.sans, 9.5, color=INK2)
            self.multi_cell(0, 4.8, self.t(lead), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def label(self, text: str, x=None, y=None, color=INK2):
        if x is not None:
            self.set_xy(x, y)
        self.font(self.sans, 7.5, True, color)
        self.cell(0, 4, self.t(text.upper()), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def swatch(self, sev: str, x: float, y: float, size=2.6):
        self.set_fill_color(*SEV.get(sev, SEV["Info"]))
        self.rect(x, y, size, size, style="F")

    def sev_word(self, sev: str, h=4.6):
        x, y = self.get_x(), self.get_y()
        self.swatch(sev, x, y + (h - 2.6) / 2)
        self.set_xy(x + 4, y)
        self.font(self.sans, 8.5, True, SEV.get(sev, INK))
        self.cell(self.get_string_width(sev) + 2, h, sev)

    def table(self, headers, rows, widths, mono_cols=(), size=8, sev_col=None):
        self.set_draw_color(*RULE)
        self.set_line_width(0.2)
        self.set_fill_color(255, 255, 255)
        self.font(self.sans, size)
        mono = FontFace(family=self.mono, size_pt=size - 0.6, color=INK)
        with super().table(col_widths=widths, text_align="LEFT", line_height=size * 0.5, borders_layout="HORIZONTAL_LINES",
                           headings_style=FontFace(family=self.sans, emphasis="BOLD", size_pt=size - 0.5, color=INK2, fill_color=(255, 255, 255)),
                           cell_fill_mode="ROWS", cell_fill_color=SHEET, padding=(1.4, 1.6), first_row_as_headings=True) as tb:
            hr = tb.row()
            for h in headers:
                hr.cell(self.t(h))
            for r in rows:
                row = tb.row()
                for i, v in enumerate(r):
                    if sev_col is not None and i == sev_col:
                        row.cell(self.t(v), style=FontFace(family=self.sans, emphasis="BOLD", size_pt=size, color=SEV.get(v, INK)))
                    else:
                        row.cell(self.t(v), style=mono if i in mono_cols else None)
        self.ln(2)

    # ---- signature drawings ----------------------------------------------
    def score_scale(self, x, y, w, score: int):
        bands = [(0, 20, "Clean", (220, 232, 222)), (20, 60, "Suspicious", (238, 227, 196)), (60, 100, "Compromised", (241, 214, 208))]
        h = 6
        for a, b, name, col in bands:
            self.set_fill_color(*col)
            self.rect(x + w * a / 100, y, w * (b - a) / 100, h, style="F")
            self.font(self.sans, 7, color=INK2)
            self.set_xy(x + w * a / 100 + 1, y + h + 2.2)
            self.cell(30, 3, name)
        self.set_draw_color(*INK)
        self.set_line_width(0.35)
        self.rect(x, y, w, h)
        for i in range(11):
            tx = x + w * i / 10
            self.line(tx, y + h, tx, y + h + (1.8 if i % 5 == 0 else 1))
        mx = x + w * max(0, min(100, score)) / 100
        self.set_fill_color(*TAPE)
        self.rect(mx - 0.7, y - 2, 1.4, h + 4, style="F")

    def time_scale(self, x, y, w, start: datetime, end: datetime, events: list[dict]):
        """The attack measured on the forensic photo scale: alternating ink/paper segments, minute ticks,
        one mark per notable event (tall = High/Critical)."""
        span = max(1.0, (end - start).total_seconds())
        pad = max(30.0, span * 0.04)
        t0, t1 = start.timestamp() - pad, end.timestamp() + pad
        X = lambda ts: x + (ts - t0) / (t1 - t0) * w  # noqa: E731
        bar_y, bar_h = y + 11, 2.6
        step = 60 if span <= 1200 else 300 if span <= 7200 else 1800 if span <= 43200 else 3600
        ticks = list(range(int(t0 // step + 1) * step, int(t1), step))
        edges = [t0] + ticks + [t1]
        self.set_draw_color(*INK)
        self.set_line_width(0.25)
        for i in range(len(edges) - 1):
            self.set_fill_color(*(INK if i % 2 == 0 else (255, 255, 255)))
            self.rect(X(edges[i]), bar_y, X(edges[i + 1]) - X(edges[i]), bar_h, style="DF")
        every = max(1, len(ticks) // 8)
        for i, tk in enumerate(ticks):
            self.line(X(tk), bar_y + bar_h, X(tk), bar_y + bar_h + (1.6 if i % every == 0 else 0.8))
            if i % every == 0:
                self.font(self.mono, 6.5, color=INK2)
                lbl = datetime.fromtimestamp(tk, timezone.utc).strftime("%H:%M")
                self.set_xy(X(tk) - 6, bar_y + bar_h + 2)
                self.cell(12, 3, lbl, align="C")
        for e in events:
            ts = datetime.fromisoformat(e["timestamp_utc"].replace("Z", "+00:00")).timestamp()
            big = e["severity"] in ("Critical", "High")
            self.set_draw_color(*SEV.get(e["severity"], SEV["Info"]))
            self.set_line_width(0.7 if big else 0.45)
            self.line(X(ts), bar_y - (9 if big else 5), X(ts), bar_y)


def _plain_lead(exec_summary: str) -> str:
    return (exec_summary or "").split(" Sequence (UTC):")[0]


def _story(findings: list[dict], limit=8, by_plain: bool = False) -> list[dict]:
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: f["first_seen"]):
        key = plain(f) if by_plain else f["title"]
        if key in seen or f["severity"] == "Info":
            continue
        seen.add(key)
        out.append(f)
    return out[:limit]


def write_pdf(ctx: dict, path: Path, report_hash: str, use_bundled_fonts: bool = True) -> None:
    case, summary = ctx["case"], ctx["summary"]
    pdf = ReportPDF(case, report_hash, use_bundled_fonts)
    verdict = summary.get("verdict", "Clean")
    score = int(summary.get("score") or 0)
    host = case.get("host") or "This machine"
    L, W = pdf.l_margin, pdf.epw

    # ================= page 1: at a glance =================================
    pdf.add_page()
    pdf.mark(L, 14, 9)
    pdf.set_xy(L + 12, 14.6)
    pdf.font(pdf.serif, 17, True)
    pdf.cell(60, 8, "ForenSight")
    pdf.set_xy(L, 13.5)
    pdf.font(pdf.sans, 7.5, True, INK2)
    pdf.cell(W, 4, "INCIDENT REPORT", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(L)
    pdf.font(pdf.mono, 8.5, color=INK)
    pdf.cell(W, 5, pdf.t(case["id"]), align="R")
    # evidence tape across the page
    tape_y = 29
    pdf.set_fill_color(*TAPE)
    pdf.rect(0, tape_y, pdf.w, 7, style="F")
    pdf.font(pdf.sans, 7, True, (255, 255, 255))
    stamp = pdf.t(f"EVIDENCE · DO NOT ALTER · {case['id']} · ")
    pdf.set_xy(0, tape_y + 1.4)
    pdf.cell(pdf.w, 4.2, (stamp * 8)[:400])
    # headline + lead
    pdf.set_xy(L, tape_y + 15)
    pdf.font(pdf.serif, 30, True)
    pdf.multi_cell(W, 12, pdf.t(HEADLINE.get(verdict, HEADLINE["Clean"]).format(h=host)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)
    pdf.font(pdf.serif, 12.5, color=INK)
    pdf.multi_cell(W, 6.2, pdf.t(VERDICT_MEANS.get(verdict, "") + " " + _plain_lead(ctx["exec_summary"]).split(". ", 1)[-1]),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    # score on its scale + severity counts
    y = pdf.get_y() + 7
    pdf.label("Compromise score", L, y)
    pdf.set_xy(L, y + 4.5)
    pdf.font(pdf.serif, 26, True, VERDICT.get(verdict, INK))
    pdf.cell(22, 11, str(score))
    pdf.font(pdf.sans, 9, color=INK2)
    pdf.set_xy(L + 21, y + 9.5)
    pdf.cell(30, 5, pdf.t(f"of 100 · {verdict}"))
    pdf.score_scale(L + 58, y + 6, 70, score)
    cx = L + 140
    pdf.label("Findings", cx, y)
    counts = ctx["sev_counts"]
    for i, k in enumerate(("Critical", "High", "Medium", "Low")):
        yy = y + 5 + i * 4.6
        pdf.swatch(k, cx, yy + 1)
        pdf.set_xy(cx + 4, yy)
        pdf.font(pdf.sans, 8.5, color=INK)
        pdf.cell(20, 4.6, k)
        pdf.font(pdf.sans, 8.5, True)
        pdf.cell(8, 4.6, str(counts.get(k, 0)), align="R")
    # the attack, measured
    y = pdf.get_y() + 12
    pdf.set_y(y)
    if summary.get("attack_start") and ctx["events"]:
        a = datetime.fromisoformat(summary["attack_start"].replace("Z", "+00:00"))
        b = datetime.fromisoformat(summary["attack_end"].replace("Z", "+00:00"))
        mins = int((b - a).total_seconds() // 60)
        secs = int((b - a).total_seconds() % 60)
        pdf.label("The attack, measured", L, y)
        pdf.set_x(L)
        pdf.font(pdf.sans, 9.5, color=INK)
        pdf.cell(0, 5, pdf.t(f"{mins} min {secs} s, from {a:%H:%M:%S} to {b:%H:%M:%S} UTC on {a:%d %b %Y}. "
                             "Each mark is an event; tall marks are High or Critical."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.time_scale(L, pdf.get_y() + 1, W, a, b, ctx["events"])
        pdf.set_y(pdf.get_y() + 17)
    # two columns: what happened / what to do now
    y = pdf.get_y() + 3
    colw = (W - 8) / 2
    story = _story(ctx["findings"], 6, by_plain=True)
    pdf.label("What happened, step by step", L, y)
    yy = pdf.get_y() + 1
    if not story:
        pdf.set_xy(L, yy)
        pdf.font(pdf.sans, 9.5, color=INK2)
        pdf.multi_cell(colw, 5, "No attacker activity was found in the collected evidence.")
        yy = pdf.get_y()
    for n, f in enumerate(story, 1):
        pdf.set_xy(L, yy)
        pdf.set_fill_color(*INK)
        pdf.ellipse(L, yy + 0.3, 4.6, 4.6, style="F")
        pdf.font(pdf.sans, 7.5, True, (255, 255, 255))
        pdf.set_xy(L, yy + 0.4)
        pdf.cell(4.6, 4.4, str(n), align="C")
        pdf.set_xy(L + 7, yy)
        pdf.font(pdf.sans, 9, True, INK)
        pdf.cell(colw - 7, 5, pdf.t(f"{f['first_seen'][11:16]}  {plain(f)}"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(L + 7)
        pdf.font(pdf.sans, 8.5, color=INK2)
        pdf.multi_cell(colw - 7, 4.3, pdf.t(f["title"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        yy = pdf.get_y() + 1.6
    left_bottom = yy
    rx = L + colw + 8
    pdf.label("What to do now", rx, y)
    yy = y + 5
    recs = ctx["recommendations"][:4] or ["No action needed beyond routine monitoring."]
    for n, r in enumerate(recs, 1):
        pdf.set_xy(rx, yy)
        pdf.font(pdf.serif, 12, True, TAPE)
        pdf.cell(6, 5, str(n))
        pdf.set_xy(rx + 6, yy + 0.3)
        pdf.font(pdf.sans, 9, color=INK)
        pdf.multi_cell(colw - 6, 4.5, pdf.t(r), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        yy = pdf.get_y() + 2
    # bottom: case label + verification QR
    by = max(left_bottom, yy) + 6
    by = max(by, pdf.h - 66)
    if by + 44 > pdf.h - 16:
        by = pdf.h - 60
    pdf.set_fill_color(*SHEET)
    pdf.set_draw_color(*RULE)
    pdf.set_line_width(0.3)
    pdf.rect(L, by, W, 42, style="DF", round_corners=True, corner_radius=2)
    pdf.set_draw_color(*INK2)
    pdf.ellipse(L + 4, by + 4, 3, 3)  # punched hole of the evidence label
    hi = case.get("host_info") or {}
    rows = [("Case", case.get("name")), ("Host", f"{host} ({case.get('os', '')})"),
            ("Investigator", case.get("investigator")), ("Case opened", (case.get("created_at") or "")[:19].replace("T", " ") + " UTC"),
            ("Report generated", ctx["generated_at"][:19].replace("T", " ") + " UTC")]
    qx = L + W - 36
    vw = (qx - 54) - (L + 10 + 28) - 3
    for i, (k, v) in enumerate(rows):
        pdf.set_xy(L + 10, by + 5 + i * 6.2)
        pdf.font(pdf.sans, 8, color=INK2)
        pdf.cell(28, 5, k)
        pdf.font(pdf.sans, 9, color=INK)
        val = pdf.t(v)
        while pdf.get_string_width(val) > vw and len(val) > 4:
            val = val[:-2]
        pdf.cell(vw, 5, val if val == pdf.t(v) else val.rstrip() + "…")
    pdf.image(io.BytesIO(base64.b64decode(ctx["qr"].split(",", 1)[1])), x=qx, y=by + 4, w=32)
    pdf.set_xy(qx - 52, by + 6)
    pdf.font(pdf.sans, 8.5, True, INK)
    pdf.multi_cell(50, 4.2, "Scan to verify this report", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_xy(qx - 52, pdf.get_y() + 0.5)
    pdf.font(pdf.sans, 7.5, color=INK2)
    pdf.multi_cell(50, 3.8, pdf.t("Signed with Ed25519. Editing a single byte breaks the signature. Key "
                                   f"{ctx['key_fingerprint'][:19]}"), align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ================= page 2: how to read + the story =====================
    pdf.add_page()
    pdf.section("How to read this report", "Pages 1 and 2 are written for anyone. The appendices are for the investigator.")
    pdf.set_fill_color(*SHEET)
    y0 = pdf.get_y()
    pdf.rect(L, y0, W, 38, style="F", round_corners=True, corner_radius=2)
    pdf.set_xy(L + 5, y0 + 4)
    pdf.font(pdf.sans, 7.5, True, INK2)
    pdf.cell(0, 4, "SEVERITY LEVELS", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    for i, (k, v) in enumerate(SEV_MEANS.items()):
        cy = y0 + 9.5 + i * 5.3
        pdf.swatch(k, L + 5, cy + 1.1)
        pdf.set_xy(L + 9, cy)
        pdf.font(pdf.sans, 9, True, SEV[k])
        pdf.cell(18, 5, k)
        pdf.font(pdf.sans, 9, color=INK)
        pdf.cell(60, 5, pdf.t(v))
    nx = L + W * 0.55
    pdf.set_xy(nx, y0 + 4)
    pdf.font(pdf.sans, 7.5, True, INK2)
    pdf.cell(0, 4, "THE VERDICT", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    for i, (k, v) in enumerate((("Compromised", "score 60-100: treat as breached"), ("Suspicious", "score 20-59: investigate"),
                                 ("Clean", "score 0-19: nothing matched"))):
        pdf.set_xy(nx, y0 + 9.5 + i * 5.3)
        pdf.font(pdf.sans, 9, True, VERDICT[k])
        pdf.cell(24, 5, k)
        pdf.font(pdf.sans, 9, color=INK)
        pdf.cell(W * 0.4, 5, v)
    pdf.set_xy(nx, y0 + 27)
    pdf.font(pdf.sans, 8, color=INK2)
    pdf.multi_cell(W * 0.42, 3.9, "Words like hash, IOC and ATT&CK are explained in the glossary on the last page.")
    pdf.set_y(y0 + 42)

    pdf.section("The attack, step by step", "Every finding in the order it happened, in plain words. Times are UTC.")
    full_story = _story(ctx["findings"], 14)
    if not full_story:
        pdf.font(pdf.sans, 10, color=INK2)
        pdf.multi_cell(0, 5, "No finding: nothing in the collected evidence matched known attacker behaviour.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    for n, f in enumerate(full_story, 1):
        pdf.need(20)
        y = pdf.get_y()
        pdf.font(pdf.mono, 9, True, INK)
        pdf.set_xy(L, y)
        pdf.cell(16, 5, f["first_seen"][11:19])
        pdf.set_draw_color(*RULE)
        pdf.set_line_width(0.4)
        pdf.set_fill_color(*SEV.get(f["severity"], SEV["Info"]))
        pdf.ellipse(L + 18, y + 1, 3, 3, style="F")
        pdf.set_xy(L + 25, y)
        pdf.font(pdf.sans, 10, True, INK)
        pdf.cell(0, 5, pdf.t(plain(f)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(L + 25)
        pdf.font(pdf.sans, 8.5, color=INK2)
        desc = f["description"] if len(f["description"]) < 120 else f["description"][:117] + "…"
        pdf.font(pdf.sans, 8.5, color=INK)
        pdf.multi_cell(W - 25, 4.3, pdf.t(f["title"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(L + 25)
        pdf.font(pdf.sans, 8, color=INK2)
        pdf.multi_cell(W - 25, 4.1, pdf.t(f"{desc}   {f['severity']} · {f['attck_id'] or 'no ATT&CK id'}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if n < len(full_story):
            pdf.set_draw_color(*RULE)
            pdf.line(L + 19.5, y + 4.5, L + 19.5, pdf.get_y() + 2.5)
        pdf.ln(2.5)

    pdf.section("What was examined")
    col = ctx["collection"] or {}
    eng = summary.get("engines") or {}
    pdf.table(["Item", "Detail"], [
        ["Evidence", f"{len(ctx['manifest'])} files, each SHA-256 fingerprinted and chained (see Appendix C)"],
        ["Collection", f"{col.get('profile') or '-'}: {', '.join((col.get('modules') or {}).keys()) or '-'}"],
        ["Events reviewed", f"{summary.get('records', 0)} raw records, {ctx['all_events']} on the timeline, {ctx['events_total']} notable"],
        ["Detection", f"{eng.get('custom_rules', 0)} ForenSight rules, {eng.get('sigma_rules', 0)} Sigma rules, YARA, "
                      f"{'Volatility 3 memory analysis' if eng.get('volatility') else 'no memory analysis'}, "
                      f"{'online' if eng.get('online_intel') else 'offline'} threat intel"],
        ["Time", "All times are UTC"],
    ], (34, W - 34))

    # ================= appendices ==========================================
    pdf.add_page()
    pdf.section("Appendix A. Timeline of notable events", "Every High, Medium and Low event, with the evidence source it came from.")
    pdf.table(["UTC", "Severity", "ATT&CK", "What happened", "Source"],
              [[e["timestamp_utc"][11:19], e["severity"], e.get("attck_id") or "", e["description"][:200],
                ", ".join(e.get("sources", [e["source"]])).replace(".evtx.jsonl", ".evtx")] for e in ctx["events"]] or [["", "", "", "No notable events", ""]],
              (15, 16, 18, W - 15 - 16 - 18 - 33, 33), mono_cols=(0, 2, 4), size=7.5, sev_col=1)

    pdf.section("Appendix B. Findings in detail", "Grouped by attacker goal. Each finding lists its evidence and the recommended response.")
    for tactic, fs in ctx["grouped"]:
        pdf.need(42)
        pdf.font(pdf.serif, 13, True)
        pdf.cell(0, 7, pdf.t(f"{tactic}  ·  {TACTIC_PLAIN.get(tactic, '')}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for f in fs:
            pdf.need(28)
            y = pdf.get_y() + 1
            pdf.set_xy(L, y)
            pdf.sev_word(f["severity"])
            pdf.font(pdf.sans, 10, True, INK)
            pdf.cell(0, 4.6, pdf.t(f["title"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.font(pdf.mono, 7.5, color=INK2)
            pdf.cell(0, 4, pdf.t(f"{f['attck_id']} {f['technique']}  ·  rule {f['rule_id'][:40]}  ·  confidence {round(f['confidence'] * 100)}%"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.font(pdf.sans, 9, color=INK)
            pdf.multi_cell(0, 4.5, pdf.t(f["description"][:420]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if f.get("pre_existing"):
                pdf.font(pdf.sans, 8, color=INK2)
                pdf.cell(0, 4, pdf.t(f"Already present in the clean baseline, so lowered from {f['original_severity']}."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            for ev in f["evidence"][:3]:
                pdf.font(pdf.mono, 6.8, color=INK2)
                pdf.multi_cell(0, 3.4, pdf.t("evidence  " + ev["ref"] + (f"   sha256 {ev['sha256'][:16]}…" if ev.get("sha256") else "")),
                               new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if f.get("playbook"):
                pdf.font(pdf.sans, 8.5, True, OK)
                pdf.cell(0, 4.5, "Recommended response", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for step in f["playbook"]:
                    pdf.font(pdf.sans, 8.5, color=INK)
                    pdf.set_x(L + 3)
                    pdf.multi_cell(W - 3, 4.2, pdf.t(f"–  {step}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_draw_color(*RULE)
            pdf.set_line_width(0.2)
            pdf.ln(1.5)
            pdf.line(L, pdf.get_y(), L + W, pdf.get_y())
            pdf.ln(1.5)

    # ATT&CK heatmap grid (same as the dashboard): active tactics as columns, darker = more findings
    matrix = ctx["matrix"]
    if matrix:
        pdf.section("MITRE ATT&CK map", "The public catalogue of attacker techniques. Darker cells carry more findings.")
        pdf.need(60)
        mx = max([t["count"] for c in matrix for t in c["techniques"]] or [1])
        colw2 = W / max(4, len(matrix))
        y0 = pdf.get_y()
        bottom = y0
        for i, c in enumerate(matrix):
            x = L + i * colw2
            pdf.set_xy(x, y0)
            pdf.font(pdf.sans, 8, True, INK)
            pdf.multi_cell(colw2 - 2, 3.8, pdf.t(c["tactic"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_draw_color(*INK)
            pdf.set_line_width(0.5)
            yy = y0 + 9
            pdf.line(x, yy - 1, x + colw2 - 2, yy - 1)
            for t in c["techniques"]:
                with pdf.local_context(fill_opacity=0.12 + 0.45 * t["count"] / mx):
                    pdf.set_fill_color(*TAPE)
                    pdf.rect(x, yy, colw2 - 2, 13, style="F", round_corners=True, corner_radius=1)
                pdf.set_xy(x + 1.5, yy + 1.2)
                pdf.font(pdf.mono, 7, True, INK)
                pdf.cell(colw2 - 5, 3.4, f"{t['id']}  {t['count']}x")
                pdf.set_xy(x + 1.5, yy + 4.8)
                pdf.font(pdf.sans, 7, color=INK)
                pdf.multi_cell(colw2 - 5, 3.2, pdf.t(t["name"][:48]))
                yy += 14.5
            bottom = max(bottom, yy)
        pdf.set_y(bottom + 2)

    pdf.add_page()
    pdf.section("Appendix C. Indicators of compromise", "Concrete clues to search for on other machines. Also exported as iocs.csv and iocs.stix.json (STIX 2.1).")
    pdf.table(["Type", "Value", "Severity", "Seen in"], [[i["type"].replace("_", " "), i["value"], i["severity"], i["context"]] for i in ctx["iocs"]]
              or [["-", "None", "", ""]], (24, 86, 18, W - 128), mono_cols=(1,), size=7.5, sev_col=2)

    pdf.section("Appendix D. Chain of custody", "Proof the evidence was not altered between collection and this report.")
    v = ctx["verify"]
    ok = v["ok"]
    y = pdf.get_y()
    pdf.set_fill_color(*((226, 238, 229) if ok else (246, 222, 218)))
    pdf.rect(L, y, W, 15, style="F", round_corners=True, corner_radius=2)
    pdf.set_xy(L + 4, y + 2.5)
    pdf.font(pdf.sans, 10, True, OK if ok else TAPE)
    pdf.cell(0, 5, pdf.t(f"Verified: all {v['total']} files match their fingerprints and the chain is intact." if ok else
                         f"Verification failed: {v['mismatches']} mismatches" + (f", chain broken at entry {v['first_break']}" if v.get("first_break") else "")),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(L + 4)
    pdf.font(pdf.mono, 7, color=INK2)
    pdf.cell(0, 4, pdf.t(f"checked {v['verified_at'][:19]} UTC · root {v['root_hash']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_y(y + 18)
    pdf.table(["#", "File", "Size", "SHA-256 fingerprint", "Collected (UTC)"],
              [[str(e["seq"]), e["path"], f"{e['size']:,}", e["sha256"], e["collected_at"][11:19]] for e in ctx["manifest"]],
              (7, 54, 14, W - 7 - 54 - 14 - 20, 20), mono_cols=(1, 3, 4), size=7)
    pdf.font(pdf.sans, 7.5, color=INK2)
    pdf.multi_cell(0, 3.8, pdf.t(f"entry_hash = SHA-256(previous entry_hash + file fingerprint + metadata). Signing key (Ed25519): {ctx['public_key']}"),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.section("Glossary", keep=75)
    for term, meaning in GLOSSARY:
        pdf.need(10)
        y = pdf.get_y()
        pdf.font(pdf.sans, 9, True, INK)
        pdf.set_xy(L, y)
        pdf.multi_cell(48, 4.6, pdf.t(term))
        y1 = pdf.get_y()
        pdf.set_xy(L + 50, y)
        pdf.font(pdf.sans, 9, color=INK)
        pdf.multi_cell(W - 50, 4.6, pdf.t(meaning), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_y(max(y1, pdf.get_y()) + 1.5)

    if ctx.get("ai_summary"):
        pdf.section("AI summary", ctx["ai_label"])
        pdf.font(pdf.serif, 11)
        pdf.multi_cell(0, 5.5, pdf.t(ctx["ai_summary"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.output(str(path))
