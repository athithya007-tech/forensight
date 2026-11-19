# ForenSight: automated incident response and forensics toolkit

ForenSight collects evidence from a suspected compromised Windows or Linux machine, analyzes it automatically and
produces a minute-by-minute attack timeline, an interactive dashboard and a signed PDF incident report.

```
collect ─► case folder (read-only evidence, SHA-256 hash chain) ─► analyze ─► correlate ─► dashboard · PDF · exports
```

## Quick start (no lab VM needed)

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[analysis,dev]"
cd web && npm install && npm run build && cd ..           # builds the dashboard into web/dist
forensight demo                                           # simulated 8-step lab attack → analyze → signed PDF
forensight serve                                          # http://localhost:8080
```

`forensight demo --steps 1,2,5,7` runs only the steps the judges pick. `--steps none` gives a clean host, and
`--linux` gives the SSH brute-force scenario. In the dashboard, the **Run the lab attack demo** panel does the same
thing and streams the collection live.

## Commands

| Command | What it does |
|---|---|
| `forensight new-case --name "Lab-Breach-01" --investigator "Asha"` | Creates `cases/CASE-YYYYMMDD-NNN/` with `case.json` and `audit.log` |
| `forensight collect --case <id> --out E:\evidence --profile full` | Collects in order of volatility. Every file is hashed, chained and made read-only. Profiles: `quick`, `full`, `custom --modules ...` |
| `forensight collect --baseline --case <id>` | Saves a clean snapshot for the "what changed?" diff |
| `forensight analyze --case <id> [--online]` | Runs Volatility 3, event-log rules, Sigma, YARA and threat intel, then the timeline, ATT&CK mapping, attack graph and score |
| `forensight report --case <id> [--ai]` | Writes a signed PDF and HTML report, IOCs as CSV and STIX 2.1, and the timeline as CSV/JSONL (Timesketch) |
| `forensight verify --case <id>` | Re-hashes everything, walks the hash chain and checks both signatures. Mismatches show in red |
| `forensight serve [--case <id>]` | Starts the dashboard on `localhost:8080` (bound to localhost by default) |
| `forensight metrics --case <id>` | Scores detection against `lab_truth.json` (PRD section 12) |
| `forensight cases` | Lists cases with their verdict and score |

Every command has `--help`.

## Measured results (demo case, this repo's test suite)

| PRD metric | Target | Result |
|---|---|---|
| Attack steps detected | 8 of 8 | **8/8**, including after step 8 wipes the Security log |
| False positives on a clean host | < 10 % | **0 findings** on the clean demo host and on a real Linux host |
| Timeline accuracy | within 1 s | **≤ 1.0 s** for every step |
| ATT&CK techniques covered by rules | ≥ 15 | **22** |
| Evidence integrity | 100 % verified | `verify` passes, and a 1-byte edit, a deleted entry or an edited entry all fail |
| Collector footprint | < 50 MB | **18.6 MB** single binary (PyInstaller, Linux x64) |
| End-to-end time | < 15 min | ~3 s on the demo case (excluding RAM capture and Volatility on a real 4 GB dump) |

Run `pytest` for the 27 tests: unit tests for every parser, rules, Sigma, hash chain, scoring, plus end-to-end and API tests.

## How detection survives anti-forensics

Step 8 of the lab attack clears the Security log, which erases the 4625/4624/4720/4732/4698 records left by steps 1–6.
Rules marked `fallback: true` in `rules/custom/resilience.yaml` recover those techniques from evidence the attacker
did not wipe:

- RDP logs (RdpCoreTS 140, LocalSessionManager 21/25)
- Sysmon and PowerShell 4104
- TaskScheduler 106
- live state and memory
- the baseline diff

Fallbacks are reported only when no primary rule found the same technique, so they never double-count.

## Repository layout (PRD 15.8)

```
collector/   collection modules (memory, live state, logs, artifacts), order of volatility, failure isolation
core/        case management, audit log, manifest hash chain, Ed25519 signing, SQLite schema, time handling
analyzer/    record loaders (EVTX, auth.log, histories, Volatility), rule engine, Sigma, YARA, intel,
             correlation (timeline, phases, graph, IOCs, diff, score), exports, metrics
rules/       custom/*.yaml (each with attck_id + playbook), sigma/*.yml, yara/*.yar, intel/*.txt
api/         FastAPI app (REST + WebSocket), report generator + template, chat (retrieval + Ollama), views
web/         React 18 + Vite + TypeScript dashboard: pages/ (one per route), components/, stores/, api/, theme/
demo/        lab-attack case generator (judges pick the steps)
lab/         attack.ps1 (-Steps), attacker.sh, linux_attack.sh, printable attack_menu.html, VM setup notes
tests/       pytest: parsers, rules, custody chain, end-to-end, API
cli.py       Typer entry point
forensight-collector.spec   PyInstaller build for the USB collector
```

## Adding a detection

Drop a YAML file into `rules/custom/`. No code change is needed.

```yaml
id: FS-WIN-100
title: Suspicious certutil download
kind: [evtx, process]          # record kinds: evtx, process, netconn, runkey, task, auth, shell, cron, yara, ...
attck_id: T1105
severity: High
confidence: 0.8
match:
  cmdline|re: "certutil.*-urlcache.*http"
description: "certutil download: {cmdline}"
playbook: [Block the URL at the proxy, Hash and analyse the downloaded file]
```

Operators are `|contains`, `|startswith`, `|endswith`, `|re`, `|gte`, `|lte`, `|exists` and `|in_file`, plus
`any:`, `all:` and `not:`. Rules can also use `threshold` with `followed_by` (brute-force style), `in_window`, a
`baseline` key (pre-existing findings are lowered one severity) and `dedupe`.

Sigma rules go in `rules/sigma/`. They run through Chainsaw when it is installed in `tools/`, otherwise through the
built-in evaluator. YARA rules go in `rules/yara/`.

## External tools (not bundled)

| Tool | Where | Used for |
|---|---|---|
| WinPmem / AVML / LiME | `tools/` next to the collector | RAM capture (skipped with a warning if absent) |
| Volatility 3 | analyst machine: `pip install volatility3` + symbol packs | Memory analysis (cached JSON in `analysis/volatility/` is used if present) |
| Chainsaw | `tools/chainsaw` + its `mappings/` | Optional, faster Sigma over EVTX |
| Ollama | analyst machine (`OLLAMA_HOST`, `FORENSIGHT_MODEL`, default `llama3.1:8b`) | Optional AI chat and summary. Without it, chat answers with cited evidence excerpts |

API keys come only from environment variables (`VT_API_KEY`, `ABUSEIPDB_API_KEY`). Only hashes and IPs are sent,
and only when you pass `--online`.

## Status and limits

- **Tested:** the full pipeline on the generated demo cases (Windows 8-step and Linux SSH), a real collection on Linux,
  the packaged Linux collector, and every dashboard page in Chromium at 1366×768 and phone width.
- **Not yet tested on real Windows.** The Windows collector code paths (`wevtutil epl`, `winreg`, `schtasks`, WinPmem)
  are written but have not run on a real Windows VM. Do that first in the lab (week 2 of the PRD plan).
- **Demo memory.** The demo case ships cached Volatility output instead of a 4 GB `memory.raw`.
- **Deviations from PRD section 15:**
  - SQLite through the standard library instead of SQLModel.
  - shadcn-style components are written by hand rather than generated.
  - The process tree is an indented, collapsible tree instead of a Cytoscape view, because it is easier to read with
    200+ processes.
- **Ethics.** Run only on machines you own or have written permission to investigate, and inside the host-only lab
  network. Case folders can hold personal data, so encrypt them and delete them after the project.
