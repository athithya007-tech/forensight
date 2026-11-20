# Deploying ForenSight

ForenSight has two halves:

| Half | Needs | Why |
|---|---|---|
| **Engine** (collect, seal, analyze, report, verify, chat) | Python on a real computer | It reads the suspect machine's memory, logs and files, and signs evidence with a private key |
| **Dashboard** (the web pages) | Any web host | It only displays results |

So there are four ways to "deploy" it, depending on who you want to reach.

| Option | Who it's for | Full features? | Cost |
|---|---|---|---|
| [1. Your own computer](#1-your-own-computer-recommended) | Investigators, students, demos | Yes | Free |
| [2. GitHub Pages online demo](#2-github-pages-online-demo) | Anyone with the link (portfolio, judges, README) | Read-only | Free |
| [3. USB collector](#3-usb-collector-for-a-suspect-machine) | First responders | Collection only | Free |
| [4. A shared server](#4-a-shared-analysis-server-team-use) | A team in one lab | Yes | A VM |

---

## Can it run on GitHub Pages?

**Partly, by design.** GitHub Pages serves static files only: no Python, no database, no WebSocket. ForenSight's engine
has to run where the evidence is, and it should never be on the public internet anyway (evidence contains personal
data, and the signing key must stay private).

What GitHub Pages *can* host is the complete dashboard with four pre-analysed lab cases baked in. Visitors can open every
page, replay the attack, filter the timeline, explore the graph, verify the evidence, ask the suggested questions and
download the signed PDF. Buttons that would collect, analyze or generate are disabled with an "install it" message.

---

## 1. Your own computer (recommended)

See the [Quick start](../README.md#quick-start-5-minutes). In short:

```bash
pip install -e ".[analysis,dev]"
cd web && npm install && npm run build && cd ..
forensight doctor     # checks everything, including a real signed test report
forensight serve      # http://localhost:8080
```

After `git pull`, always run `pip install -e .` and restart `forensight serve`. If you forget, the dashboard shows a yellow
"server is running an older version" bar telling you exactly that.

---

## 2. GitHub Pages online demo

The repository already contains the workflow: `.github/workflows/pages.yml`. It runs the tests, builds the dashboard in
static mode, generates fresh demo cases (simulated data only) and publishes everything.

**One-time setup (2 minutes):**

1. Open the repository on GitHub → **Settings** → **Pages**.
2. Under **Build and deployment → Source**, choose **GitHub Actions**.
3. Go to the **Actions** tab, pick **Online demo (GitHub Pages)**, press **Run workflow** (or just push to `master`).
4. When it turns green (about 3 minutes), the demo is live at
   **`https://<your-username>.github.io/<repo-name>/`**, e.g. `https://athithya007-tech.github.io/forensight/`.

Every later push to `master` republishes it automatically.

**Build it yourself (to test locally or host elsewhere: Netlify, Vercel, Cloudflare Pages, any static host):**

```bash
cd web
PAGES_BASE=/forensight/ npm run build:pages     # → web/dist-pages   (PowerShell: $env:PAGES_BASE="/forensight/"; npm run build:pages)
cd ..
forensight export-site --out web/dist-pages      # adds demo-data/ (4 demo cases, about 1.5 MB)
```

`PAGES_BASE` is the URL path the site lives under: `/<repo-name>/` for GitHub Pages, `/` for a custom domain or Netlify.
`404.html` is a copy of `index.html`, so deep links such as `/forensight/cases/CASE-.../graph` work on GitHub Pages.

> If pushing the workflow file is rejected with *"refusing to allow ... without `workflow` scope"*, add the file through
> GitHub's web editor (Add file → Create new file → `.github/workflows/pages.yml`) or push with a token that has the
> `workflow` scope.

---

## 3. USB collector for a suspect machine

```bash
pip install -e ".[build]"
pyinstaller forensight-collector.spec    # → dist/forensight-collector(.exe), about 19 MB
```

Copy the executable (and optionally `tools/winpmem.exe` or `tools/avml`) to a USB drive. On the suspect machine, as
administrator: `forensight-collector collect --out E:\evidence`. Bring the drive back and run `forensight analyze`
on your own computer. Build on the same OS you will collect from (a Windows build for Windows targets).

---

## 4. A shared analysis server (team use)

Only inside a private lab network or behind a VPN. Never expose it to the internet: there is no login, and evidence
contains personal data.

```bash
forensight serve --host 0.0.0.0 --port 8080    # prints a warning on purpose
```

For a longer-lived setup, run it as a service (systemd, NSSM on Windows) and put a reverse proxy with authentication
in front (for example Caddy or nginx with basic auth and TLS). Keep `FORENSIGHT_CASES` on an encrypted disk.
Render, Railway or Fly.io *can* run the FastAPI server, but their disks are ephemeral and public by default, so they
suit a demo of the analysis pipeline, not real evidence.
