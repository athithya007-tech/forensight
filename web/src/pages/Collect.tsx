import { CheckCircle2, Circle, Loader2, MinusCircle, Play, XCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { startCollect, useSummary } from "../api/client";
import type { ProgressEvent } from "../api/types";
import { Button, Card, Mono, PageHeader } from "../components/ui";

const ORDER = ["memory", "network", "processes", "users", "services", "tasks", "logs", "browser", "persistence", "programs", "files"];

/** Progress measured on the forensic scale: one segment per module, filled as each completes. */
function ModuleScale({ modules, states, pct, label }: { modules: string[]; states: Record<string, string>; pct: number; label: string }) {
  const fill = (st: string | undefined, i: number) => st === "done" ? (i % 2 ? "rgb(var(--ink-2))" : "rgb(var(--ink))")
    : st === "running" ? "rgb(var(--amber))" : st === "failed" ? "rgb(var(--sev-critical))"
    : st === "skipped" ? "repeating-linear-gradient(135deg, rgb(var(--rule)) 0 3px, rgb(var(--sheet)) 3px 6px)" : i % 2 ? "rgb(var(--sheet))" : "rgb(var(--well))";
  return (
    <div className="w-full">
      <div className="flex items-baseline justify-between mb-3">
        <span className="h-display text-5xl tnum">{Math.round(pct)}<span className="text-2xl text-ink-2">%</span></span>
        <span className="text-sm text-ink-2">{label}</span>
      </div>
      <div className="flex h-6 border border-ink rounded-[2px] overflow-hidden" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
        {(modules.length ? modules : ["…"]).map((m, i) => (
          <div key={m} title={`${m}: ${states[m] ?? "pending"}`} className="flex-1 border-r border-ink/50 last:border-r-0 transition-colors duration-300"
            style={{ background: fill(states[m], i) }} />
        ))}
      </div>
      <div className="flex justify-between mt-1.5 text-2xs text-ink-2"><span>RAM first</span><span>files last (RFC 3227 order of volatility)</span></div>
    </div>
  );
}

/** Live collection (US-019, FR-40): module checklist, progress on the forensic scale and the SHA-256 hash stream over WebSocket. */
export default function Collect() {
  const { id = "" } = useParams();
  const [evs, setEvs] = useState<ProgressEvent[]>([]);
  const [conn, setConn] = useState<"connecting" | "open" | "closed">("connecting");
  const qc = useQueryClient();
  const s = useSummary(id);
  const stream = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setEvs([]);
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/cases/${id}/progress`);
    ws.onopen = () => setConn("open");
    ws.onclose = () => setConn("closed");
    ws.onmessage = (m) => {
      const ev = JSON.parse(m.data) as ProgressEvent;
      setEvs((all) => (ev.module === "collect" && ev.status === "start" ? [ev] : [...all, ev]));
      if (ev.module === "analyze:done") qc.invalidateQueries();
    };
    return () => ws.close();
  }, [id, qc]);
  useEffect(() => { stream.current?.scrollTo({ top: stream.current.scrollHeight }); }, [evs]);

  const state = useMemo(() => {
    const mods: Record<string, { status: string; message?: string; files: number }> = {};
    let pct = 0, apct = 0, done = false, analyzed = false, failure: string | null = null;
    for (const e of evs) {
      if (e.module === "collect") {
        if (e.pct != null) pct = e.pct;
        if (e.status === "complete") done = true;
        if (e.status === "failed") failure = e.message ?? "Collection stopped";
        continue;
      }
      if (e.module.startsWith("analyze:")) { if (e.pct != null) apct = e.pct; if (e.status === "complete") analyzed = true; continue; }
      const m = (mods[e.module] ??= { status: "pending", files: 0 });
      if (e.status === "file") { m.files++; if (m.status === "pending") m.status = "running"; }
      else if (!(m.status === "skipped" && e.status === "done")) { m.status = e.status; if (e.message) m.message = e.message; }
      if (e.pct != null && e.status !== "file") pct = Math.max(pct, e.pct);
    }
    if (done) Object.values(mods).forEach((m) => { if (m.status === "running" || m.status === "pending") m.status = "done"; });
    // a module that only reported files (baseline, snapshot) is finished once the next module starts
    const order = Object.keys(mods);
    order.forEach((k, i) => { if (mods[k].status === "running" && mods[k].files && i < order.length - 1) mods[k].status = "done"; });
    if (failure) Object.values(mods).forEach((m) => { if (m.status === "running" || m.status === "pending") m.status = "failed"; });
    return { mods, pct: done ? 100 : pct, done, apct, analyzed, failure };
  }, [evs]);
  const files = evs.filter((e) => e.status === "file");
  const modules = ORDER.filter((m) => state.mods[m]).concat(Object.keys(state.mods).filter((m) => !ORDER.includes(m)));
  const icon = (st: string) => st === "done" ? <CheckCircle2 size={16} className="text-ok" /> : st === "failed" ? <XCircle size={16} className="text-critical" />
    : st === "skipped" ? <MinusCircle size={16} className="text-ink-2" /> : st === "running" ? <Loader2 size={16} className="text-amber animate-spin" /> : <Circle size={16} className="text-rule" />;

  return (
    <div className="space-y-4">
      <PageHeader title="Live collection" subtitle={<>Modules run in order of volatility, and every file is hashed the moment it is written. Live link: {conn === "open" ? "connected" : conn}.</>}
        actions={<>
          {!evs.length && <Button onClick={() => startCollect(id, "quick")} title="Collect from the machine running ForenSight (lab use)"><Play size={14} />Collect this machine (quick)</Button>}
          {state.analyzed && <Link to={`/cases/${id}/story`}><Button variant="primary"><Play size={14} />Watch the attack story</Button></Link>}
        </>} />
      {state.failure && (
        <div role="alert" className="mb-4 rounded-lg border border-critical/40 bg-critical/5 px-4 py-3 text-sm">
          <div className="font-semibold text-ink">Collection stopped: {state.failure}</div>
          <div className="text-ink-2 mt-0.5">Evidence written so far is hashed and kept. The full error is in this case's audit.log.</div>
        </div>
      )}
      <div className="grid lg:grid-cols-3 gap-4">
        <Card title="Modules">
          {!modules.length ? <div className="text-ink-2 text-sm">Waiting for the collector… Start one with <Mono>forensight collect --case {id}</Mono> or run the demo from the case list.</div> : (
            <ul className="space-y-1.5">{modules.map((m) => (
              <li key={m} className="flex items-center gap-2 text-sm">{icon(state.mods[m].status)}<span className="flex-1 capitalize">{m}</span>
                <span className="text-xs text-ink-2 truncate max-w-[55%] text-right" title={state.mods[m].message}>{state.mods[m].files ? `${state.mods[m].files} file${state.mods[m].files > 1 ? "s" : ""}` : state.mods[m].status === "skipped" ? "skipped" : ""}</span></li>))}</ul>
          )}
        </Card>
        <Card bodyClass="flex flex-col items-start justify-center gap-4 py-8">
          <ModuleScale modules={modules} states={Object.fromEntries(modules.map((m) => [m, state.mods[m].status]))}
            pct={state.done && state.apct ? state.apct : state.pct}
            label={state.failure ? "Collection stopped" : state.analyzed ? "Analysis complete" : state.done ? (state.apct ? "Analyzing the evidence" : "Collection complete") : evs.length ? "Collecting in order of volatility" : "Waiting for a collector"} />
          <div className="text-sm text-ink-2 w-full">{files.length} artifacts hashed into the custody chain</div>
          {state.analyzed && s.data && <div className="w-full font-serif text-lg">Verdict: <b>{s.data.verdict}</b>, score {s.data.score} of 100.</div>}
        </Card>
        <Card title="Hash stream" bodyClass="p-0">
          <div ref={stream} className="h-[380px] overflow-auto p-3 font-mono text-xs space-y-1">
            {files.map((f, i) => (
              <div key={i} className="rise"><span className="text-ink">{f.file?.replace(/^raw\//, "")}</span> <span className="text-ink-2">→</span> <span className={f.file?.startsWith("quarantined:") ? "text-high" : "text-ok"}>{f.sha256?.slice(0, 24)}…</span></div>
            ))}
            {!files.length && <div className="text-ink-2">No files yet.</div>}
          </div>
        </Card>
      </div>
    </div>
  );
}
