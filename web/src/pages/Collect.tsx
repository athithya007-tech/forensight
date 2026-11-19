import { CheckCircle2, Circle, Loader2, MinusCircle, Play, XCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { startCollect, useSummary } from "../api/client";
import type { ProgressEvent } from "../api/types";
import { Button, Card, Mono, PageHeader } from "../components/ui";

const ORDER = ["memory", "network", "processes", "users", "services", "tasks", "logs", "browser", "persistence", "programs", "files"];

function ProgressRing({ pct, label }: { pct: number; label: string }) {
  const r = 70, c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 180 180" className="w-56 h-56">
      <circle cx="90" cy="90" r={r} stroke="rgb(var(--border))" strokeWidth="12" fill="none" />
      <circle cx="90" cy="90" r={r} stroke="rgb(var(--accent))" strokeWidth="12" fill="none" strokeLinecap="round" strokeDasharray={c}
        strokeDashoffset={c * (1 - pct / 100)} transform="rotate(-90 90 90)" style={{ transition: "stroke-dashoffset .4s" }} />
      <text x="90" y="92" textAnchor="middle" fontSize="34" fontWeight="800" fill="rgb(var(--text))">{Math.round(pct)}%</text>
      <text x="90" y="116" textAnchor="middle" fontSize="11" fill="rgb(var(--muted))">{label}</text>
    </svg>
  );
}

/** Live collection (US-019, FR-40): module checklist, progress ring and SHA-256 hash stream over WebSocket. */
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
    let pct = 0, apct = 0, done = false, analyzed = false;
    for (const e of evs) {
      if (e.module === "collect") { if (e.pct != null) pct = e.pct; if (e.status === "complete") done = true; continue; }
      if (e.module.startsWith("analyze:")) { if (e.pct != null) apct = e.pct; if (e.status === "complete") analyzed = true; continue; }
      const m = (mods[e.module] ??= { status: "pending", files: 0 });
      if (e.status === "file") { m.files++; if (m.status === "pending") m.status = "running"; }
      else if (!(m.status === "skipped" && e.status === "done")) { m.status = e.status; if (e.message) m.message = e.message; }
      if (e.pct != null && e.status !== "file") pct = Math.max(pct, e.pct);
    }
    if (done) Object.values(mods).forEach((m) => { if (m.status === "running" || m.status === "pending") m.status = "done"; });
    return { mods, pct: done ? 100 : pct, done, apct, analyzed };
  }, [evs]);
  const files = evs.filter((e) => e.status === "file");
  const modules = ORDER.filter((m) => state.mods[m]).concat(Object.keys(state.mods).filter((m) => !ORDER.includes(m)));
  const icon = (st: string) => st === "done" ? <CheckCircle2 size={16} className="text-ok" /> : st === "failed" ? <XCircle size={16} className="text-critical" />
    : st === "skipped" ? <MinusCircle size={16} className="text-medium" /> : st === "running" ? <Loader2 size={16} className="text-accent animate-spin" /> : <Circle size={16} className="text-muted" />;

  return (
    <div className="space-y-4">
      <PageHeader title="Live collection" subtitle={<>Order of volatility (RFC 3227) · WebSocket {conn} · every file hashed as it is written</>}
        actions={<>
          {!evs.length && <Button onClick={() => startCollect(id, "quick")} title="Collect from the machine running ForenSight (lab use)"><Play size={14} />Collect this machine (quick)</Button>}
          {state.analyzed && <Link to={`/cases/${id}/story`}><Button variant="primary"><Play size={14} />Watch the attack story</Button></Link>}
        </>} />
      <div className="grid lg:grid-cols-3 gap-4">
        <Card title="Modules">
          {!modules.length ? <div className="text-muted text-[13px]">Waiting for the collector… Start one with <Mono>forensight collect --case {id}</Mono> or run the demo from the case list.</div> : (
            <ul className="space-y-1.5">{modules.map((m) => (
              <li key={m} className="flex items-center gap-2 text-[13.5px]">{icon(state.mods[m].status)}<span className="flex-1 capitalize">{m}</span>
                <span className="text-[12px] text-muted">{state.mods[m].files ? `${state.mods[m].files} files` : state.mods[m].message?.slice(0, 40) ?? ""}</span></li>))}</ul>
          )}
        </Card>
        <Card bodyClass="flex flex-col items-center justify-center gap-3 py-8">
          <ProgressRing pct={state.done && state.apct ? state.apct : state.pct} label={state.analyzed ? "analysis complete" : state.done ? (state.apct ? "analyzing…" : "collection complete") : "collecting"} />
          <div className="text-[13px] text-muted">{files.length} artifacts hashed</div>
          {state.analyzed && s.data && <div className="text-[14px]">Verdict: <b>{s.data.verdict}</b> · score {s.data.score}</div>}
        </Card>
        <Card title="Hash stream" bodyClass="p-0">
          <div ref={stream} className="h-[380px] overflow-auto p-3 font-mono text-[11.5px] space-y-1">
            {files.map((f, i) => (
              <div key={i} className="slide-in"><span className="text-text">{f.file?.replace(/^raw\//, "")}</span> <span className="text-muted">→</span> <span className="text-ok">{f.sha256?.slice(0, 24)}…</span></div>
            ))}
            {!files.length && <div className="text-muted">No files yet.</div>}
          </div>
        </Card>
      </div>
    </div>
  );
}
