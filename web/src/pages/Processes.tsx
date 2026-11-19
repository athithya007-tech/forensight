import { ChevronDown, ChevronRight, EyeOff, X } from "lucide-react";
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useProcesses } from "../api/client";
import type { Proc } from "../api/types";
import { EvidenceChip } from "../components/EvidenceChip";
import { SEV_COLOR, SeverityBadge } from "../components/SeverityBadge";
import { Card, Empty, ErrorState, Loading, Mono, PageHeader, cx, fmtDateTime } from "../components/ui";

const hasFlag = (p: Proc): boolean => p.flagged || p.children.some(hasFlag);

function Row({ p, depth, sel, onSel, flaggedOnly, open, toggle }:
  { p: Proc; depth: number; sel?: Proc | null; onSel: (p: Proc) => void; flaggedOnly: boolean; open: Set<number>; toggle: (pid: number) => void }) {
  const kids = flaggedOnly ? p.children.filter(hasFlag) : p.children;
  const isOpen = open.has(p.pid);
  const c = p.flagged ? SEV_COLOR[p.severity === "Info" ? "High" : p.severity] : undefined;
  return (
    <>
      <div onClick={() => onSel(p)} style={{ paddingLeft: depth * 18 + 8 }}
        className={cx("flex items-center gap-2 py-1 pr-3 cursor-pointer rounded text-[13px]", sel?.pid === p.pid ? "bg-accent/15" : "hover:bg-surface2")}>
        <button className="w-4 text-muted" onClick={(e) => { e.stopPropagation(); toggle(p.pid); }} aria-label="Expand">
          {kids.length ? (isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />) : null}
        </button>
        <span className={cx("font-medium", p.exited && "line-through opacity-60")} style={{ color: c }}>{p.name}</span>
        <Mono className="text-muted">{p.pid}</Mono>
        {p.hidden && <span className="inline-flex items-center gap-1 text-[11px] text-critical"><EyeOff size={12} />hidden</span>}
        {p.flagged && <SeverityBadge severity={p.severity === "Info" ? "High" : p.severity} />}
        <span className="text-muted text-[12px] truncate flex-1">{p.cmdline}</span>
        <span className="text-[11px] text-muted hidden md:inline">{p.sources.join("+")}</span>
      </div>
      {isOpen && kids.map((k) => <Row key={k.pid} p={k} depth={depth + 1} sel={sel} onSel={onSel} flaggedOnly={flaggedOnly} open={open} toggle={toggle} />)}
    </>
  );
}

export default function ProcessesPage() {
  const { id = "" } = useParams();
  const q = useProcesses(id);
  const [sel, setSel] = useState<Proc | null>(null);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const all = useMemo(() => { const out: Proc[] = []; const walk = (p: Proc) => { out.push(p); p.children.forEach(walk); }; q.data?.roots.forEach(walk); return out; }, [q.data]);
  const [open, setOpen] = useState<Set<number> | null>(null);
  const openSet = open ?? new Set(all.map((p) => p.pid));
  const toggle = (pid: number) => { const n = new Set(openSet); n.has(pid) ? n.delete(pid) : n.add(pid); setOpen(n); };
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const roots = flaggedOnly ? q.data!.roots.filter(hasFlag) : q.data!.roots;
  return (
    <div>
      <PageHeader title="Process tree" subtitle={`${q.data!.count} processes from live collection and memory · ${q.data!.flagged} flagged (red)`}
        actions={<label className="inline-flex items-center gap-2 text-[13px] text-muted"><input type="checkbox" checked={flaggedOnly} onChange={(e) => setFlaggedOnly(e.target.checked)} className="accent-[#22D3EE]" />Flagged branches only</label>} />
      {!all.length ? <Card><Empty title="No process data" hint="This case has no processes.json or Volatility pslist output." /></Card> : (
        <div className="flex flex-col lg:flex-row gap-4">
          <Card className="flex-1" bodyClass="p-2 max-h-[calc(100vh-12rem)] overflow-auto">
            {roots.map((p) => <Row key={p.pid} p={p} depth={0} sel={sel} onSel={setSel} flaggedOnly={flaggedOnly} open={openSet} toggle={toggle} />)}
          </Card>
          {sel && (
            <aside className="w-full lg:w-[400px] shrink-0 bg-surface border border-border rounded-lg p-4 space-y-3 text-[13px] self-start">
              <div className="flex items-start justify-between"><div><div className="font-semibold text-base">{sel.name}</div><Mono className="text-muted">PID {sel.pid} · PPID {sel.ppid}</Mono></div>
                <button onClick={() => setSel(null)} className="text-muted hover:text-text" aria-label="Close"><X size={18} /></button></div>
              {sel.flagged && <div className="rounded-md border border-critical/40 bg-critical/10 p-2.5 space-y-1">{sel.reasons.map((r, i) => <div key={i}>⚠ {r}</div>)}</div>}
              <div><div className="text-muted text-[12px]">Command line</div><pre className="font-mono text-[12px] whitespace-pre-wrap break-all bg-bg border border-border rounded p-2 mt-1">{sel.cmdline || "—"}</pre></div>
              {[["Path", sel.path], ["User", sel.user], ["Started", fmtDateTime(sel.start_time)], ["Exited", sel.exited && fmtDateTime(sel.exited)], ["SHA-256", sel.sha256], ["Seen in", sel.sources.join(", ")]]
                .filter(([, v]) => v).map(([k, v]) => <div key={k as string} className="flex justify-between gap-3"><span className="text-muted shrink-0">{k}</span><Mono className="text-right">{v}</Mono></div>)}
              <EvidenceChip evidenceRef={sel.evidence_ref} />
            </aside>
          )}
        </div>
      )}
    </div>
  );
}
