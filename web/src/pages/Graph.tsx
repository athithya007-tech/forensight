import type { Core } from "cytoscape";
import { ArrowRight, ImageDown, Maximize2, Minus, Pause, Play, Plus, Search, SkipBack, SkipForward, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useEvents, useGraph } from "../api/client";
import type { Graph, GraphEdge, GraphNode } from "../api/types";
import { AttackGraph, EDGE_WORDS, EdgeLegend, Legend, NODE_STYLE, type GraphLayout } from "../components/AttackGraph";
import { EvidenceChip } from "../components/EvidenceChip";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Empty, ErrorState, Loading, Mono, PageHeader, cx } from "../components/ui";

/** Node detail: relationships are explained here, not as edge labels on the canvas (flowchart skill). */
function NodeDetailPanel({ node, graph, onClose, onPick }: { node: GraphNode; graph: Graph; onClose: () => void; onPick: (n: GraphNode) => void }) {
  const { id = "" } = useParams();
  const ev = useEvents(id);
  const evs = (ev.data?.items ?? []).filter((e) => node.event_ids.includes(e.id));
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const rels = graph.edges.filter((e) => e.source === node.id || e.target === node.id);
  return (
    <aside className="w-full lg:w-[380px] shrink-0 bg-sheet border border-rule rounded-lg shadow-sheet flex flex-col max-h-full min-h-0 rise">
      <header className="flex items-start justify-between gap-2 px-5 pt-4 pb-3 border-b border-rule">
        <div className="min-w-0">
          <div className="text-xs text-ink-2">{NODE_STYLE[node.type]?.label ?? node.type}</div>
          <div className="h-display text-xl break-all leading-snug">{node.label}</div>
          {node.value !== node.label && <Mono className="text-ink-2">{node.value}</Mono>}
          <div className="mt-1.5"><SeverityBadge severity={node.severity} /></div>
        </div>
        <button onClick={onClose} className="text-ink-2 hover:text-ink p-1" aria-label="Close details"><X size={18} /></button>
      </header>
      <div className="px-5 py-4 overflow-auto space-y-5">
        {rels.length > 0 && (
          <section>
            <h3 className="text-sm font-semibold mb-2">Relationships</h3>
            <ul className="space-y-1.5 text-sm">
              {rels.map((r) => {
                const out = r.source === node.id, other = byId.get(out ? r.target : r.source);
                return (
                  <li key={r.id} className="flex items-center gap-1.5 flex-wrap">
                    {!out && other && <button onClick={() => onPick(other)} className="underline decoration-rule hover:decoration-ink">{other.label}</button>}
                    {!out && <ArrowRight size={12} className="text-ink-2" />}
                    <span className="text-ink-2">{EDGE_WORDS[r.type] ?? r.type}</span>
                    {out && <ArrowRight size={12} className="text-ink-2" />}
                    {out && other && <button onClick={() => onPick(other)} className="underline decoration-rule hover:decoration-ink">{other.label}</button>}
                    <Mono className="text-ink-2 ml-auto">{r.ts.slice(11, 19)}</Mono>
                  </li>
                );
              })}
            </ul>
          </section>
        )}
        <section>
          <h3 className="text-sm font-semibold mb-2">{evs.length} related event{evs.length === 1 ? "" : "s"}</h3>
          <ol className="space-y-3">
            {evs.map((e) => (
              <li key={e.id} className="space-y-1">
                <div className="flex items-center gap-2"><Mono className="text-ink-2">{e.timestamp_utc.slice(11, 19)}</Mono><SeverityBadge severity={e.severity} /></div>
                <div className="text-sm break-words">{e.description}</div>
                <EvidenceChip evidenceRef={e.evidence_ref} />
              </li>
            ))}
          </ol>
        </section>
      </div>
    </aside>
  );
}

const LAYOUTS: [GraphLayout, string, string][] = [
  ["lanes", "Story lanes", "Who got in → what ran → what stayed behind"],
  ["dagre", "Flow", "Left-to-right by relationship"],
  ["cose", "Organic", "Clusters pull together"],
];

function IconBtn({ label, onClick, children, disabled }: { label: string; onClick: () => void; children: React.ReactNode; disabled?: boolean }) {
  return (
    <button onClick={onClick} disabled={disabled} aria-label={label} title={label}
      className="grid place-items-center w-8 h-8 text-ink-2 hover:text-ink hover:bg-well disabled:opacity-40 transition-colors">{children}</button>
  );
}

export default function GraphPage() {
  const { id = "" } = useParams();
  const g = useGraph(id);
  const [sel, setSel] = useState<GraphNode | null>(null);
  const [layout, setLayout] = useState<GraphLayout>("lanes");
  const [query, setQuery] = useState("");
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [step, setStep] = useState<number | null>(null);   // replay position: index into time-ordered edges
  const [playing, setPlaying] = useState(false);
  const cyRef = useRef<Core | null>(null);
  const order = useMemo(() => [...(g.data?.edges ?? [])].sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : a.id - b.id)), [g.data]);
  const counts = useMemo(() => (g.data?.nodes ?? []).reduce<Record<string, number>>((m, n) => ((m[n.type] = (m[n.type] ?? 0) + 1), m), {}), [g.data]);
  const byId = useMemo(() => new Map((g.data?.nodes ?? []).map((n) => [n.id, n])), [g.data]);

  useEffect(() => {
    if (!playing) return;
    const t = setTimeout(() => {
      if (step == null || step < order.length - 1) setStep((s) => (s == null ? 0 : s + 1));
      else setPlaying(false);
    }, step == null ? 200 : 1100);
    return () => clearTimeout(t);
  }, [playing, step, order.length]);

  const onReady = useCallback((c: Core | null) => { cyRef.current = c; }, []);
  const zoomBy = (f: number) => { const c = cyRef.current; if (!c) return; c.animate({ zoom: { level: c.zoom() * f, position: { x: c.width() / 2, y: c.height() / 2 } as any } } as any, { duration: 180 }); };
  const zoomTo = (eles?: any) => cyRef.current?.animate({ fit: { eles: eles ?? cyRef.current.elements(), padding: 40 } } as any, { duration: 300 });
  const findIt = () => { const m = cyRef.current?.nodes(".match"); if (m?.nonempty()) zoomTo(m.closedNeighborhood()); };
  const exportPng = () => {
    const c = cyRef.current; if (!c) return;
    const bg = getComputedStyle(document.documentElement).getPropertyValue("--sheet").trim().split(" ").join(",");
    const a = document.createElement("a");
    a.href = c.png({ full: true, scale: 2, bg: `rgb(${bg})` } as any);
    a.download = `${id}-attack-graph.png`; a.click();
  };

  if (g.isLoading) return <Loading />;
  if (g.error) return <ErrorState error={g.error} />;
  const { nodes, edges } = g.data!;
  const live = step != null ? order[step] : null;
  const matches = query.trim() ? nodes.filter((n) => `${n.label} ${n.value}`.toLowerCase().includes(query.trim().toLowerCase())).length : 0;
  const say = (e: GraphEdge) => `${byId.get(e.source)?.label ?? e.source} ${EDGE_WORDS[e.type] ?? e.type} ${byId.get(e.target)?.label ?? e.target}`;
  return (
    <div className="flex flex-col h-[calc(100vh-7rem)] min-h-[600px]">
      <PageHeader title="Attack graph" subtitle={`${nodes.length} things the attack touched, joined by ${edges.length} relationships. Hover to isolate, click to trace the whole chain and see the evidence, double-click to zoom in.`}
        actions={
          <div role="radiogroup" aria-label="Layout" className="inline-flex rounded border border-rule bg-sheet p-0.5">
            {LAYOUTS.map(([k, label, hint]) => (
              <button key={k} role="radio" aria-checked={layout === k} title={hint} onClick={() => setLayout(k)}
                className={cx("px-3 h-7 text-sm rounded-[3px] transition-colors", layout === k ? "bg-ink text-paper" : "text-ink-2 hover:text-ink")}>{label}</button>
            ))}
          </div>} />
      {!nodes.length ? <Empty title="No linked entities" hint="The analyzer found no IPs, accounts, processes or files that connect to each other in this case." /> : (
        <div className="flex-1 flex flex-col lg:flex-row gap-4 min-h-0">
          <div className="flex-1 flex flex-col bg-sheet border border-rule rounded-lg shadow-sheet overflow-hidden min-h-[440px]">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 border-b border-rule">
              <label className="relative flex items-center">
                <Search size={14} className="absolute left-2.5 text-ink-2 pointer-events-none" />
                <input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && findIt()}
                  placeholder="Find a process, file, IP…" aria-label="Find in graph"
                  className="h-8 w-56 rounded border border-rule bg-paper pl-8 pr-14 text-sm placeholder:text-ink-2/70 focus:border-ink outline-none" />
                {query && <span className="absolute right-2 text-xs text-ink-2 tnum">{matches} found</span>}
              </label>
              <Legend counts={counts} hidden={hidden} onToggle={(t) => setHidden((h) => { const n = new Set(h); n.has(t) ? n.delete(t) : n.add(t); return n; })} />
            </div>
            <div className="px-4 py-1.5 border-b border-rule bg-paper/60"><EdgeLegend /></div>
            <div className="relative flex-1 min-h-0">
              <AttackGraph nodes={nodes} edges={edges} onSelect={setSel} highlightId={sel?.id} layout={layout} onReady={onReady}
                query={query} hiddenTypes={hidden} cutoff={live?.ts ?? null} liveEdgeId={live?.id ?? null} />
              <div className="absolute right-3 top-3 flex flex-col rounded border border-rule bg-sheet/95 shadow-sheet divide-y divide-rule overflow-hidden">
                <IconBtn label="Zoom in" onClick={() => zoomBy(1.3)}><Plus size={15} /></IconBtn>
                <IconBtn label="Zoom out" onClick={() => zoomBy(1 / 1.3)}><Minus size={15} /></IconBtn>
                <IconBtn label="Fit everything" onClick={() => zoomTo()}><Maximize2 size={14} /></IconBtn>
                <IconBtn label="Save as image (PNG)" onClick={exportPng}><ImageDown size={15} /></IconBtn>
              </div>
            </div>
            {/* replay: the attack re-drawn one relationship at a time, in the order it happened */}
            <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 border-t border-rule bg-paper/60">
              <Button variant={playing ? undefined : "primary"} onClick={() => { if (!playing && step != null && step >= order.length - 1) setStep(null); setPlaying(!playing); }}>
                {playing ? <Pause size={14} /> : <Play size={14} />}{playing ? "Pause" : step == null ? "Replay the attack" : "Resume"}
              </Button>
              <div className="flex items-center">
                <IconBtn label="Previous step" disabled={!order.length} onClick={() => { setPlaying(false); setStep((s) => (s == null ? order.length - 1 : Math.max(0, s - 1))); }}><SkipBack size={14} /></IconBtn>
                <IconBtn label="Next step" disabled={!order.length} onClick={() => { setPlaying(false); setStep((s) => (s == null ? 0 : Math.min(order.length - 1, s + 1))); }}><SkipForward size={14} /></IconBtn>
              </div>
              <input type="range" min={0} max={Math.max(0, order.length - 1)} value={step ?? order.length - 1} aria-label="Replay position"
                onChange={(e) => { setPlaying(false); setStep(+e.target.value); }} className="flex-1 min-w-[140px] accent-[rgb(var(--tape))]" />
              <div className="min-w-0 basis-full xl:basis-[360px] text-sm" aria-live="polite">
                {live ? <><Mono className="text-ink-2 mr-2">{live.ts.slice(11, 19)} UTC</Mono><span className="text-ink-2 tnum mr-1.5">{step! + 1}/{order.length}</span>{say(live)}</>
                  : <span className="text-ink-2">Showing everything. Press replay to watch the attack unfold step by step.</span>}
              </div>
              {step != null && <button className="text-sm text-ink-2 underline decoration-rule hover:text-ink" onClick={() => { setPlaying(false); setStep(null); }}>Show all</button>}
            </div>
          </div>
          {sel && <NodeDetailPanel node={sel} graph={g.data!} onClose={() => setSel(null)} onPick={setSel} />}
        </div>
      )}
    </div>
  );
}
