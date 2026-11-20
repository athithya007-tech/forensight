import { ArrowRight, Maximize2, X } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useEvents, useGraph } from "../api/client";
import type { Graph, GraphNode } from "../api/types";
import { AttackGraph, EDGE_WORDS, Legend, NODE_STYLE } from "../components/AttackGraph";
import { EvidenceChip } from "../components/EvidenceChip";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Empty, ErrorState, Loading, Mono, PageHeader } from "../components/ui";

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

export default function GraphPage() {
  const { id = "" } = useParams();
  const g = useGraph(id);
  const [sel, setSel] = useState<GraphNode | null>(null);
  const [layout, setLayout] = useState<"dagre" | "cose">("dagre");
  if (g.isLoading) return <Loading />;
  if (g.error) return <ErrorState error={g.error} />;
  const { nodes, edges } = g.data!;
  return (
    <div className="flex flex-col h-[calc(100vh-7rem)] min-h-[560px]">
      <PageHeader title="Attack graph" subtitle={`${nodes.length} entities joined by ${edges.length} relationships. Hover a node to isolate its neighbours; click it for the evidence.`}
        actions={<Button onClick={() => setLayout(layout === "dagre" ? "cose" : "dagre")}><Maximize2 size={13} />{layout === "dagre" ? "Organic layout" : "Left-to-right layout"}</Button>} />
      {!nodes.length ? <Empty title="No linked entities" hint="The analyzer found no IPs, accounts, processes or files that connect to each other in this case." /> : (
        <div className="flex-1 flex flex-col lg:flex-row gap-4 min-h-0">
          <div className="flex-1 flex flex-col bg-sheet border border-rule rounded-lg shadow-sheet overflow-hidden min-h-[400px]">
            <div className="px-4 py-2.5 border-b border-rule"><Legend /></div>
            <div className="flex-1 min-h-0"><AttackGraph nodes={nodes} edges={edges} onSelect={setSel} highlightId={sel?.id} layout={layout} /></div>
          </div>
          {sel && <NodeDetailPanel node={sel} graph={g.data!} onClose={() => setSel(null)} onPick={setSel} />}
        </div>
      )}
    </div>
  );
}
