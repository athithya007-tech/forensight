import { X } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useEvents, useGraph } from "../api/client";
import type { GraphNode } from "../api/types";
import { AttackGraph, Legend, NODE_STYLE } from "../components/AttackGraph";
import { EvidenceChip } from "../components/EvidenceChip";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Card, Empty, ErrorState, Loading, Mono, PageHeader } from "../components/ui";

function NodeDetailPanel({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  const { id = "" } = useParams();
  const ev = useEvents(id);
  const evs = (ev.data?.items ?? []).filter((e) => node.event_ids.includes(e.id));
  return (
    <aside className="w-full lg:w-96 shrink-0 bg-surface border border-border rounded-lg flex flex-col max-h-full">
      <header className="flex items-start justify-between gap-2 p-4 border-b border-border">
        <div className="min-w-0">
          <div className="text-[11px] uppercase font-bold" style={{ color: NODE_STYLE[node.type]?.color }}>{node.type}</div>
          <div className="font-semibold break-all">{node.label}</div>
          {node.value !== node.label && <Mono className="text-muted">{node.value}</Mono>}
          <div className="mt-1"><SeverityBadge severity={node.severity} /></div>
        </div>
        <button onClick={onClose} className="text-muted hover:text-text" aria-label="Close"><X size={18} /></button>
      </header>
      <div className="p-4 overflow-auto space-y-3">
        <div className="text-[12px] uppercase text-muted">{evs.length} related events</div>
        {evs.map((e) => (
          <div key={e.id} className="border-l-2 pl-3 space-y-1" style={{ borderColor: e.severity === "Info" ? "rgb(var(--border))" : undefined }}>
            <div className="flex items-center gap-2"><Mono className="text-muted">{e.timestamp_utc.slice(11, 19)}</Mono><SeverityBadge severity={e.severity} /></div>
            <div className="text-[13px]">{e.description}</div>
            <EvidenceChip evidenceRef={e.evidence_ref} />
          </div>
        ))}
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
    <div className="flex flex-col h-[calc(100vh-7.5rem)] min-h-[560px]">
      <PageHeader title="Attack graph" subtitle={`${nodes.length} entities · ${edges.length} relationships · click a node for its events`}
        actions={<><Legend /><Button onClick={() => setLayout(layout === "dagre" ? "cose" : "dagre")}>{layout === "dagre" ? "Force layout" : "Flow layout"}</Button></>} />
      {!nodes.length ? <Card><Empty title="No entities" hint="The analyzer found no linked IPs, users, processes or files." /></Card> : (
        <div className="flex-1 flex flex-col lg:flex-row gap-4 min-h-0">
          <div className="flex-1 bg-surface border border-border rounded-lg overflow-hidden min-h-[400px]">
            <AttackGraph nodes={nodes} edges={edges} onSelect={setSel} highlightId={sel?.id} layout={layout} />
          </div>
          {sel && <NodeDetailPanel node={sel} onClose={() => setSel(null)} />}
        </div>
      )}
    </div>
  );
}
