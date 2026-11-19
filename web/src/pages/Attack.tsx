import { Download } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useAttack, useFindings } from "../api/client";
import type { TechniqueCell } from "../api/types";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Card, Empty, ErrorState, Loading, Mono, PageHeader } from "../components/ui";

function shade(count: number, max: number) {
  const a = 0.25 + 0.75 * (count / Math.max(1, max));
  return `rgba(239, 68, 68, ${a.toFixed(2)})`;
}

export function ExportLayerButton({ caseId }: { caseId: string }) {
  return <a href={`/api/cases/${caseId}/attack/layer`} download><Button variant="primary"><Download size={14} />Export Navigator layer</Button></a>;
}

/** Tactic columns, detected techniques shaded by finding count (US-019, FR-41). */
export default function AttackPage() {
  const { id = "" } = useParams();
  const q = useAttack(id);
  const fq = useFindings(id);
  const [sel, setSel] = useState<TechniqueCell | null>(null);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const cols = q.data!;
  const max = Math.max(1, ...cols.flatMap((c) => c.techniques.map((t) => t.count)));
  const total = cols.reduce((n, c) => n + c.techniques.length, 0);
  const selFindings = (fq.data ?? []).filter((f) => sel?.finding_ids.includes(f.id));
  return (
    <div className="space-y-4">
      <PageHeader title="MITRE ATT&CK heatmap" subtitle={`${total} techniques detected across ${cols.filter((c) => c.count).length} tactics`} actions={<ExportLayerButton caseId={id} />} />
      {!total ? <Card><Empty title="No techniques detected" /></Card> : (
        <div className="overflow-x-auto pb-2">
          <div className="grid gap-2 min-w-[1250px]" style={{ gridTemplateColumns: `repeat(${cols.length}, minmax(0, 1fr))` }}>
            {cols.map((c) => (
              <div key={c.tactic} className="flex flex-col gap-1.5">
                <div className={`rounded-md px-1.5 py-2 text-[10.5px] font-bold uppercase leading-tight text-center min-h-[56px] grid place-items-center break-words hyphens-auto ${c.count ? "bg-accent/15 text-accent" : "bg-surface text-muted border border-border"}`}>
                  {c.tactic}<span className="block font-normal normal-case">{c.count ? `${c.count} findings` : ""}</span>
                </div>
                {c.techniques.map((t) => (
                  <button key={t.id} onClick={() => setSel(t)} className={`rounded-md px-2 py-1.5 text-left text-[11.5px] text-white hover:ring-2 ring-accent ${sel?.id === t.id ? "ring-2" : ""}`}
                    style={{ background: shade(t.count, max) }}>
                    <div className="font-mono font-bold">{t.id}</div><div className="leading-tight">{t.name}</div><div className="opacity-80">{t.count}×</div>
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
      {sel && (
        <Card title={`${sel.id} · ${sel.name}`}>
          <ul className="divide-y divide-border">{selFindings.map((f) => (
            <li key={f.id} className="py-2 flex gap-3"><SeverityBadge severity={f.severity} /><div><div className="font-medium">{f.title}</div><div className="text-muted text-[13px]">{f.description}</div></div>
              <Mono className="text-muted ml-auto shrink-0">{f.first_seen.slice(11, 19)}</Mono></li>))}</ul>
        </Card>
      )}
    </div>
  );
}
