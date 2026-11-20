import { Download } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useAttack, useFindings } from "../api/client";
import type { TechniqueCell } from "../api/types";
import { EvidenceChip } from "../components/EvidenceChip";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Card, Empty, ErrorState, Loading, Mono, PageHeader, cx } from "../components/ui";

/** Single-hue sequential scale (Tufte: no rainbow for ordered data). Text stays ink for contrast. */
const shade = (count: number, max: number) => `rgb(var(--tape) / ${(0.1 + 0.42 * (count / Math.max(1, max))).toFixed(2)})`;

export function ExportLayerButton({ caseId }: { caseId: string }) {
  return <a href={`/api/cases/${caseId}/attack/layer`} download><Button variant="primary"><Download size={14} />Export Navigator layer</Button></a>;
}

/** Tactic columns, detected techniques shaded by finding count (US-019, FR-41). Empty tactics collapse. */
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
  const active = cols.filter((c) => c.count).length;
  const selFindings = (fq.data ?? []).filter((f) => sel?.finding_ids.includes(f.id));
  return (
    <div className="space-y-5 max-w-[1180px]">
      <PageHeader title="ATT&CK map" subtitle={`${total} techniques across ${active} of 14 enterprise tactics, in kill-chain order. Darker cells carry more findings; empty tactics are folded.`}
        actions={<ExportLayerButton caseId={id} />} />
      {!total ? <Card><Empty title="No techniques detected" hint="No finding in this case maps to MITRE ATT&CK." /></Card> : (
        <div className="bg-sheet border border-rule rounded-lg shadow-sheet p-4">
          <div className="flex gap-1.5 items-stretch">
            {cols.map((c) => c.count ? (
              <div key={c.tactic} className="flex-1 min-w-[7.5rem] flex flex-col gap-1.5">
                <div className="px-2 pb-2 border-b-2 border-ink min-h-[3.25rem] flex flex-col justify-end">
                  <div className="text-sm font-semibold leading-tight">{c.tactic}</div>
                  <div className="text-2xs text-ink-2 tnum">{c.count} finding{c.count > 1 ? "s" : ""}</div>
                </div>
                {c.techniques.map((t) => (
                  <button key={t.id} onClick={() => setSel(sel?.id === t.id ? null : t)} aria-pressed={sel?.id === t.id}
                    className={cx("rounded-[3px] px-2 py-1.5 text-left text-ink transition-shadow duration-150 hover:shadow-[0_0_0_2px_rgb(var(--ink))]",
                      sel?.id === t.id && "shadow-[0_0_0_2px_rgb(var(--amber))]")}
                    style={{ background: shade(t.count, max) }}>
                    <div className="flex items-baseline justify-between gap-1"><span className="font-mono text-xs font-medium">{t.id}</span><span className="text-2xs tnum">{t.count}×</span></div>
                    <div className="text-xs leading-snug mt-0.5">{t.name}</div>
                  </button>
                ))}
              </div>
            ) : (
              <div key={c.tactic} className="w-7 shrink-0 flex flex-col items-center" title={`${c.tactic}: nothing detected`}>
                <div className="border-b-2 border-rule w-full min-h-[3.25rem]" />
                <div className="mt-2 text-2xs text-ink-2/80 [writing-mode:vertical-rl] rotate-180 whitespace-nowrap">{c.tactic}</div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-2 mt-5 text-2xs text-ink-2">
            <span>1 finding</span>
            <div className="h-2 w-28 rounded-sm" style={{ background: `linear-gradient(90deg, ${shade(1, max)}, ${shade(max, max)})` }} />
            <span>{max} findings</span>
          </div>
        </div>
      )}
      {sel && (
        <Card title={`${sel.id} ${sel.name}`} note={`${selFindings.length} finding${selFindings.length > 1 ? "s" : ""} map to this technique`}>
          <ul className="divide-y divide-rule -mt-1">{selFindings.map((f) => (
            <li key={f.id} className="py-3 grid grid-cols-[5.5rem_1fr_auto] gap-x-4">
              <SeverityBadge severity={f.severity} />
              <div className="min-w-0"><div className="font-medium">{f.title}</div><div className="text-ink-2 text-sm [overflow-wrap:anywhere]">{f.description}</div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">{f.evidence.slice(0, 2).map((e) => <EvidenceChip key={e.ref} evidenceRef={e.ref} />)}</div></div>
              <Mono className="text-ink-2">{f.first_seen.slice(11, 19)}</Mono>
            </li>))}</ul>
        </Card>
      )}
    </div>
  );
}
