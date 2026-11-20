import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useDiff } from "../api/client";
import type { DiffItem } from "../api/types";
import { Card, Empty, ErrorState, Loading, Mono, PageHeader, cx, fmtDateTime } from "../components/ui";

const CH = { Added: "rgb(var(--ok))", Removed: "rgb(var(--sev-critical))", Modified: "rgb(var(--sev-medium))" } as const;
const SIGN = { Added: "+", Removed: "−", Modified: "~" } as const;
const LABEL: Record<string, string> = { users: "Users", groups: "Groups", services: "Services", tasks: "Tasks", run_keys: "Run keys", ports: "Ports", startup: "Startup files", programs: "Programs" };

function BeforeAfterPanel({ item }: { item: DiffItem }) {
  const fmt = (v: any) => (v == null ? "— (not present)" : JSON.stringify(v, null, 2));
  return (
    <div className="grid md:grid-cols-2 gap-3">
      {[["Before (baseline)", item.before], ["After (incident)", item.after]].map(([t, v]) => (
        <div key={t as string}><div className="text-2xs text-ink-2 mb-1">{t as string}</div>
          <pre className="bg-well border border-rule rounded p-2.5 font-mono text-xs whitespace-pre-wrap break-all min-h-[60px]">{fmt(v)}</pre></div>
      ))}
    </div>
  );
}

/** "What changed?" (US-015): tabs per category, rows coloured Added / Removed / Modified, click for before/after. */
export default function DiffPage() {
  const { id = "" } = useParams();
  const q = useDiff(id);
  const [tab, setTab] = useState<string | null>(null);
  const [sel, setSel] = useState<DiffItem | null>(null);
  const cats = useMemo(() => Object.keys(q.data?.categories ?? {}), [q.data]);
  const active = tab ?? cats[0];
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const d = q.data!;
  if (!d.available) return <Card><Empty title="No baseline for this case" hint={d.message} /></Card>;
  const items = d.items.filter((i) => i.category === active);
  return (
    <div className="space-y-4">
      <PageHeader title="Baseline diff" subtitle={<>Clean baseline {fmtDateTime(d.baseline_taken)} → incident {fmtDateTime(d.incident_taken)} UTC · {d.items.length} changes</>} />
      {!cats.length ? <Card><Empty title="Nothing changed" hint="Users, groups, services, tasks, Run keys, startup files, ports and programs match the baseline." /></Card> : (
        <>
          <div className="flex flex-wrap gap-1 border-b border-rule">
            {cats.map((c) => {
              const n = d.categories[c];
              return (
                <button key={c} onClick={() => { setTab(c); setSel(null); }} className={cx("px-3 py-2 text-sm border-b-2 -mb-px", active === c ? "border-ink text-ink" : "border-transparent text-ink-2 hover:text-ink")}>
                  {LABEL[c] ?? c} <span className="text-2xs">{(["Added", "Removed", "Modified"] as const).map((k) => n[k] ? <span key={k} className="font-mono ml-1" style={{ color: CH[k] }}>{SIGN[k]}{n[k]}</span> : null)}</span>
                </button>
              );
            })}
          </div>
          <div className="border border-rule rounded-lg overflow-hidden bg-sheet shadow-sheet">
            {items.map((i) => (
              <div key={i.key}>
                <button onClick={() => setSel(sel?.key === i.key ? null : i)} aria-expanded={sel?.key === i.key}
                  className="w-full grid grid-cols-[1.5rem_6rem_1fr] items-center gap-2 px-4 py-2.5 text-left border-t border-rule first:border-0 hover:bg-amber/[0.07] transition-colors">
                  <span className="font-mono text-base font-medium" style={{ color: CH[i.change] }} aria-hidden>{SIGN[i.change]}</span>
                  <span className="text-xs font-medium" style={{ color: CH[i.change] }}>{i.change}</span>
                  <Mono className="text-ink">{i.key}</Mono>
                </button>
                {sel?.key === i.key && <div className="p-3 border-t border-rule"><BeforeAfterPanel item={i} /></div>}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
