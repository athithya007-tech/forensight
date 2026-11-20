import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useFindings } from "../api/client";
import { SEVERITIES, type Finding, type Severity } from "../api/types";
import { EvidenceChip } from "../components/EvidenceChip";
import { SEV_COLOR, SeverityBadge } from "../components/SeverityBadge";
import { Card, Empty, ErrorState, Loading, Mono, PageHeader, cx, fmtTime } from "../components/ui";

const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

export function PlaybookList({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <div><div className="text-2xs text-ink-2 mb-1">Recommended actions</div>
      <ol className="list-decimal ml-5 space-y-0.5 text-sm">{items.map((p) => <li key={p}>{p}</li>)}</ol></div>
  );
}

export default function FindingsPage() {
  const { id = "" } = useParams();
  const q = useFindings(id);
  const [open, setOpen] = useState<number | null>(null);
  const [sev, setSev] = useState<Severity | null>(null);
  const [sort, setSort] = useState<"severity" | "time" | "attck">("severity");
  const rows = useMemo(() => {
    let r = (q.data ?? []).filter((f) => !sev || f.severity === sev);
    r = [...r].sort((a, b) => sort === "time" ? a.first_seen.localeCompare(b.first_seen) : sort === "attck" ? (a.attck_id ?? "").localeCompare(b.attck_id ?? "")
      : RANK[b.severity] - RANK[a.severity] || a.first_seen.localeCompare(b.first_seen));
    return r;
  }, [q.data, sev, sort]);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <div>
      <PageHeader title="Findings" subtitle={`${q.data!.length} findings. Open a row for its evidence and the recommended response.`}
        actions={<div className="flex items-center gap-1.5 flex-wrap">
          {SEVERITIES.map((s) => { const n = q.data!.filter((f) => f.severity === s).length; return n ? (
            <button key={s} onClick={() => setSev(sev === s ? null : s)} aria-pressed={sev === s}
              className={cx("inline-flex items-center gap-1.5 rounded-sm px-2 h-7 text-xs border transition-colors", sev === s ? "border-ink bg-ink text-paper" : "border-rule text-ink hover:border-ink-2")}>
              <span className="w-2 h-2 rounded-[1px]" style={{ background: SEV_COLOR[s] }} />{s} <span className="tnum">{n}</span></button>) : null; })}
          <select value={sort} onChange={(e) => setSort(e.target.value as any)} aria-label="Sort findings" className="field h-7 py-0 text-xs">
            <option value="severity">Sort: severity</option><option value="time">Sort: time</option><option value="attck">Sort: ATT&CK</option></select>
        </div>} />
      {!rows.length ? <Card><Empty title="No findings" hint="Nothing matched the detection rules on this host." /></Card> : (
        <div className="border border-rule rounded-lg overflow-auto bg-sheet shadow-sheet">
          <table className="w-full text-sm">
            <thead className="text-ink-2 text-xs border-b border-ink/70"><tr>
              <th className="w-6" /><th className="text-left px-3 py-2">Severity</th><th className="text-left px-3 py-2">Finding</th>
              <th className="text-left px-3 py-2">ATT&CK</th><th className="text-left px-3 py-2">Rule</th><th className="text-left px-3 py-2">Confidence</th><th className="text-left px-3 py-2">First seen</th></tr></thead>
            <tbody>
              {rows.map((f: Finding) => (
                <Fragment key={f.id}>
                  <tr onClick={() => setOpen(open === f.id ? null : f.id)} className="border-t border-rule cursor-pointer hover:bg-amber/[0.07] align-top">
                    <td className="pl-2 pt-2.5 text-ink-2">{open === f.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                    <td className="px-3 py-2"><SeverityBadge severity={f.severity} />{f.pre_existing && <div className="text-2xs text-ink-2 mt-1">pre-existing</div>}</td>
                    <td className="px-3 py-2 max-w-[520px]"><div className="font-medium">{f.title}</div><div className="text-ink-2 text-sm line-clamp-2 [overflow-wrap:anywhere]">{f.description}</div></td>
                    <td className="px-3 py-2"><Mono>{f.attck_id}</Mono><div className="text-xs text-ink-2">{f.technique}</div></td>
                    <td className="px-3 py-2 max-w-[9rem]"><span className="font-mono text-xs text-ink-2 block truncate" title={f.rule_id}>{f.rule_id}</span><div className="text-2xs text-ink-2">{f.engine}</div></td>
                    <td className="px-3 py-2 tnum">{Math.round(f.confidence * 100)}%</td>
                    <td className="px-3 py-2 whitespace-nowrap"><Mono className="break-normal">{fmtTime(f.first_seen)}</Mono></td>
                  </tr>
                  {open === f.id && (
                    <tr className="bg-well/40"><td /><td colSpan={6} className="px-3 py-4 space-y-4">
                      <div className="text-sm [overflow-wrap:anywhere] max-w-4xl">{f.description}</div>
                      {f.pre_existing && <div className="text-xs text-ink-2">Present in the clean baseline: lowered from {f.original_severity} to {f.severity}.</div>}
                      <div><div className="text-2xs text-ink-2 mb-1">Evidence ({f.evidence.length})</div>
                        <div className="flex flex-wrap gap-1.5">{f.evidence.slice(0, 12).map((e) => <EvidenceChip key={e.ref} evidenceRef={e.ref} />)}
                          {f.evidence.length > 12 && <span className="text-ink-2 text-xs">+{f.evidence.length - 12} more</span>}</div>
                        {f.evidence[0]?.sha256 && <div className="text-xs text-ink-2 mt-1">File SHA-256 <Mono>{f.evidence[0].sha256}</Mono></div>}</div>
                      <PlaybookList items={f.playbook} />
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
