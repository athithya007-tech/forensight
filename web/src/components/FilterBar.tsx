import { Search, X } from "lucide-react";
import { SEVERITIES, type Severity } from "../api/types";
import type { Filters } from "../stores/filters";
import { SEV_COLOR } from "./SeverityBadge";
import { cx } from "./ui";

/** Severity, source, tactic, time range and text search (FR-26). */
export function FilterBar({ filters, onChange, sources, tactics }: { filters: Filters; onChange: (f: Partial<Filters>) => void; sources: string[]; tactics: string[] }) {
  const toggle = <K extends "severity" | "source" | "tactic">(k: K, v: Filters[K][number]) => {
    const cur = filters[k] as string[];
    onChange({ [k]: cur.includes(v as string) ? cur.filter((x) => x !== v) : [...cur, v] } as Partial<Filters>);
  };
  const active = filters.severity.length + filters.source.length + filters.tactic.length + (filters.q ? 1 : 0) + (filters.from ? 1 : 0) + (filters.to ? 1 : 0);
  return (
    <div className="flex flex-col gap-2.5 bg-surface border border-border rounded-lg p-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-2.5 top-2.5 text-muted" />
          <input value={filters.q} onChange={(e) => onChange({ q: e.target.value })} placeholder="Search descriptions, users, IPs, hashes…"
            className="w-full bg-bg border border-border rounded-md pl-8 pr-3 py-1.5 text-[13px] focus:outline-none focus:border-accent" />
        </label>
        <input type="datetime-local" step={1} value={filters.from} onChange={(e) => onChange({ from: e.target.value })} title="From (UTC)"
          className="bg-bg border border-border rounded-md px-2 py-1.5 text-[12px] font-mono" />
        <span className="text-muted text-[12px]">→</span>
        <input type="datetime-local" step={1} value={filters.to} onChange={(e) => onChange({ to: e.target.value })} title="To (UTC)"
          className="bg-bg border border-border rounded-md px-2 py-1.5 text-[12px] font-mono" />
        {active > 0 && (
          <button className="inline-flex items-center gap-1 text-[12px] text-muted hover:text-text" onClick={() => onChange({ severity: [], source: [], tactic: [], q: "", from: "", to: "" })}>
            <X size={13} />Clear {active}
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5 items-center">
        <span className="text-[11px] uppercase text-muted mr-1">Severity</span>
        {SEVERITIES.map((s: Severity) => {
          const on = filters.severity.includes(s);
          return (
            <button key={s} onClick={() => toggle("severity", s)}
              className={cx("rounded px-2 py-0.5 text-[12px] border transition", on ? "text-[#0B0F17] font-semibold" : "text-muted border-border hover:text-text")}
              style={on ? { background: SEV_COLOR[s], borderColor: SEV_COLOR[s] } : {}}>{s}</button>
          );
        })}
        {tactics.length > 0 && <span className="text-[11px] uppercase text-muted ml-3 mr-1">Tactic</span>}
        {tactics.map((t) => (
          <button key={t} onClick={() => toggle("tactic", t)}
            className={cx("rounded px-2 py-0.5 text-[12px] border", filters.tactic.includes(t) ? "bg-accent/20 border-accent text-accent" : "border-border text-muted hover:text-text")}>{t}</button>
        ))}
      </div>
      {sources.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-[11px] uppercase text-muted mr-1">Source</span>
          {sources.map((s) => (
            <button key={s} onClick={() => toggle("source", s)}
              className={cx("rounded px-2 py-0.5 text-[11.5px] font-mono border", filters.source.includes(s) ? "bg-accent/20 border-accent text-accent" : "border-border text-muted hover:text-text")}>{s.replace(".evtx.jsonl", ".evtx")}</button>
          ))}
        </div>
      )}
    </div>
  );
}
