import { Search, X } from "lucide-react";
import { SEVERITIES, type Severity } from "../api/types";
import type { Filters } from "../stores/filters";
import { SEV_VAR } from "./ForensicScale";
import { cx } from "./ui";

/** Severity, source, tactic, time range and text search (FR-26). */
export function FilterBar({ filters, onChange, sources, tactics }: { filters: Filters; onChange: (f: Partial<Filters>) => void; sources: string[]; tactics: string[] }) {
  const toggle = <K extends "severity" | "source" | "tactic">(k: K, v: Filters[K][number]) => {
    const cur = filters[k] as string[];
    onChange({ [k]: cur.includes(v as string) ? cur.filter((x) => x !== v) : [...cur, v] } as Partial<Filters>);
  };
  const active = filters.severity.length + filters.source.length + filters.tactic.length + (filters.q ? 1 : 0) + (filters.from ? 1 : 0) + (filters.to ? 1 : 0);
  return (
    <div className="flex flex-col gap-3 bg-sheet border border-rule rounded-lg px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-2.5 top-2.5 text-ink-2" />
          <input value={filters.q} onChange={(e) => onChange({ q: e.target.value })} placeholder="Search descriptions, users, IPs, hashes" aria-label="Search events"
            className="field w-full pl-8" />
        </label>
        <input type="datetime-local" step={1} value={filters.from} onChange={(e) => onChange({ from: e.target.value })} title="From (UTC)"
          className="field font-mono text-xs" />
        <span className="text-ink-2 text-xs">to</span>
        <input type="datetime-local" step={1} value={filters.to} onChange={(e) => onChange({ to: e.target.value })} title="To (UTC)"
          className="field font-mono text-xs" />
        {active > 0 && (
          <button className="inline-flex items-center gap-1 text-xs text-ink-2 hover:text-ink underline" onClick={() => onChange({ severity: [], source: [], tactic: [], q: "", from: "", to: "" })}>
            <X size={13} />Clear {active}
          </button>
        )}
      </div>
      <div className="flex items-start gap-3">
        <span className="label w-16 shrink-0 pt-1">Severity</span>
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s: Severity) => {
            const on = filters.severity.includes(s);
            return (
              <button key={s} onClick={() => toggle("severity", s)}
                aria-pressed={on}
                className={cx("inline-flex items-center gap-1.5 rounded-sm px-2 h-6 text-xs border transition-colors duration-150", on ? "border-ink bg-ink text-paper" : "text-ink border-rule hover:border-ink-2")}>
                <span className="w-2 h-2 rounded-[1px]" style={{ background: SEV_VAR[s] }} />{s}</button>
            );
          })}
        </div>
      </div>
      {tactics.length > 0 && (
        <div className="flex items-start gap-3">
          <span className="label w-16 shrink-0 pt-1">Tactic</span>
          <div className="flex flex-wrap gap-1.5">
            {tactics.map((t) => (
              <button key={t} onClick={() => toggle("tactic", t)}
                aria-pressed={filters.tactic.includes(t)}
                className={cx("rounded-sm px-2 h-6 text-xs border transition-colors duration-150", filters.tactic.includes(t) ? "border-ink bg-ink text-paper" : "border-rule text-ink hover:border-ink-2")}>{t}</button>
            ))}
          </div>
        </div>
      )}
      {sources.length > 0 && (
        <div className="flex items-start gap-3">
          <span className="label w-16 shrink-0 pt-1">Source</span>
          <div className="flex flex-wrap gap-1.5">
          {sources.map((s) => (
            <button key={s} onClick={() => toggle("source", s)}
              aria-pressed={filters.source.includes(s)}
              className={cx("rounded-sm px-2 h-6 text-2xs font-mono border transition-colors duration-150", filters.source.includes(s) ? "border-ink bg-ink text-paper" : "border-rule text-ink-2 hover:text-ink hover:border-ink-2")}>{s.replace(".evtx.jsonl", ".evtx")}</button>
          ))}
          </div>
        </div>
      )}
    </div>
  );
}
