import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Search } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { cx } from "./ui";

export interface Column<T> {
  key: string; header: string; render?: (row: T) => ReactNode; sort?: (row: T) => string | number; className?: string; width?: string;
}

/** Sortable, searchable table with 50-row pagination (PRD 15.4). */
export function DataTable<T>({ columns, rows, searchText, onRowClick, rowClass, pageSize = 50, empty, initialSort }:
  { columns: Column<T>[]; rows: T[]; searchText?: (r: T) => string; onRowClick?: (r: T) => void; rowClass?: (r: T) => string;
    pageSize?: number; empty?: ReactNode; initialSort?: { key: string; dir: 1 | -1 } }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(initialSort ?? null);
  const [page, setPage] = useState(0);
  const filtered = useMemo(() => {
    let r = rows;
    if (q && searchText) { const lq = q.toLowerCase(); r = r.filter((x) => searchText(x).toLowerCase().includes(lq)); }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col?.sort) r = [...r].sort((a, b) => { const x = col.sort!(a), y = col.sort!(b); return (x < y ? -1 : x > y ? 1 : 0) * sort.dir; });
    }
    return r;
  }, [rows, q, sort, columns, searchText]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const p = Math.min(page, pages - 1);
  const view = filtered.slice(p * pageSize, (p + 1) * pageSize);
  return (
    <div className="flex flex-col gap-2 min-w-0">
      {searchText && (
        <label className="relative max-w-xs">
          <Search size={14} className="absolute left-2.5 top-2.5 text-muted" />
          <input value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} placeholder="Search…"
            className="w-full bg-bg border border-border rounded-md pl-8 pr-3 py-1.5 text-[13px] focus:outline-none focus:border-accent" />
        </label>
      )}
      <div className="overflow-auto border border-border rounded-lg">
        <table className="w-full text-[13px]">
          <thead className="bg-surface2/60 text-muted text-[11.5px] uppercase tracking-wide sticky top-0">
            <tr>
              {columns.map((c) => (
                <th key={c.key} style={{ width: c.width }} className={cx("text-left font-semibold px-3 py-2 whitespace-nowrap", c.sort && "cursor-pointer select-none hover:text-text")}
                  onClick={() => c.sort && setSort((s) => (s?.key === c.key ? { key: c.key, dir: (s.dir * -1) as 1 | -1 } : { key: c.key, dir: 1 }))}>
                  <span className="inline-flex items-center gap-1">{c.header}
                    {sort?.key === c.key && (sort.dir === 1 ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {view.map((r, i) => (
              <tr key={i} onClick={() => onRowClick?.(r)}
                className={cx("border-t border-border/70 align-top", onRowClick && "cursor-pointer hover:bg-surface2/60", rowClass?.(r))}>
                {columns.map((c) => <td key={c.key} className={cx("px-3 py-2", c.className)}>{c.render ? c.render(r) : String((r as any)[c.key] ?? "")}</td>)}
              </tr>
            ))}
            {!view.length && <tr><td colSpan={columns.length} className="px-3 py-10 text-center text-muted">{empty ?? "No rows"}</td></tr>}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="flex items-center justify-end gap-2 text-[12px] text-muted">
          {filtered.length} rows · page {p + 1}/{pages}
          <button className="p-1 hover:text-text disabled:opacity-30" disabled={p === 0} onClick={() => setPage(p - 1)} aria-label="Previous page"><ChevronLeft size={16} /></button>
          <button className="p-1 hover:text-text disabled:opacity-30" disabled={p >= pages - 1} onClick={() => setPage(p + 1)} aria-label="Next page"><ChevronRight size={16} /></button>
        </div>
      )}
    </div>
  );
}
