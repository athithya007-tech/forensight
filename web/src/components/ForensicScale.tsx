import type { Severity } from "../api/types";

/** Signature move: the forensic photo scale (ABFO-style ruler) that evidence is measured against.
 *  Used for time (attack span, replay position) and for the 0-100 compromise score. */

export const SEV_VAR: Record<Severity, string> = {
  Critical: "rgb(var(--sev-critical))", High: "rgb(var(--sev-high))", Medium: "rgb(var(--sev-medium))",
  Low: "rgb(var(--sev-low))", Info: "rgb(var(--sev-info))",
};

interface Mark { t: number; severity: Severity; id?: number; label?: string }

/** Time scale: alternating ink/paper segments, minute ticks, event marks above, optional cursor. */
export function TimeScale({ start, end, marks = [], cursor, onMark, height = 64, labelEvery }:
  { start: number; end: number; marks?: Mark[]; cursor?: number | null; onMark?: (id: number) => void; height?: number; labelEvery?: number }) {
  const W = 1000, pad = 8, barY = height - 26, barH = 7;
  const span = Math.max(1, end - start);
  const x = (t: number) => pad + ((t - start) / span) * (W - pad * 2);
  const minute = 60_000;
  const step = span <= 20 * minute ? minute : span <= 2 * 3600_000 ? 5 * minute : span <= 12 * 3600_000 ? 30 * minute : 3600_000;
  const first = Math.ceil(start / step) * step;
  const ticks: number[] = [];
  for (let t = first; t <= end; t += step) ticks.push(t);
  const every = labelEvery ?? Math.max(1, Math.ceil(ticks.length / 10));
  const segs = [start, ...ticks.filter((t) => t > start && t < end), end];
  const fmt = (t: number) => new Date(t).toISOString().slice(11, 16);
  return (
    <svg viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" className="w-full block overflow-visible" style={{ height }} role="img"
      aria-label={`Time scale from ${fmt(start)} to ${fmt(end)} UTC with ${marks.length} marked events`}>
      {/* the ruler body: alternating segments, like an evidence photo scale */}
      {segs.slice(0, -1).map((t, i) => (
        <rect key={t} x={x(t)} y={barY} width={Math.max(0, x(segs[i + 1]) - x(t))} height={barH}
          fill={i % 2 ? "rgb(var(--sheet))" : "rgb(var(--ink))"} stroke="rgb(var(--ink))" strokeWidth={0.8} vectorEffect="non-scaling-stroke" />
      ))}
      {ticks.map((t, i) => (
        <g key={t}>
          <line x1={x(t)} x2={x(t)} y1={barY + barH} y2={barY + barH + (i % every === 0 ? 6 : 3)} stroke="rgb(var(--ink))" strokeWidth={1} vectorEffect="non-scaling-stroke" />
        </g>
      ))}
      {marks.map((m, i) => {
        const big = m.severity === "Critical" || m.severity === "High";
        return (
          <g key={i} onClick={() => m.id != null && onMark?.(m.id)} style={{ cursor: onMark ? "pointer" : undefined }}>
            <title>{`${new Date(m.t).toISOString().slice(11, 19)} UTC · ${m.severity}${m.label ? ` · ${m.label}` : ""}`}</title>
            <line x1={x(m.t)} x2={x(m.t)} y1={barY - (big ? 22 : 13)} y2={barY} stroke={SEV_VAR[m.severity]} strokeWidth={big ? 2.2 : 1.4} vectorEffect="non-scaling-stroke" />
            <rect x={x(m.t) - 6} y={barY - 26} width={12} height={26} fill="transparent" />
          </g>
        );
      })}
      {cursor != null && (
        <g>
          <line x1={x(cursor)} x2={x(cursor)} y1={2} y2={barY + barH + 2} stroke="rgb(var(--amber))" strokeWidth={2.5} vectorEffect="non-scaling-stroke" />
        </g>
      )}
    </svg>
  );
}

/** HTML labels under the scale (SVG text would stretch with preserveAspectRatio="none"). */
export function TimeScaleLabels({ start, end, count = 6 }: { start: number; end: number; count?: number }) {
  const span = end - start;
  return (
    <div className="relative h-4 font-mono text-2xs text-ink-2 tnum" aria-hidden>
      {Array.from({ length: count }).map((_, i) => {
        const t = start + (span * i) / (count - 1);
        return (
          <span key={i} className="absolute -translate-x-1/2" style={{ left: `${(i / (count - 1)) * 100}%`, transform: i === 0 ? "none" : i === count - 1 ? "translateX(-100%)" : undefined }}>
            {new Date(t).toISOString().slice(11, 16)}
          </span>
        );
      })}
    </div>
  );
}

/** The compromise score measured on a 0-100 scale with the verdict bands marked (FR-33). */
export function ScoreScale({ score }: { score: number }) {
  const bands = [
    { from: 0, to: 20, label: "Clean", fill: "rgb(var(--ok) / .16)" },
    { from: 20, to: 60, label: "Suspicious", fill: "rgb(var(--sev-medium) / .18)" },
    { from: 60, to: 100, label: "Compromised", fill: "rgb(var(--sev-critical) / .14)" },
  ];
  return (
    <div className="w-full" role="img" aria-label={`Compromise score ${score} out of 100`}>
      <div className="relative h-9">
        <div className="absolute inset-x-0 top-2 h-5 flex rounded-sm overflow-hidden border border-ink">
          {bands.map((b) => <div key={b.label} style={{ width: `${b.to - b.from}%`, background: b.fill }} className="border-r border-ink/40 last:border-r-0" />)}
        </div>
        {/* decade ticks */}
        {Array.from({ length: 11 }).map((_, i) => (
          <div key={i} className="absolute top-7 w-px bg-ink" style={{ left: `${i * 10}%`, height: i % 5 === 0 ? 8 : 4 }} />
        ))}
        <div className="absolute top-0 -translate-x-1/2 flex flex-col items-center transition-[left] duration-500 ease-out" style={{ left: `${score}%` }}>
          <div className="w-[3px] h-9 bg-tape rounded-full" />
        </div>
      </div>
      <div className="relative h-4 mt-1 text-2xs text-ink-2">
        {bands.map((b) => <span key={b.label} className="absolute" style={{ left: `${b.from + 0.6}%` }}>{b.label}</span>)}
      </div>
    </div>
  );
}
