import type { Severity, Verdict } from "../api/types";
import { cx } from "./ui";

export const SEV_COLOR: Record<Severity, string> = { Critical: "#EF4444", High: "#F97316", Medium: "#EAB308", Low: "#3B82F6", Info: "#6B7280" };
export const VERDICT_COLOR: Record<Verdict, string> = { Compromised: "#EF4444", Suspicious: "#EAB308", Clean: "#22C55E" };

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const c = SEV_COLOR[severity] ?? SEV_COLOR.Info;
  return (
    <span className={cx("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold whitespace-nowrap", className)}
      style={{ background: `${c}26`, color: c, border: `1px solid ${c}66` }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />{severity}
    </span>
  );
}

export function VerdictBadge({ verdict, size = "sm" }: { verdict?: Verdict | null; size?: "sm" | "lg" }) {
  if (!verdict) return <span className="text-muted text-[12px]">not analyzed</span>;
  const c = VERDICT_COLOR[verdict];
  return (
    <span className={cx("inline-flex items-center rounded-md font-bold uppercase tracking-wide", size === "lg" ? "px-3 py-1 text-base" : "px-2 py-0.5 text-[11px]")}
      style={{ background: `${c}22`, color: c, border: `1px solid ${c}88` }}>{verdict}</span>
  );
}
