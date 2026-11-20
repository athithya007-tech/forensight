import type { Severity, Verdict } from "../api/types";
import { SEV_VAR } from "./ForensicScale";
import { cx } from "./ui";

/** Kept for graph/canvas code that needs literal colours. */
export const SEV_COLOR: Record<Severity, string> = { Critical: "#B3261E", High: "#C95B0C", Medium: "#9C7300", Low: "#346091", Info: "#7D776C" };
export const VERDICT_COLOR: Record<Verdict, string> = { Compromised: "rgb(var(--sev-critical))", Suspicious: "rgb(var(--sev-medium))", Clean: "rgb(var(--ok))" };

/** A square swatch + word: readable in greyscale and for colour-blind viewers (never colour alone). */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 text-xs font-medium text-ink whitespace-nowrap", className)}>
      <span className="w-2 h-2 rounded-[1px] shrink-0" style={{ background: SEV_VAR[severity] ?? SEV_VAR.Info }} aria-hidden />
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict, size = "sm" }: { verdict?: Verdict | null; size?: "sm" | "lg" }) {
  if (!verdict) return <span className="text-ink-2 text-xs">Not analyzed</span>;
  const c = VERDICT_COLOR[verdict];
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-sm border font-semibold", size === "lg" ? "px-2.5 py-1 text-sm" : "px-1.5 py-px text-xs")}
      style={{ color: c, borderColor: c }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} aria-hidden />{verdict}
    </span>
  );
}
