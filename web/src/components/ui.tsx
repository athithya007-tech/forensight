import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

export function cx(...c: (string | false | null | undefined)[]) { return c.filter(Boolean).join(" "); }

export function Card({ title, actions, children, className, bodyClass }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={cx("bg-surface border border-border rounded-lg flex flex-col min-w-0", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 px-4 py-2.5 border-b border-border">
          <h2 className="text-[13px] font-semibold uppercase tracking-wide text-muted">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={cx("p-4 min-h-0", bodyClass)}>{children}</div>
    </section>
  );
}

export function Button({ children, onClick, variant = "default", disabled, title, className, type = "button" }:
  { children: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "ghost" | "danger"; disabled?: boolean; title?: string; className?: string; type?: "button" | "submit" }) {
  const v = {
    default: "bg-surface2 border-border hover:border-accent/60 text-text",
    primary: "bg-accent text-[#0B0F17] border-accent hover:brightness-110 font-semibold",
    ghost: "bg-transparent border-transparent hover:bg-surface2 text-muted hover:text-text",
    danger: "bg-critical/15 border-critical/50 text-critical hover:bg-critical/25",
  }[variant];
  return (
    <button type={type} title={title} disabled={disabled} onClick={onClick}
      className={cx("inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[13px] transition disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-accent", v, className)}>
      {children}
    </button>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
      <div>
        <h1 className="text-xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="text-muted text-[13px] mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="flex items-center justify-center gap-2 text-muted py-16"><Loader2 className="animate-spin" size={18} />{label}</div>;
}

export function Empty({ title, hint, icon }: { title: string; hint?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center gap-2 py-14 text-muted">
      {icon ?? <Inbox size={28} className="opacity-60" />}
      <div className="text-text font-medium">{title}</div>
      {hint && <div className="text-[13px] max-w-md">{hint}</div>}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="flex items-start gap-3 rounded-lg border border-critical/40 bg-critical/10 p-4 text-[13px]">
      <AlertTriangle className="text-critical shrink-0" size={18} />
      <div><div className="font-semibold text-critical">Could not load data</div><div className="text-muted mt-0.5">{msg}</div>
        <div className="text-muted mt-1">Check that <code className="font-mono">forensight serve</code> is running and the case was analyzed.</div></div>
    </div>
  );
}

export function Stat({ label, value, sub, color }: { label: string; value: ReactNode; sub?: ReactNode; color?: string }) {
  return (
    <div className="bg-surface border border-border rounded-lg px-4 py-3">
      <div className="text-[12px] uppercase tracking-wide text-muted">{label}</div>
      <div className="text-3xl font-bold mt-1 tabular-nums" style={{ color }}>{value}</div>
      {sub && <div className="text-[12px] text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("font-mono text-[12px] break-all", className)}>{children}</span>;
}

export const fmtTime = (iso?: string | null) => (iso ? iso.slice(11, 19) : "—");
export const fmtDateTime = (iso?: string | null) => (iso ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}` : "—");
export function fmtDuration(s?: number | null) {
  if (s == null) return "—";
  const m = Math.floor(s / 60), sec = Math.round(s % 60);
  return m ? `${m}m ${sec}s` : `${sec}s`;
}
export function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 2 ** 20) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 2 ** 20).toFixed(1)} MB`;
}
