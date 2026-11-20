import { AlertTriangle, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

export function cx(...c: (string | false | null | undefined)[]) { return c.filter(Boolean).join(" "); }

/** A sheet of paper on the evidence table. Titles are sentence-case headings, never eyebrows. */
export function Card({ title, actions, children, className, bodyClass, note }:
  { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; note?: ReactNode }) {
  return (
    <section className={cx("bg-sheet border border-rule rounded-lg shadow-sheet flex flex-col min-w-0", className)}>
      {(title || actions) && (
        <header className="flex items-baseline justify-between gap-3 px-5 pt-4 pb-3">
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-ink leading-tight">{title}</h2>
            {note && <p className="text-xs text-ink-2 mt-0.5">{note}</p>}
          </div>
          <div className="flex items-center gap-2 shrink-0">{actions}</div>
        </header>
      )}
      <div className={cx("px-5 pb-5 min-h-0", !(title || actions) && "pt-5", bodyClass)}>{children}</div>
    </section>
  );
}

export function Button({ children, onClick, variant = "default", disabled, title, className, type = "button", busy }:
  { children: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "ghost" | "danger"; disabled?: boolean; title?: string;
    className?: string; type?: "button" | "submit"; busy?: boolean }) {
  const v = {
    default: "bg-sheet border-rule text-ink hover:border-ink-2 hover:bg-well/60",
    primary: "bg-ink border-ink text-paper hover:bg-ink/90",
    ghost: "bg-transparent border-transparent text-ink-2 hover:text-ink hover:bg-well",
    danger: "bg-sheet border-critical/50 text-critical hover:bg-critical/10",
  }[variant];
  return (
    <button type={type} title={title} disabled={disabled || busy} onClick={onClick} aria-busy={busy || undefined}
      className={cx("inline-flex items-center justify-center gap-1.5 rounded border px-3 h-8 text-sm font-medium whitespace-nowrap",
        "transition-[background-color,border-color,transform] duration-150 ease-out active:translate-y-px",
        "disabled:opacity-45 disabled:cursor-not-allowed disabled:active:translate-y-0", v, className)}>
      {busy && <Loader2 size={14} className="animate-spin" />}{children}
    </button>
  );
}

/** Page title in the case-file serif. Subtitle states what the page contains, in plain words. */
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 mb-5">
      <div className="min-w-0">
        <h1 className="h-display text-2xl">{title}</h1>
        {subtitle && <p className="text-ink-2 text-sm mt-1 max-w-[72ch]">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Skeleton rows instead of a spinner in the middle of content (Impeccable operate). */
export function Loading({ label = "Loading the case…", rows = 5 }: { label?: string; rows?: number }) {
  return (
    <div className="space-y-3 py-6" role="status" aria-label={label}>
      <div className="skeleton h-7 w-64" />
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="skeleton h-10" style={{ width: `${92 - i * 7}%` }} />)}
      <span className="sr-only">{label}</span>
    </div>
  );
}

export function Empty({ title, hint, icon, action }: { title: string; hint?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-2 py-10 px-1 max-w-lg">
      {icon}
      <div className="h-display text-lg">{title}</div>
      {hint && <div className="text-sm text-ink-2">{hint}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, title = "This view could not load", hint }: { error: unknown; title?: string; hint?: ReactNode }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-critical/40 bg-critical/5 p-4 text-sm">
      <AlertTriangle className="text-critical shrink-0 mt-0.5" size={16} />
      <div className="min-w-0"><div className="font-semibold text-ink">{title}</div>
        <div className="text-ink mt-0.5 break-words">{msg}</div>
        <div className="text-ink-2 mt-1">{hint ?? <>Check that <code className="font-mono text-xs">forensight serve</code> is still running in its terminal, then reload the page.</>}</div></div>
    </div>
  );
}

export function Stat({ label, value, sub, color }: { label: string; value: ReactNode; sub?: ReactNode; color?: string }) {
  return (
    <div>
      <div className="label">{label}</div>
      <div className="text-xl font-semibold tnum mt-0.5" style={{ color }}>{value}</div>
      {sub && <div className="text-xs text-ink-2 mt-0.5">{sub}</div>}
    </div>
  );
}

export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return <span title={title} className={cx("font-mono text-xs break-all", className)}>{children}</span>;
}

export const fmtTime = (iso?: string | null) => (iso ? iso.slice(11, 19) : "—");
export const fmtDateTime = (iso?: string | null) => (iso ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}` : "—");
export function fmtDuration(s?: number | null) {
  if (s == null) return "—";
  const m = Math.floor(s / 60), sec = Math.round(s % 60);
  return m ? `${m} min ${sec} s` : `${sec} s`;
}
export function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 2 ** 20) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 2 ** 20).toFixed(1)} MB`;
}
