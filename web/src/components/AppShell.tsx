import { ChevronRight, Menu, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import { Link, NavLink, useParams } from "react-router-dom";
import { useSummary } from "../api/client";
import { useUi } from "../stores/ui";
import { ChatDrawer } from "./ChatDrawer";
import { Glyph, type GlyphName } from "./Glyph";
import { EvidenceDrawer } from "./EvidenceChip";
import { VerdictBadge } from "./SeverityBadge";
import { cx } from "./ui";

const NAV: { heading: string; items: { to: string; label: string; icon: GlyphName; end?: boolean }[] }[] = [
  { heading: "Read the case", items: [
    { to: "", label: "Summary", icon: "case-file", end: true },
    { to: "story", label: "Attack story", icon: "replay" },
    { to: "timeline", label: "Timeline", icon: "timeline" },
    { to: "graph", label: "Attack graph", icon: "string-board" },
  ] },
  { heading: "Examine", items: [
    { to: "findings", label: "Findings", icon: "exhibit-lens" },
    { to: "attack", label: "ATT&CK map", icon: "attack-map" },
    { to: "processes", label: "Processes", icon: "process-tree" },
    { to: "network", label: "Network", icon: "host-links" },
    { to: "diff", label: "Baseline diff", icon: "baseline-diff" },
  ] },
  { heading: "Custody", items: [
    { to: "evidence", label: "Evidence", icon: "evidence-bag" },
    { to: "report", label: "Report", icon: "signed-report" },
    { to: "collect", label: "Live collection", icon: "collector" },
  ] },
];

export function ThemeSync() {
  const theme = useUi((s) => s.theme);
  useEffect(() => { document.documentElement.className = theme; }, [theme]);
  return null;
}

/** Wordmark: the case-file serif with the evidence-tape mark. */
export function Brand({ onRail = false }: { onRail?: boolean }) {
  return (
    <Link to="/" className={cx("inline-flex items-center gap-2.5", onRail ? "text-rail-ink" : "text-ink")} aria-label="ForenSight, all cases">
      <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden>
        <rect x="1" y="1" width="20" height="20" rx="3" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <rect x="1" y="14" width="20" height="4" fill="rgb(var(--tape))" />
        <path d="M5 1v5M9 1v3M13 1v5M17 1v3" stroke="currentColor" strokeWidth="1.5" />
      </svg>
      <span className="font-serif text-xl font-medium tracking-[-0.01em]">ForenSight</span>
    </Link>
  );
}

export function ThemeToggle({ onRail = false }: { onRail?: boolean }) {
  const { theme, toggleTheme } = useUi();
  return (
    <button onClick={toggleTheme} title={theme === "light" ? "Switch to night shift" : "Switch to daylight"} aria-label="Toggle theme"
      className={cx("w-8 h-8 grid place-items-center rounded transition-colors duration-150", onRail ? "text-rail-ink/70 hover:text-rail-ink hover:bg-rail-2" : "text-ink-2 hover:text-ink hover:bg-well")}>
      {theme === "dark" ? <Glyph name="daylight" size={17} /> : <Glyph name="night-shift" size={17} />}
    </button>
  );
}

/** Shell: ink rail with grouped navigation, a paper work area, a slim case bar (PRD 15.3). */
export function CaseShell({ children }: { children: ReactNode }) {
  const { id = "" } = useParams();
  const s = useSummary(id);
  const { sidebarOpen, setSidebar, setChat } = useUi();
  const c = s.data?.case;
  return (
    <div className="h-full flex">
      <ThemeSync />
      {sidebarOpen && <div className="fixed inset-0 bg-ink/40 z-30 lg:hidden" onClick={() => setSidebar(false)} />}
      <nav aria-label="Case navigation" className={cx("fixed lg:static z-40 h-full w-60 shrink-0 bg-rail text-rail-ink flex flex-col transition-transform duration-200 ease-out",
        sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0")}>
        <div className="px-5 h-14 flex items-center justify-between border-b border-rail-2"><Brand onRail />
          <button className="lg:hidden text-rail-ink/70 p-1" onClick={() => setSidebar(false)} aria-label="Close menu"><X size={18} /></button></div>
        <div className="px-5 py-4 border-b border-rail-2">
          <div className="font-serif text-lg leading-tight truncate" title={c?.name}>{c?.name ?? "Loading case"}</div>
          <div className="text-xs text-rail-ink/60 mt-1 truncate">{c?.host} · {c?.investigator}</div>
        </div>
        <div className="flex-1 overflow-auto py-3">
          {NAV.map((g) => (
            <div key={g.heading} className="mb-3">
              <div className="px-5 pb-1 text-2xs text-rail-ink/45">{g.heading}</div>
              {g.items.map((n) => (
                <NavLink key={n.to} to={`/cases/${id}${n.to ? `/${n.to}` : ""}`} end={n.end} onClick={() => setSidebar(false)}
                  className={({ isActive }) => cx("relative flex items-center gap-2.5 mx-2 px-3 h-8 rounded text-sm transition-colors duration-150",
                    isActive ? "bg-rail-ink text-rail font-medium" : "text-rail-ink/75 hover:text-rail-ink hover:bg-rail-2")}>
                  <Glyph name={n.icon} size={17} />{n.label}
                </NavLink>
              ))}
            </div>
          ))}
        </div>
        <div className="px-5 py-3 border-t border-rail-2 flex items-center justify-between">
          <span className="text-2xs text-rail-ink/50 leading-snug">Bound to localhost.<br />Evidence never leaves this machine.</span>
          <ThemeToggle onRail />
        </div>
      </nav>
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 shrink-0 border-b border-rule bg-paper flex items-center gap-3 px-4 lg:px-8">
          <button className="lg:hidden text-ink-2 p-1" onClick={() => setSidebar(true)} aria-label="Open menu"><Menu size={20} /></button>
          <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-sm min-w-0">
            <Link to="/" className="text-ink-2 hover:text-ink">Cases</Link>
            <ChevronRight size={14} className="text-ink-2 shrink-0" />
            <span className="font-mono text-xs text-ink truncate">{id}</span>
          </nav>
          {s.data?.analyzed && (
            <span className="hidden sm:inline-flex items-center gap-2 ml-2">
              <VerdictBadge verdict={s.data.verdict} />
              <span className="text-xs text-ink-2 tnum">score <b className="text-ink font-semibold">{s.data.score}</b>/100</span>
            </span>
          )}
          <div className="flex-1" />
          <button onClick={() => setChat(true)}
            className="inline-flex items-center gap-1.5 whitespace-nowrap rounded border border-ink px-3 h-8 text-sm font-medium text-ink hover:bg-ink hover:text-paper transition-colors duration-150">
            <Glyph name="ask" size={16} />Ask the evidence
          </button>
        </header>
        <main className="flex-1 overflow-auto px-4 py-6 lg:px-8">{children}</main>
      </div>
      <ChatDrawer caseId={id} />
      <EvidenceDrawer />
    </div>
  );
}
