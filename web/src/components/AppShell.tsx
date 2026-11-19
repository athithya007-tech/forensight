import {
  Activity, ArrowLeftRight, Clapperboard, Cpu, FileText, Fingerprint, GitFork, Grid3x3, LayoutDashboard, ListTree, Menu, Moon, Network,
  ShieldAlert, Sparkles, Sun, X,
} from "lucide-react";
import { useEffect, type ReactNode } from "react";
import { Link, NavLink, useParams } from "react-router-dom";
import { useSummary } from "../api/client";
import { useUi } from "../stores/ui";
import { ChatDrawer } from "./ChatDrawer";
import { EvidenceDrawer } from "./EvidenceChip";
import { VERDICT_COLOR, VerdictBadge } from "./SeverityBadge";
import { cx } from "./ui";

const NAV = [
  { to: "", label: "Summary", icon: LayoutDashboard, end: true },
  { to: "story", label: "Attack story", icon: Clapperboard },
  { to: "timeline", label: "Timeline", icon: Activity },
  { to: "graph", label: "Attack graph", icon: GitFork },
  { to: "findings", label: "Findings", icon: ShieldAlert },
  { to: "attack", label: "ATT&CK", icon: Grid3x3 },
  { to: "processes", label: "Processes", icon: Cpu },
  { to: "network", label: "Network", icon: Network },
  { to: "diff", label: "Baseline diff", icon: ArrowLeftRight },
  { to: "evidence", label: "Evidence", icon: Fingerprint },
  { to: "report", label: "Report", icon: FileText },
  { to: "collect", label: "Live collection", icon: ListTree },
];

export function ThemeSync() {
  const theme = useUi((s) => s.theme);
  useEffect(() => { document.documentElement.className = theme; }, [theme]);
  return null;
}

export function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2 font-extrabold tracking-wide">
      <span className="w-7 h-7 rounded-md bg-accent/15 border border-accent/40 grid place-items-center text-accent text-[13px]">FS</span>
      <span>Foren<span className="text-accent">Sight</span></span>
    </Link>
  );
}

export function ThemeToggle() {
  const { theme, toggleTheme } = useUi();
  return (
    <button onClick={toggleTheme} className="p-2 rounded-md text-muted hover:text-text hover:bg-surface2" title="Toggle theme" aria-label="Toggle theme">
      {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}

/** Left sidebar + top bar + main area; sidebar collapses below 1024 px (PRD 15.3). */
export function CaseShell({ children }: { children: ReactNode }) {
  const { id = "" } = useParams();
  const s = useSummary(id);
  const { sidebarOpen, setSidebar, setChat } = useUi();
  const v = s.data?.verdict;
  return (
    <div className="h-full flex">
      <ThemeSync />
      {sidebarOpen && <div className="fixed inset-0 bg-black/50 z-30 lg:hidden" onClick={() => setSidebar(false)} />}
      <nav className={cx("fixed lg:static z-40 h-full w-60 shrink-0 bg-surface border-r border-border flex flex-col transition-transform",
        sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0")}>
        <div className="px-4 py-4 border-b border-border flex items-center justify-between"><Brand />
          <button className="lg:hidden text-muted" onClick={() => setSidebar(false)} aria-label="Close menu"><X size={18} /></button></div>
        <div className="px-4 py-3 border-b border-border">
          <div className="font-semibold truncate" title={s.data?.case?.name}>{s.data?.case?.name ?? "…"}</div>
          <div className="text-[12px] text-muted truncate">{s.data?.case?.host} · {s.data?.case?.investigator}</div>
          <div className="mt-2"><VerdictBadge verdict={v} /></div>
        </div>
        <div className="flex-1 overflow-auto py-2">
          {NAV.map((n) => (
            <NavLink key={n.to} to={`/cases/${id}${n.to ? `/${n.to}` : ""}`} end={n.end} onClick={() => setSidebar(false)}
              className={({ isActive }) => cx("flex items-center gap-2.5 mx-2 px-3 py-2 rounded-md text-[13.5px]",
                isActive ? "bg-accent/15 text-accent font-medium" : "text-muted hover:text-text hover:bg-surface2")}>
              <n.icon size={16} />{n.label}
            </NavLink>
          ))}
        </div>
        <div className="px-4 py-3 border-t border-border text-[11px] text-muted">localhost only · evidence stays on this machine</div>
      </nav>
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 shrink-0 border-b border-border bg-surface/80 backdrop-blur flex items-center gap-3 px-4">
          <button className="lg:hidden text-muted" onClick={() => setSidebar(true)} aria-label="Open menu"><Menu size={20} /></button>
          <span className="font-mono text-[13px] truncate">{id}</span>
          {s.data?.analyzed && (
            <span className="inline-flex items-center gap-1.5 text-[13px]">
              <span className="text-muted">score</span>
              <b className="tabular-nums" style={{ color: v ? VERDICT_COLOR[v] : undefined }}>{s.data.score}</b>
            </span>
          )}
          <div className="flex-1" />
          <button onClick={() => setChat(true)} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-accent/50 bg-accent/10 text-accent px-3 py-1.5 text-[13px] hover:bg-accent/20">
            <Sparkles size={14} />Ask AI
          </button>
          <ThemeToggle />
        </header>
        <main className="flex-1 overflow-auto p-4 lg:p-6">{children}</main>
      </div>
      <ChatDrawer caseId={id} />
      <EvidenceDrawer />
    </div>
  );
}
