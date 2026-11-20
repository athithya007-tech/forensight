import { Play } from "lucide-react";
import { Glyph } from "../components/Glyph";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createCase, startDemo, useCases } from "../api/client";
import type { CaseRow } from "../api/types";
import { Brand, ThemeSync, ThemeToggle } from "../components/AppShell";
import { VERDICT_COLOR, VerdictBadge } from "../components/SeverityBadge";
import { Button, Card, Empty, ErrorState, Loading, cx, fmtDateTime } from "../components/ui";

const STEPS: [string, string][] = [
  ["Password-guess RDP/SMB login from Kali", "T1110"], ["Log in as a weak-password admin", "T1078"],
  ["Run encoded PowerShell that downloads a test file", "T1059.001"], ["Drop the EICAR test file in %TEMP%", "T1105"],
  ["Create user support_backup and add to admins", "T1136 · T1098"], ["Add a Run-key entry and a scheduled task", "T1547.001 · T1053.005"],
  ["Open an outbound connection to Kali port 4444", "T1071"], ["Clear the Security log", "T1070.001"],
];

/** One row of the case register: verdict, the score on a mini scale, host, when. */
function CaseRowView({ c }: { c: CaseRow }) {
  const nav = useNavigate();
  const col = c.verdict ? VERDICT_COLOR[c.verdict] : "rgb(var(--rule))";
  return (
    <tr onClick={() => nav(`/cases/${c.id}`)} className="border-t border-rule cursor-pointer hover:bg-amber/[0.07] transition-colors duration-100 group">
      <td className="py-3 pl-4 pr-3">
        <div className="font-serif text-lg leading-tight group-hover:underline underline-offset-4 decoration-1">{c.name}</div>
        <div className="font-mono text-2xs text-ink-2 mt-0.5">{c.id}</div>
      </td>
      <td className="py-3 px-3 text-sm whitespace-nowrap">{c.host}<div className="text-xs text-ink-2">{c.os}</div></td>
      <td className="py-3 px-3"><VerdictBadge verdict={c.verdict} /></td>
      <td className="py-3 px-3 w-44">
        {c.score != null ? (
          <div className="flex items-center gap-2">
            <div className="relative flex-1 h-2 border border-ink/70 rounded-[1px] bg-sheet">
              <div className="absolute inset-y-0 left-0" style={{ width: `${c.score}%`, background: col }} />
            </div>
            <span className="tnum text-sm font-medium w-7 text-right">{c.score}</span>
          </div>
        ) : <span className="text-xs text-ink-2">{c.status}</span>}
      </td>
      <td className="py-3 px-3 pr-4 text-xs text-ink-2 font-mono whitespace-nowrap">{fmtDateTime(c.created_at)}<div className="font-sans">{c.investigator}</div></td>
    </tr>
  );
}

function NewCaseDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState(""); const [inv, setInv] = useState(""); const [notes, setNotes] = useState("");
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  return (
    <div className="fixed inset-0 z-50 bg-ink/40 grid place-items-center p-4" onClick={onClose}>
      <form role="dialog" aria-label="Open a new case" className="bg-sheet border border-rule rounded-lg shadow-lift p-6 w-full max-w-md space-y-4 rise" onClick={(e) => e.stopPropagation()}
        onSubmit={async (e) => { e.preventDefault(); setBusy(true); try { const c = await createCase({ name, investigator: inv, notes }); nav(`/cases/${c.id}/collect`); } catch (x) { setErr((x as Error).message); setBusy(false); } }}>
        <h2 className="h-display text-xl">Open a new case</h2>
        {[["Case name", name, setName, "Lab-Breach-01"], ["Investigator", inv, setInv, "Asha"]].map(([l, v, s, ph]: any) => (
          <label key={l} className="block"><span className="label">{l}</span>
            <input required value={v} onChange={(e) => s(e.target.value)} placeholder={ph} className="field mt-1 w-full h-9" /></label>
        ))}
        <label className="block"><span className="label">Notes</span>
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} className="field mt-1 w-full" /></label>
        {err && <div role="alert" className="text-critical text-sm">{err}</div>}
        <p className="text-xs text-ink-2">On a victim machine, collect from the USB drive instead: <code className="font-mono">forensight collect --case &lt;id&gt; --out E:\evidence</code></p>
        <div className="flex justify-end gap-2 pt-1"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button type="submit" variant="primary" busy={busy}>Open case</Button></div>
      </form>
    </div>
  );
}

/** Judges pick the attack (US-014). */
function DemoPanel() {
  const [sel, setSel] = useState<number[]>([1, 2, 3, 4, 5, 6, 7, 8]);
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  return (
    <Card title="Stage the lab attack" note="Tick the steps that ran. ForenSight must find exactly these, and nothing else.">
      <ul className="-mx-2">
        {STEPS.map(([s, t], i) => {
          const n = i + 1, on = sel.includes(n);
          return (
            <li key={n}>
              <label className={cx("grid grid-cols-[1.25rem_1.25rem_1fr] items-start gap-2 rounded px-2 py-1.5 cursor-pointer transition-colors duration-100", on ? "" : "opacity-55", "hover:bg-well/70")}>
                <input type="checkbox" checked={on} onChange={() => setSel(on ? sel.filter((x) => x !== n) : [...sel, n].sort())} className="mt-0.5 accent-[rgb(var(--ink))]" />
                <span className="font-mono text-xs text-ink-2 mt-0.5 tnum">{n}</span>
                <span className="text-sm leading-snug">{s}<span className="block font-mono text-2xs text-ink-2">{t}</span></span>
              </label>
            </li>
          );
        })}
      </ul>
      <div className="flex items-center gap-2 mt-4">
        <Button variant="primary" busy={busy} onClick={async () => { setBusy(true); try { const r = await startDemo(sel); nav(`/cases/${r.case_id}/collect`); } catch { setBusy(false); } }}>
          <Play size={13} />{sel.length ? `Run ${sel.length} step${sel.length > 1 ? "s" : ""}` : "Run a clean host"}
        </Button>
        <Button variant="ghost" onClick={() => setSel(sel.length ? [] : [1, 2, 3, 4, 5, 6, 7, 8])}>{sel.length ? "Clear all" : "Select all"}</Button>
      </div>
    </Card>
  );
}

export default function CaseList() {
  const q = useCases();
  const [dlg, setDlg] = useState(false);
  const cases = q.data ?? [];
  const compromised = cases.filter((c) => c.verdict === "Compromised").length;
  return (
    <div className="min-h-full">
      <ThemeSync />
      <header className="h-14 bg-rail text-rail-ink flex items-center px-6 lg:px-10 gap-4">
        <Brand onRail /><div className="flex-1" /><ThemeToggle onRail />
      </header>
      <main className="max-w-[1180px] mx-auto px-6 lg:px-10 py-8">
        <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
          <div>
            <h1 className="h-display text-3xl">Case register</h1>
            <p className="text-ink-2 text-sm mt-1">{cases.length ? `${cases.length} case${cases.length > 1 ? "s" : ""} on this machine, ${compromised} compromised. Every artifact is SHA-256 hashed and chained.` : "Collect, analyze, correlate and report, with every artifact hashed."}</p>
          </div>
          <Button variant="primary" onClick={() => setDlg(true)}><Glyph name="open-case" size={16} />Open a new case</Button>
        </div>
        <div className="grid lg:grid-cols-[1fr_360px] gap-6 items-start">
          <div className="min-w-0">
            {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : !cases.length ? (
              <Card><Empty title="No cases yet" hint={<>Stage the lab attack on the right to build one in about ten seconds, or run <code className="font-mono text-xs">forensight demo</code>.</>} /></Card>
            ) : (
              <div className="bg-sheet border border-rule rounded-lg shadow-sheet overflow-x-auto">
                <table className="w-full text-left">
                  <thead className="text-xs text-ink-2 border-b border-ink/70">
                    <tr><th className="font-medium py-2.5 pl-4 pr-3">Case</th><th className="font-medium px-3">Host</th><th className="font-medium px-3">Verdict</th>
                      <th className="font-medium px-3">Score</th><th className="font-medium px-3 pr-4">Opened (UTC)</th></tr>
                  </thead>
                  <tbody>{cases.map((c) => <CaseRowView key={c.id} c={c} />)}</tbody>
                </table>
              </div>
            )}
          </div>
          <DemoPanel />
        </div>
      </main>
      {dlg && <NewCaseDialog onClose={() => setDlg(false)} />}
    </div>
  );
}
