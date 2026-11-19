import { FolderPlus, Monitor, Play, Server } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createCase, startDemo, useCases } from "../api/client";
import type { CaseRow } from "../api/types";
import { Brand, ThemeSync, ThemeToggle } from "../components/AppShell";
import { VERDICT_COLOR, VerdictBadge } from "../components/SeverityBadge";
import { Button, Card, Empty, ErrorState, Loading, cx, fmtDateTime } from "../components/ui";

const STEPS = [
  "Password-guess RDP/SMB login from Kali", "Log in as a weak-password admin", "Run encoded PowerShell that downloads a test file",
  "Drop EICAR file in %TEMP%", "Create user support_backup and add to admins", "Add Run-key entry and a scheduled task",
  "Open outbound connection to Kali port 4444", "Clear the Security log",
];

function CaseCard({ c }: { c: CaseRow }) {
  const nav = useNavigate();
  const col = c.verdict ? VERDICT_COLOR[c.verdict] : "rgb(var(--border))";
  return (
    <button onClick={() => nav(`/cases/${c.id}`)} className="text-left bg-surface border border-border rounded-lg p-4 hover:border-accent/60 transition flex flex-col gap-2"
      style={{ borderTop: `3px solid ${col}` }}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0"><div className="font-semibold truncate">{c.name}</div><div className="font-mono text-[12px] text-muted">{c.id}</div></div>
        {c.score != null && <div className="text-2xl font-extrabold tabular-nums" style={{ color: col }}>{c.score}</div>}
      </div>
      <div className="flex items-center gap-2 text-[13px] text-muted">{c.os === "Linux" ? <Server size={14} /> : <Monitor size={14} />}{c.host}</div>
      <div className="flex items-center justify-between">
        <VerdictBadge verdict={c.verdict} />
        <span className="text-[12px] text-muted">{c.status} · {fmtDateTime(c.created_at)}</span>
      </div>
    </button>
  );
}

function NewCaseDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState(""); const [inv, setInv] = useState(""); const [notes, setNotes] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const nav = useNavigate();
  return (
    <div className="fixed inset-0 z-50 bg-black/60 grid place-items-center p-4" onClick={onClose}>
      <form className="bg-surface border border-border rounded-lg p-5 w-full max-w-md space-y-3" onClick={(e) => e.stopPropagation()}
        onSubmit={async (e) => { e.preventDefault(); try { const c = await createCase({ name, investigator: inv, notes }); nav(`/cases/${c.id}/collect`); } catch (x) { setErr((x as Error).message); } }}>
        <h2 className="font-bold text-lg">New case</h2>
        {[["Case name", name, setName, "Lab-Breach-01"], ["Investigator", inv, setInv, "Asha"]].map(([l, v, s, ph]: any) => (
          <label key={l} className="block text-[13px]"><span className="text-muted">{l}</span>
            <input required value={v} onChange={(e) => s(e.target.value)} placeholder={ph} className="mt-1 w-full bg-bg border border-border rounded-md px-3 py-2 focus:outline-none focus:border-accent" /></label>
        ))}
        <label className="block text-[13px]"><span className="text-muted">Notes</span>
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} className="mt-1 w-full bg-bg border border-border rounded-md px-3 py-2 focus:outline-none focus:border-accent" /></label>
        {err && <div className="text-critical text-[13px]">{err}</div>}
        <p className="text-[12px] text-muted">Collection from a victim normally runs from the USB collector: <code className="font-mono">forensight collect --case &lt;id&gt; --out E:\evidence</code></p>
        <div className="flex justify-end gap-2"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button type="submit" variant="primary">Create</Button></div>
      </form>
    </div>
  );
}

/** Judges pick the attack (US-014): choose steps, generate the demo case, watch it collect live. */
function DemoPanel() {
  const [sel, setSel] = useState<number[]>([1, 2, 3, 4, 5, 6, 7, 8]);
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  return (
    <Card title="Run the lab attack demo" className="lg:col-span-1">
      <p className="text-[13px] text-muted mb-3">Pick which of the 8 scripted attack steps ran. ForenSight builds the case from the lab snapshot and must detect exactly these steps.</p>
      <div className="space-y-1.5">
        {STEPS.map((s, i) => {
          const n = i + 1, on = sel.includes(n);
          return (
            <label key={n} className={cx("flex items-center gap-2.5 rounded-md border px-2.5 py-1.5 text-[13px] cursor-pointer", on ? "border-accent/50 bg-accent/10" : "border-border")}>
              <input type="checkbox" checked={on} onChange={() => setSel(on ? sel.filter((x) => x !== n) : [...sel, n].sort())} className="accent-[#22D3EE]" />
              <span className="font-mono text-muted w-4">{n}</span>{s}
            </label>
          );
        })}
      </div>
      <div className="flex gap-2 mt-3">
        <Button variant="primary" disabled={busy} onClick={async () => { setBusy(true); try { const r = await startDemo(sel); nav(`/cases/${r.case_id}/collect`); } finally { setBusy(false); } }}>
          <Play size={14} />{sel.length ? `Run ${sel.length} step${sel.length > 1 ? "s" : ""}` : "Run clean host"}
        </Button>
        <Button variant="ghost" onClick={() => setSel(sel.length ? [] : [1, 2, 3, 4, 5, 6, 7, 8])}>{sel.length ? "None" : "All"}</Button>
      </div>
    </Card>
  );
}

export default function CaseList() {
  const q = useCases();
  const [dlg, setDlg] = useState(false);
  return (
    <div className="min-h-full">
      <ThemeSync />
      <header className="h-14 border-b border-border bg-surface flex items-center px-6 gap-4"><Brand /><div className="flex-1" /><ThemeToggle /></header>
      <main className="max-w-7xl mx-auto p-6">
        <div className="flex items-end justify-between mb-5">
          <div><h1 className="text-2xl font-bold">Cases</h1><p className="text-muted text-[13px]">Collect → analyze → correlate → report, with every artifact hashed.</p></div>
          <Button variant="primary" onClick={() => setDlg(true)}><FolderPlus size={15} />New case</Button>
        </div>
        <div className="grid lg:grid-cols-3 gap-5">
          <div className="lg:col-span-2">
            {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : !q.data?.length ? (
              <Card><Empty title="No cases yet" hint={<>Run the demo on the right, or from a terminal: <code className="font-mono">forensight demo</code></>} /></Card>
            ) : (
              <div className="grid sm:grid-cols-2 gap-3">{q.data.map((c) => <CaseCard key={c.id} c={c} />)}</div>
            )}
          </div>
          <DemoPanel />
        </div>
      </main>
      {dlg && <NewCaseDialog onClose={() => setDlg(false)} />}
    </div>
  );
}
