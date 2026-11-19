import { Download, FileText, Loader2, QrCode, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getJob, startReport, useReportStatus } from "../api/client";
import { Button, Card, Empty, ErrorState, Loading, Mono, PageHeader } from "../components/ui";

const FILES: [string, string][] = [["report.pdf", "PDF report (signed)"], ["report.html", "HTML report"], ["report.sig", "Ed25519 signature"], ["iocs.csv", "IOCs (CSV)"],
  ["iocs.stix.json", "IOCs (STIX 2.1)"], ["timeline.csv", "Timeline (CSV)"], ["timeline.json", "Timeline (JSON)"]];

export function DownloadButtons({ id, files }: { id: string; files: Record<string, boolean> }) {
  return (
    <div className="flex flex-col gap-2">
      {FILES.filter(([f]) => files[f]).map(([f, label]) => (
        <a key={f} href={`/api/cases/${id}/report/file/${f}`} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 hover:border-accent text-[13px]">
          <Download size={14} className="text-accent" /><span className="flex-1">{label}</span><Mono className="text-muted">{f}</Mono></a>
      ))}
    </div>
  );
}

export default function ReportPage() {
  const { id = "" } = useParams();
  const q = useReportStatus(id);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ai, setAi] = useState(false);
  const [v, setV] = useState(0);
  async function gen() {
    setBusy(true); setErr(null);
    try {
      const { job } = await startReport(id, ai);
      for (;;) { await new Promise((r) => setTimeout(r, 800)); const j = await getJob(job); if (j.status === "failed") throw new Error(j.error); if (j.status === "done") break; }
      await q.refetch(); setV((x) => x + 1);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const has = q.data!.files["report.pdf"];
  return (
    <div className="space-y-4">
      <PageHeader title="Report" subtitle={q.data!.meta ? <>Generated {q.data!.meta.generated_at} · content hash <Mono>{q.data!.meta.content_hash.slice(0, 16)}</Mono>{q.data!.meta.ai ? " · includes AI summary" : ""}</> : "No report yet"}
        actions={<>
          <label className="inline-flex items-center gap-1.5 text-[13px] text-muted" title="Needs Ollama running locally; labelled AI-generated"><input type="checkbox" checked={ai} onChange={(e) => setAi(e.target.checked)} className="accent-[#22D3EE]" />AI summary</label>
          <Button variant="primary" onClick={gen} disabled={busy}>{busy ? <Loader2 size={14} className="animate-spin" /> : has ? <RefreshCw size={14} /> : <FileText size={14} />}{has ? "Regenerate" : "Generate report"}</Button>
          <Link to={`/verify/${id}`} target="_blank"><Button><QrCode size={14} />Verify page</Button></Link>
        </>} />
      {err && <ErrorState error={err} />}
      <div className="grid lg:grid-cols-3 gap-4">
        <Card title="Preview" className="lg:col-span-2" bodyClass="p-0">
          {has ? <iframe key={v} title="Report preview" src={`/api/cases/${id}/report/pdf#view=FitH`} className="w-full h-[75vh] rounded-b-lg bg-white" />
            : <Empty title="No report generated" hint="Generate the signed PDF: executive summary, scope, timeline, findings, IOCs, ATT&CK map, recommendations, chain of custody." />}
        </Card>
        <Card title="Downloads"><DownloadButtons id={id} files={q.data!.files} /></Card>
      </div>
    </div>
  );
}
