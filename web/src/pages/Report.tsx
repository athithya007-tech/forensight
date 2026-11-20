import { Download, FileText, Loader2, QrCode, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { STATIC, fileUrl, getJob, pdfUrl, startReport, useHealth, useReportStatus, useSummary } from "../api/client";
import { Button, Card, Empty, ErrorState, Loading, Mono, PageHeader, cx, fmtDateTime } from "../components/ui";

const FILES: [string, string, string][] = [
  ["report.pdf", "Signed PDF report", "For managers, legal and the case file"],
  ["report.html", "Web version of the report", "Same content, opens in any browser"],
  ["report.sig", "Digital signature", "Proves the PDF was not edited"],
  ["iocs.csv", "Indicators of compromise (CSV)", "IPs, file fingerprints, accounts to search for"],
  ["iocs.stix.json", "Indicators (STIX 2.1)", "For threat-intel platforms"],
  ["timeline.csv", "Timeline (CSV)", "Opens in Excel"],
  ["timeline.json", "Timeline (JSON)", "For scripts and Timesketch"],
];

export function DownloadButtons({ id, files }: { id: string; files: Record<string, boolean> }) {
  const avail = FILES.filter(([f]) => files[f]);
  if (!avail.length) return <p className="text-sm text-ink-2">Downloads appear here once the report is generated.</p>;
  return (
    <ul className="flex flex-col gap-2">
      {avail.map(([f, label, hint]) => (
        <li key={f}>
          <a href={fileUrl(id, f)} download={STATIC ? f : undefined} className="group flex items-start gap-3 rounded border border-rule bg-paper px-3 py-2.5 hover:border-ink transition-colors">
            <Download size={15} className="text-ink-2 group-hover:text-ink mt-0.5 shrink-0" />
            <span className="min-w-0"><span className="block text-sm font-medium text-ink">{label}</span>
              <span className="block text-xs text-ink-2">{hint}</span></span>
          </a>
        </li>
      ))}
    </ul>
  );
}

export default function ReportPage() {
  const { id = "" } = useParams();
  const q = useReportStatus(id);
  const s = useSummary(id);
  const health = useHealth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ai, setAi] = useState(false);
  const [v, setV] = useState(0);
  const aiAvailable = !!health.data?.ollama;
  const analyzed = !!s.data?.analyzed;
  async function gen() {
    setBusy(true); setErr(null);
    try {
      const { job } = await startReport(id, ai && aiAvailable);
      for (;;) { await new Promise((r) => setTimeout(r, 700)); const j = await getJob(job); if (j.status === "failed") throw new Error(j.error); if (j.status === "done") break; }
      await q.refetch(); setV((x) => x + 1);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }
  if (q.isLoading || s.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const has = q.data!.files["report.pdf"];
  const meta = q.data!.meta;
  return (
    <div className="space-y-5">
      <PageHeader title="Report"
        subtitle={meta && has ? <>Generated {fmtDateTime(meta.generated_at)} UTC and signed. Content hash <Mono>{meta.content_hash.slice(0, 16)}</Mono>{meta.ai ? ". Includes an AI-written summary." : "."}</>
          : "A signed PDF that explains the incident in plain words for managers and legal, with the full evidence in the appendices."}
        actions={<>
          <label className={cx("inline-flex items-center gap-1.5 text-sm", aiAvailable ? "text-ink-2 cursor-pointer" : "text-ink-2/60 cursor-not-allowed")}
            title={aiAvailable ? "Adds a summary written by your local AI model, clearly labelled AI-generated" : "Needs Ollama running on this computer (ollama.com). The report is complete without it."}>
            <input type="checkbox" checked={ai && aiAvailable} disabled={!aiAvailable} onChange={(e) => setAi(e.target.checked)} className="accent-[rgb(var(--ink))]" />
            AI summary{!aiAvailable && <span className="text-xs">(Ollama not running)</span>}
          </label>
          <Button variant="primary" onClick={gen} busy={busy} disabled={!analyzed || STATIC} title={STATIC ? "Not available in the online demo" : analyzed ? undefined : "Analyze the case first"}>
            {!busy && (has ? <RefreshCw size={14} /> : <FileText size={14} />)}{busy ? "Generating…" : has ? "Regenerate" : "Generate report"}
          </Button>
          {has && <Link to={`/verify/${id}`} target="_blank"><Button><QrCode size={14} />Check signature</Button></Link>}
        </>} />
      {err && <ErrorState error={err} title="The report could not be generated" hint="The full error is in this case's audit.log. Everything else in the dashboard keeps working." />}
      <div className="grid lg:grid-cols-[1fr_340px] gap-5 items-start">
        <Card title="Preview" note={has ? "This is the signed PDF. Use Downloads to save it." : undefined} bodyClass="!px-0 !pb-0">
          {has ? (
            <object key={v} data={`${pdfUrl(id)}#view=FitH&toolbar=0`} type="application/pdf" aria-label="Report preview"
              className="w-full h-[78vh] rounded-b-lg bg-well border-t border-rule">
              {/* browsers without a PDF viewer get the web version */}
              <iframe title="Report preview (web version)" src={STATIC ? fileUrl(id, "report.html") : `/api/cases/${id}/report/file/report.html?inline=true`} className="w-full h-[78vh] bg-white" />
            </object>
          ) : (
            <div className="px-5 pb-5">
              <Empty title={analyzed ? "No report yet" : "Analyze the case first"}
                hint={analyzed ? <>Press <b>Generate report</b>. Page 1 gives the verdict, the attack measured in time, what happened step by step and what to do now.
                  The appendices hold the timeline, findings, ATT&CK map, indicators and the chain of custody.</>
                  : "The report is built from the analysis. Use “Analyze now” at the top of this page."} />
            </div>
          )}
        </Card>
        <Card title="Downloads"><DownloadButtons id={id} files={q.data!.files} /></Card>
      </div>
    </div>
  );
}
