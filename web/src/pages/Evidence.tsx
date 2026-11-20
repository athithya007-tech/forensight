import { CheckCircle2, Link2, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { useParams } from "react-router-dom";
import { useEvidence, useVerify } from "../api/client";
import type { ManifestEntry } from "../api/types";
import { DataTable } from "../components/DataTable";
import { Button, Card, ErrorState, Loading, Mono, PageHeader, fmtBytes } from "../components/ui";

export function ChainStatus({ result }: { result: any }) {
  if (!result) return null;
  const ok = result.ok;
  return (
    <div className={`rounded-lg border p-4 flex items-start gap-3 ${ok ? "border-ok/50 bg-ok/10" : "border-critical/50 bg-critical/10"}`}>
      {ok ? <ShieldCheck className="text-ok shrink-0" /> : <XCircle className="text-critical shrink-0" />}
      <div className="text-sm">
        <div className={`font-bold text-base ${ok ? "text-ok" : "text-critical"}`}>{ok ? "Evidence verified, untouched" : "VERIFICATION FAILED"}</div>
        <div>{result.total} artifacts re-hashed · {result.mismatches} mismatches · hash chain {result.chain_ok ? "intact" : `broken at entry ${result.first_break}`}
          {result.unlisted_files?.length ? ` · ${result.unlisted_files.length} files not in manifest` : ""}</div>
        <div className="text-ink-2">Manifest signature: {result.manifest_signature?.reason}{result.report_signature ? ` · Report signature: ${result.report_signature.reason}` : ""}</div>
        <div className="text-ink-2">Root hash <Mono>{result.root_hash}</Mono></div>
      </div>
    </div>
  );
}

export default function EvidencePage() {
  const { id = "" } = useParams();
  const q = useEvidence(id);
  const v = useVerify(id);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const status = new Map<string, any>((v.data?.entries ?? []).map((e) => [e.path, e]));
  return (
    <div className="space-y-4">
      <PageHeader title="Evidence & chain of custody" subtitle={<>{q.data!.entries.length} evidence files, each fingerprinted with SHA-256 the moment it was collected and linked in a signed chain. Verify proves nothing changed since.</>}
        actions={<Button variant="primary" onClick={() => v.mutate()} disabled={v.isPending}>{v.isPending ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}Verify now</Button>} />
      {v.error && <ErrorState error={v.error} />}
      <ChainStatus result={v.data} />
      <DataTable<ManifestEntry> rows={q.data!.entries} searchText={(e) => `${e.path} ${e.sha256} ${e.module}`}
        rowClass={(e) => (status.get(e.path)?.status === "mismatch" ? "bg-critical/10" : "")}
        columns={[
          { key: "s", header: "", width: "34px", render: (e) => { const s = status.get(e.path); return !s ? <span className="sr-only">not verified yet</span> : s.status === "ok" ? <CheckCircle2 size={16} className="text-ok" /> : <XCircle size={16} className="text-critical" />; } },
          { key: "seq", header: "#", width: "44px", sort: (e) => e.seq, render: (e) => <Mono>{e.seq}</Mono> },
          { key: "p", header: "File", sort: (e) => e.path, render: (e) => <div><span className="font-mono text-xs whitespace-nowrap" title={e.path}>{e.path.replace(/^raw\//, "")}</span>{status.get(e.path)?.problems?.length ? <div className="text-critical text-xs">{status.get(e.path).problems.join("; ")}</div> : null}</div> },
          { key: "m", header: "Module", sort: (e) => e.module, render: (e) => <span className="text-xs">{e.module}</span> },
          { key: "sz", header: "Size", sort: (e) => e.size, render: (e) => <span className="tnum text-xs whitespace-nowrap">{fmtBytes(e.size)}</span> },
          { key: "h", header: "SHA-256 fingerprint", render: (e) => <span className="font-mono text-2xs text-ink-2 break-all leading-snug block max-w-[22rem]">{e.sha256}</span> },
          { key: "c", header: "Chain link", width: "120px", render: (e) => <span className="inline-flex items-center gap-1 text-2xs text-ink-2 whitespace-nowrap" title={`entry_hash ${e.entry_hash}`}><Link2 size={11} /><span className="font-mono">{e.entry_hash.slice(0, 10)}…</span></span> },
        ]} />
      <Card title="Audit log (latest)"><pre className="font-mono text-xs text-ink-2 max-h-72 overflow-auto whitespace-pre-wrap">{q.data!.audit.join("\n")}</pre></Card>
    </div>
  );
}
