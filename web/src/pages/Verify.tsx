import { ShieldCheck, ShieldX } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { publicVerify } from "../api/client";
import { Brand, ThemeSync } from "../components/AppShell";
import { VerdictBadge } from "../components/SeverityBadge";
import { ErrorState, Loading, Mono } from "../components/ui";

/** Public QR target (US-018): shows report signature status in large type. */
export default function VerifyPage() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["public-verify", id], queryFn: () => publicVerify(id) });
  const d = q.data;
  const ok = d?.report_signature?.valid && d?.manifest?.ok;
  return (
    <div className="min-h-full flex flex-col items-center p-6">
      <ThemeSync />
      <div className="mb-8"><Brand /></div>
      {q.isLoading ? <Loading label="Checking signatures…" /> : q.error ? <ErrorState error={q.error} /> : (
        <div className="w-full max-w-xl bg-sheet border border-rule rounded-xl p-8 text-center space-y-4">
          {ok ? <ShieldCheck size={72} className="mx-auto text-ok" /> : <ShieldX size={72} className="mx-auto text-critical" />}
          <div className={`text-3xl font-extrabold ${ok ? "text-ok" : "text-critical"}`}>{d.report_signature?.valid ? "Signature valid" : "Signature invalid"}</div>
          <div className="text-ink-2">{d.report_signature?.reason}</div>
          <div className="text-left text-sm space-y-1.5 border-t border-rule pt-4">
            <div className="flex justify-between"><span className="text-ink-2">Case</span><Mono>{d.case_id} · {d.case_name}</Mono></div>
            <div className="flex justify-between"><span className="text-ink-2">Host</span><span>{d.host}</span></div>
            <div className="flex justify-between items-center"><span className="text-ink-2">Verdict</span><VerdictBadge verdict={d.verdict} /></div>
            <div className="flex justify-between gap-3"><span className="text-ink-2 shrink-0">Report SHA-256</span><Mono>{d.report_signature?.sha256}</Mono></div>
            <div className="flex justify-between"><span className="text-ink-2">Signing key</span><Mono>{d.key_fingerprint}</Mono></div>
            <div className="flex justify-between"><span className="text-ink-2">Evidence chain</span>
              <span className={d.manifest.ok ? "text-ok" : "text-critical"}>{d.manifest.ok ? `✔ ${d.manifest.total} artifacts intact` : `✘ ${d.manifest.mismatches} mismatches`}</span></div>
          </div>
        </div>
      )}
    </div>
  );
}
