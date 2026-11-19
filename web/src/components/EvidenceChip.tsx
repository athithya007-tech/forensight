import { FileSearch, X } from "lucide-react";
import { useParams } from "react-router-dom";
import { useEvidenceItem } from "../api/client";
import { useUi } from "../stores/ui";
import { SeverityBadge } from "./SeverityBadge";
import { Loading, Mono, cx } from "./ui";

/** Clicking opens the EvidenceDrawer with the raw record and the file's SHA-256 (FR-29). */
export function EvidenceChip({ evidenceRef, label, className }: { evidenceRef: string; label?: string; className?: string }) {
  const open = useUi((s) => s.openEvidence);
  const [file, anchor] = evidenceRef.replace(/\.evtx\.jsonl/, ".evtx").split("#");
  const base = file.split("/").pop() ?? file;
  const tail = anchor ? `#${anchor.replace(/^EventRecordID=/, "rec ").slice(0, 22)}` : "";
  const short = label ?? `${base.replace("-Operational", "")}${tail}`;
  return (
    <button onClick={(e) => { e.stopPropagation(); open(evidenceRef); }} title={evidenceRef}
      className={cx("inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[11px] text-accent hover:bg-accent/20 max-w-full", className)}>
      <FileSearch size={11} className="shrink-0" /><span className="truncate">{short}</span>
    </button>
  );
}

export function EvidenceDrawer() {
  const { id = "" } = useParams();
  const ref = useUi((s) => s.evidenceRef);
  const close = () => useUi.getState().openEvidence(null);
  const q = useEvidenceItem(id, ref);
  if (!ref) return null;
  const d = q.data;
  let excerpt = d?.excerpt as string | null;
  try { if (excerpt && excerpt.trim().startsWith("{")) excerpt = JSON.stringify(JSON.parse(excerpt), null, 2); } catch { /* not json */ }
  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={close}>
      <div className="absolute inset-0 bg-black/50" />
      <aside className="relative w-full max-w-xl h-full bg-surface border-l border-border shadow-2xl flex flex-col slide-in" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="font-semibold flex items-center gap-2"><FileSearch size={16} className="text-accent" />Evidence</div>
          <button onClick={close} className="text-muted hover:text-text" aria-label="Close"><X size={18} /></button>
        </header>
        <div className="p-4 overflow-auto space-y-4 text-[13px]">
          <div><div className="text-muted text-[12px] mb-1">Reference</div><Mono>{ref}</Mono></div>
          {q.isLoading && <Loading />}
          {d && (
            <>
              <div className="rounded-md border border-border p-3 space-y-1.5">
                <div className="flex justify-between gap-2"><span className="text-muted">File</span><Mono>{d.path}</Mono></div>
                {d.manifest ? (
                  <>
                    <div className="flex justify-between gap-2"><span className="text-muted shrink-0">SHA-256</span><Mono className="text-ok">{d.manifest.sha256}</Mono></div>
                    <div className="flex justify-between"><span className="text-muted">Collected</span><Mono>{d.manifest.collected_at}</Mono></div>
                    <div className="flex justify-between"><span className="text-muted">Manifest entry</span><Mono>#{d.manifest.seq} · {d.manifest.module} · {d.manifest.collector}</Mono></div>
                  </>
                ) : (
                  <div className="text-muted">{d.is_original_evidence ? "Not in manifest" : "Derived analysis output (Volatility); the memory image is the hashed original"}</div>
                )}
              </div>
              {d.event && (
                <div>
                  <div className="flex items-center gap-2 mb-1"><SeverityBadge severity={d.event.severity} /><span className="font-medium">{d.event.event_type}</span>
                    <Mono className="text-muted">{d.event.attck_id}</Mono></div>
                  <div>{d.event.description}</div>
                  <div className="text-muted text-[12px] mt-1">{d.event.timestamp_utc} UTC{d.event.original_tz && d.event.original_tz !== "UTC" ? ` (original ${d.event.original_ts} ${d.event.original_tz})` : ""}</div>
                </div>
              )}
              <div>
                <div className="text-muted text-[12px] mb-1">Raw record</div>
                <pre className="bg-bg border border-border rounded-md p-3 font-mono text-[11.5px] whitespace-pre-wrap break-all max-h-[50vh] overflow-auto">
                  {excerpt ?? JSON.stringify(d.event?.raw_json ?? {}, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </aside>
    </div>
  );
}
