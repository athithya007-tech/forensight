import { FileSearch, X } from "lucide-react";
import { useParams } from "react-router-dom";
import { useEvidenceItem } from "../api/client";
import { useUi } from "../stores/ui";
import { Glyph } from "./Glyph";
import { SeverityBadge } from "./SeverityBadge";
import { Loading, Mono, cx } from "./ui";

/** Exhibit tag: a punched evidence label carrying the source file and record anchor. */

/** Clicking opens the EvidenceDrawer with the raw record and the file's SHA-256 (FR-29). */
export function EvidenceChip({ evidenceRef, label, className }: { evidenceRef: string; label?: string; className?: string }) {
  const open = useUi((s) => s.openEvidence);
  const [file, anchor] = evidenceRef.replace(/\.evtx\.jsonl/, ".evtx").split("#");
  const base = file.split("/").pop() ?? file;
  const tail = anchor ? `#${anchor.replace(/^EventRecordID=/, "rec ").slice(0, 22)}` : "";
  const short = label ?? `${base.replace("-Operational", "")}${tail}`;
  return (
    <button onClick={(e) => { e.stopPropagation(); open(evidenceRef); }} title={`Open evidence: ${evidenceRef}`} aria-label={`Open evidence ${label ?? ""} ${evidenceRef}`.replace("  ", " ")}
      className={cx("group inline-flex items-center gap-1.5 rounded-sm border border-rule bg-paper pl-1.5 pr-2 h-6 font-mono text-2xs text-ink",
        "hover:border-ink hover:bg-sheet transition-colors duration-150 max-w-full", className)}>
      <span className="w-1.5 h-1.5 rounded-full border border-ink-2 bg-sheet shrink-0 group-hover:border-tape" aria-hidden />
      <span className="truncate">{short}</span>
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
      <div className="absolute inset-0 bg-ink/30" />
      <aside role="dialog" aria-label="Evidence" className="relative w-full max-w-xl h-full bg-sheet border-l border-rule shadow-lift flex flex-col rise" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-start justify-between px-6 pt-5 pb-4 border-b border-rule">
          <div>
            <div className="h-display text-xl flex items-center gap-2"><Glyph name="evidence-bag" size={20} className="text-tape" />Exhibit</div>
            <Mono className="text-ink-2">{ref}</Mono>
          </div>
          <button onClick={close} className="text-ink-2 hover:text-ink p-1" aria-label="Close evidence"><X size={18} /></button>
        </header>
        <div className="px-6 py-5 overflow-auto space-y-5 text-sm">
          {q.isLoading && <Loading />}
          {d && (
            <>
              <dl className="grid grid-cols-[7.5rem_1fr] gap-x-4 gap-y-2 border-y border-rule py-3">
                <dt className="label">File</dt><dd><Mono>{d.path}</Mono></dd>
                {d.manifest ? (
                  <>
                    <dt className="label">SHA-256</dt><dd><Mono className="text-ok">{d.manifest.sha256}</Mono></dd>
                    <dt className="label">Collected</dt><dd><Mono>{d.manifest.collected_at}</Mono></dd>
                    <dt className="label">Custody entry</dt><dd><Mono>#{d.manifest.seq} · {d.manifest.module} · {d.manifest.collector}</Mono></dd>
                  </>
                ) : (
                  <><dt className="label">Custody</dt><dd className="text-ink-2">{d.is_original_evidence ? "Not in the manifest" : "Derived analysis output (Volatility). The memory image is the hashed original."}</dd></>
                )}
              </dl>
              {d.event && (
                <div>
                  <div className="flex items-center gap-3 mb-1.5"><SeverityBadge severity={d.event.severity} /><span className="text-xs text-ink-2">{d.event.event_type.replace(/_/g, " ")}</span>
                    <Mono className="text-ink-2">{d.event.attck_id}</Mono></div>
                  <div className="text-base text-ink break-words">{d.event.description}</div>
                  <div className="text-ink-2 text-xs mt-1 font-mono">{d.event.timestamp_utc} UTC{d.event.original_tz && d.event.original_tz !== "UTC" ? ` (original ${d.event.original_ts} ${d.event.original_tz})` : ""}</div>
                </div>
              )}
              <div>
                <div className="label mb-1.5">Raw record, as collected</div>
                <pre className="bg-well border border-rule rounded p-3 font-mono text-[11.5px] leading-relaxed text-ink whitespace-pre-wrap break-all max-h-[50vh] overflow-auto">
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
