import { Download } from "lucide-react";
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useEvents, useSummary } from "../api/client";
import type { TimelineEvent } from "../api/types";
import { DataTable } from "../components/DataTable";
import { EvidenceChip } from "../components/EvidenceChip";
import { FilterBar } from "../components/FilterBar";
import { SeverityBadge } from "../components/SeverityBadge";
import { TimelineView } from "../components/TimelineView";
import { Button, Card, Empty, ErrorState, Loading, Mono, PageHeader } from "../components/ui";
import { useFilters } from "../stores/filters";
import { useUi } from "../stores/ui";

const toIso = (v: string) => (v ? new Date(v + (v.length === 16 ? ":00" : "") + "Z").toISOString() : undefined);

export default function TimelinePage() {
  const { id = "" } = useParams();
  const f = useFilters();
  const s = useSummary(id);
  const q = useEvents(id, { severity: f.severity, source: f.source, tactic: f.tactic, q: f.q || undefined, from: toIso(f.from), to: toIso(f.to) });
  const [sel, setSel] = useState<number | null>(null);
  const open = useUi((u) => u.openEvidence);
  const events = q.data?.items ?? [];
  const byId = useMemo(() => new Map(events.map((e) => [e.id, e])), [events]);
  return (
    <div className="space-y-4">
      <PageHeader title="Timeline" subtitle={`${q.data?.total ?? 0} events · all times UTC · drag to pan, scroll to zoom`}
        actions={<>
          <a href={`/api/cases/${id}/report/file/timeline.csv`}><Button><Download size={14} />CSV</Button></a>
          <a href={`/api/cases/${id}/report/file/timeline.jsonl`}><Button><Download size={14} />JSONL (Timesketch)</Button></a>
        </>} />
      <FilterBar filters={f} onChange={f.set} sources={q.data?.sources ?? []} tactics={q.data?.tactics ?? []} />
      {q.error ? <ErrorState error={q.error} /> : q.isLoading ? <Loading /> : !events.length ? <Card><Empty title="No events match these filters" /></Card> : (
        <>
          <TimelineView events={events} phases={s.data?.phases} currentId={sel} focusOnCurrent={false} height={380}
            onSelect={(eid) => { setSel(eid); const e = byId.get(eid); if (e) open(e.evidence_ref); }} />
          <DataTable<TimelineEvent> rows={events} onRowClick={(e) => { setSel(e.id); open(e.evidence_ref); }}
            rowClass={(e) => (e.id === sel ? "bg-accent/10" : "")}
            columns={[
              { key: "t", header: "Time (UTC)", width: "110px", sort: (e) => e.timestamp_utc, render: (e) => <Mono>{e.timestamp_utc.slice(11, 23)}</Mono> },
              { key: "sev", header: "Severity", width: "90px", sort: (e) => ["Info", "Low", "Medium", "High", "Critical"].indexOf(e.severity), render: (e) => <SeverityBadge severity={e.severity} /> },
              { key: "att", header: "ATT&CK", width: "90px", render: (e) => <Mono className="text-muted">{e.attck_id}</Mono> },
              { key: "d", header: "Event", render: (e) => <div><div>{e.description}</div><div className="text-[11.5px] text-muted">{e.phase} · {e.event_type}</div></div> },
              { key: "src", header: "Evidence", width: "230px", render: (e) => <EvidenceChip evidenceRef={e.evidence_ref} /> },
            ]} />
        </>
      )}
    </div>
  );
}
