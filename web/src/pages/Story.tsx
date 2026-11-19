import { useEffect, useMemo } from "react";
import { useParams } from "react-router-dom";
import { useEvents, useGraph, useSummary } from "../api/client";
import { AttackGraph, Legend } from "../components/AttackGraph";
import { EvidenceChip } from "../components/EvidenceChip";
import { CaptionBar, ReplayControls } from "../components/ReplayControls";
import { TimelineView } from "../components/TimelineView";
import { Empty, ErrorState, Loading } from "../components/ui";
import { useReplay } from "../stores/replay";

/** Attack story (US-013): graph on top 55 %, timeline below 35 %, caption + controls at the bottom.
 *  The current event pulses on both views at once. */
export default function Story() {
  const { id = "" } = useParams();
  const includeAll = useReplay((s) => s.includeAll);
  const index = useReplay((s) => s.index);
  const setIndex = useReplay((s) => s.setIndex);
  const reset = useReplay((s) => s.reset);
  const ev = useEvents(id, includeAll ? {} : { severity: ["Critical", "High"] });
  const g = useGraph(id);
  const s = useSummary(id);
  useEffect(() => { reset(); }, [id, reset]);

  const events = ev.data?.items ?? [];
  const cur = index >= 0 ? events[index] : null;
  const shown = useMemo(() => (index >= 0 ? new Set(events.slice(0, index + 1).map((e) => e.id)) : null), [events, index]);
  const nodeForEvent = useMemo(() => {
    if (!cur || !g.data) return null;
    const ns = g.data.nodes.filter((n) => n.event_ids.includes(cur.id));
    return (ns.find((n) => n.type === "process") ?? ns.find((n) => n.severity === cur.severity) ?? ns[0])?.id ?? null;
  }, [cur, g.data]);

  if (ev.isLoading || g.isLoading) return <Loading />;
  if (ev.error || g.error) return <ErrorState error={ev.error || g.error} />;
  if (!events.length) return <Empty title="No High or Critical events to replay" hint="Tick “all events” to replay everything, or analyze the case first." />;

  return (
    <div className="flex flex-col gap-3 h-[calc(100vh-7.5rem)] min-h-[620px]">
      <div className="relative bg-surface border border-border rounded-lg overflow-hidden" style={{ flex: "55 1 0" }}>
        <AttackGraph nodes={g.data!.nodes} edges={g.data!.edges} highlightId={nodeForEvent} highlightEdgeEventId={cur?.id} activeEventIds={shown} />
        <div className="absolute left-3 top-2 bg-surface/80 rounded px-2 py-1"><Legend /></div>
      </div>
      <div className="bg-surface border border-border rounded-lg overflow-hidden" style={{ flex: "35 1 0", minHeight: 200 }}>
        <TimelineView events={events} currentId={cur?.id} phases={s.data?.phases} height="100%" onSelect={(eid) => setIndex(events.findIndex((e) => e.id === eid))} />
      </div>
      <div className="bg-surface border border-border rounded-lg px-4 py-2.5 flex flex-col gap-2">
        <div className="flex items-center gap-3 min-w-0"><CaptionBar event={cur} />{cur && <EvidenceChip evidenceRef={cur.evidence_ref} className="shrink-0" />}</div>
        <ReplayControls count={events.length} />
      </div>
    </div>
  );
}
