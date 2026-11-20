import { useEffect, useMemo } from "react";
import { useParams } from "react-router-dom";
import { useEvents, useGraph, useSummary } from "../api/client";
import { AttackGraph, Legend } from "../components/AttackGraph";
import { EvidenceChip } from "../components/EvidenceChip";
import { TimeScale } from "../components/ForensicScale";
import { CaptionBar, ReplayControls } from "../components/ReplayControls";
import { TimelineView } from "../components/TimelineView";
import { Empty, ErrorState, Loading } from "../components/ui";
import { useReplay } from "../stores/replay";

let lastCase = "";  // keep a replay position chosen on the Summary scale; reset only when the case changes

/** Attack story (US-013): graph 55 %, timeline 35 %, caption + scale + controls at the bottom.
 *  The current event is marked on the graph, the timeline and the forensic scale at once. */
export default function Story() {
  const { id = "" } = useParams();
  const includeAll = useReplay((s) => s.includeAll);
  const index = useReplay((s) => s.index);
  const setIndex = useReplay((s) => s.setIndex);
  const reset = useReplay((s) => s.reset);
  const ev = useEvents(id, includeAll ? {} : { severity: ["Critical", "High"] });
  const g = useGraph(id);
  const s = useSummary(id);
  useEffect(() => { if (lastCase !== id) { reset(); lastCase = id; } }, [id, reset]);

  const events = ev.data?.items ?? [];
  const cur = index >= 0 ? events[index] : null;
  const shown = useMemo(() => (index >= 0 ? new Set(events.slice(0, index + 1).map((e) => e.id)) : null), [events, index]);
  const nodeForEvent = useMemo(() => {
    if (!cur || !g.data) return null;
    const ns = g.data.nodes.filter((n) => n.event_ids.includes(cur.id));
    return (ns.find((n) => n.type === "process") ?? ns.find((n) => n.severity === cur.severity) ?? ns[0])?.id ?? null;
  }, [cur, g.data]);
  // sparse overview (flowchart skill): only entities touched by the events being replayed, and edges between them
  const sparse = useMemo(() => {
    if (!g.data) return null;
    const evIds = new Set(events.map((e) => e.id));
    const nodes = g.data.nodes.filter((n) => n.event_ids.some((i) => evIds.has(i)));
    const keep = new Set(nodes.map((n) => n.id));
    // keep one hop of context so the story stays connected (e.g. the account that spawned a flagged process)
    g.data.edges.forEach((e) => { if (evIds.has(e.event_id)) { keep.add(e.source); keep.add(e.target); } });
    const all = g.data.nodes.filter((n) => keep.has(n.id));
    return { nodes: all, edges: g.data.edges.filter((e) => keep.has(e.source) && keep.has(e.target)) };
  }, [g.data, events]);
  const times = events.map((e) => Date.parse(e.timestamp_utc));
  const t0 = Math.min(...times), t1 = Math.max(...times), pad = Math.max(20_000, (t1 - t0) * 0.03);

  if (ev.isLoading || g.isLoading) return <Loading />;
  if (ev.error || g.error) return <ErrorState error={ev.error || g.error} />;
  if (!events.length) return <Empty title="Nothing high-severity to replay" hint="Tick “Include low-severity events” to replay the full timeline, or analyze the case first." />;

  return (
    <div className="flex flex-col gap-3 h-[calc(100vh-7rem)] min-h-[620px] -mx-1">
      <div className="relative bg-sheet border border-rule rounded-lg overflow-hidden shadow-sheet flex flex-col" style={{ flex: "60 1 0" }}>
        <div className="px-4 py-2 border-b border-rule flex items-center justify-between gap-4"><Legend />
          <span className="text-xs text-ink-2 shrink-0">{sparse?.nodes.length} of {g.data?.nodes.length} entities, those touched by this replay</span></div>
        <div className="flex-1 min-h-0"><AttackGraph nodes={sparse!.nodes} edges={sparse!.edges} highlightId={nodeForEvent} highlightEdgeEventId={cur?.id} activeEventIds={shown} compact /></div>
      </div>
      <div className="bg-sheet border border-rule rounded-lg overflow-hidden" style={{ flex: "30 1 0", minHeight: 170 }}>
        <TimelineView events={events} currentId={cur?.id} phases={s.data?.phases} height="100%" onSelect={(eid) => setIndex(events.findIndex((e) => e.id === eid))} />
      </div>
      <div className="bg-sheet border border-rule rounded-lg px-5 pt-3 pb-3 shadow-sheet">
        <div className="flex items-center gap-3 min-w-0 min-h-[30px]"><CaptionBar event={cur} />{cur && <EvidenceChip evidenceRef={cur.evidence_ref} className="shrink-0" />}</div>
        <div className="mt-2">
          <TimeScale start={t0 - pad} end={t1 + pad} height={40} cursor={cur ? Date.parse(cur.timestamp_utc) : null}
            onMark={(eid) => setIndex(events.findIndex((e) => e.id === eid))}
            marks={events.map((e) => ({ t: Date.parse(e.timestamp_utc), severity: e.severity, id: e.id, label: e.description.slice(0, 60) }))} />
        </div>
        <div className="mt-1"><ReplayControls count={events.length} /></div>
      </div>
    </div>
  );
}
