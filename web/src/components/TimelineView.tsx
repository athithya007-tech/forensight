import { useEffect, useRef } from "react";
import { DataSet, Timeline } from "vis-timeline/standalone";
import "vis-timeline/styles/vis-timeline-graph2d.min.css";
import type { Phase, TimelineEvent } from "../api/types";

const short = (s: string) => s.replace(".evtx.jsonl", "").replace(".evtx", "").replace("-Operational", "");

/** vis-timeline wrapper: grouped by source, coloured by severity, zoomable; highlights the replay's current event. */
export function TimelineView({ events, currentId, onSelect, phases, height = 360, focusOnCurrent = true }:
  { events: TimelineEvent[]; currentId?: number | null; onSelect?: (id: number) => void; phases?: Phase[]; height?: number | string; focusOnCurrent?: boolean }) {
  const el = useRef<HTMLDivElement>(null);
  const tl = useRef<Timeline | null>(null);
  const items = useRef(new DataSet<any>());
  const onSel = useRef(onSelect);
  onSel.current = onSelect;

  useEffect(() => {
    if (!el.current) return;
    const t = new Timeline(el.current, items.current, {
      height, stack: true, zoomMin: 5_000, zoomMax: 1000 * 60 * 60 * 24 * 14, orientation: { axis: "top" },
      margin: { item: { horizontal: 2, vertical: 4 } }, showCurrentTime: false, tooltip: { followMouse: true, overflowMethod: "cap" },
      groupOrder: "content",
    } as any);
    t.on("select", (p: any) => { const id = p.items?.[0]; if (typeof id === "number") onSel.current?.(id); });
    tl.current = t;
    return () => { t.destroy(); tl.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const t = tl.current;
    if (!t) return;
    const groups = Array.from(new Set(events.map((e) => short(e.source)))).sort();
    t.setGroups(new DataSet(groups.map((g) => ({ id: g, content: g }))) as any);
    items.current.clear();
    const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
    items.current.add(events.map((e) => ({
      id: e.id, start: e.timestamp_utc, group: short(e.source), type: "box",
      content: esc((e.attck_id ? `${e.attck_id} · ` : "") + (e.event_type.replace(/_/g, " "))),
      title: `<b>${e.timestamp_utc.slice(11, 19)} UTC · ${e.severity}</b><br/>${esc(e.description.slice(0, 220))}`,
      className: `sev-${e.severity}`,
    })));
    (phases ?? []).forEach((p) => items.current.add({ id: `phase-${p.index}`, start: p.start, end: new Date(new Date(p.end).getTime() + 20_000).toISOString(),
      type: "background", className: "phase", content: p.label }));
    if (events.length) {
      const ts = events.map((e) => +new Date(e.timestamp_utc));
      const min = Math.min(...ts), max = Math.max(...ts), pad = Math.max(60_000, (max - min) * 0.05);
      t.setWindow(new Date(min - pad), new Date(max + pad), { animation: false });
    }
  }, [events, phases]);

  useEffect(() => {
    const t = tl.current;
    if (!t) return;
    events.forEach((e) => {
      const cls = `sev-${e.severity}${e.id === currentId ? " current" : ""}`;
      const it = items.current.get(e.id);
      if (it && it.className !== cls) items.current.update({ id: e.id, className: cls });
    });
    if (currentId != null && items.current.get(currentId)) {
      t.setSelection([currentId]);
      if (focusOnCurrent) t.moveTo(items.current.get(currentId).start, { animation: { duration: 400, easingFunction: "easeInOutQuad" } });
    }
  }, [currentId, events, focusOnCurrent]);

  return <div ref={el} className="w-full h-full" />;
}
