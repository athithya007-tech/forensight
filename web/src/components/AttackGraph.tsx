import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import { useEffect, useRef, useState } from "react";
import type { GraphEdge, GraphNode } from "../api/types";
import { useUi } from "../stores/ui";

cytoscape.use(dagre);

/** Colour encodes three meaningful groups (flowchart skill: colour only for real groups);
 *  shape + an icon tell the types inside a group apart. Severity is a halo, never a fill. */
export const NODE_STYLE: Record<string, { group: "actor" | "execution" | "footprint"; shape: string; label: string }> = {
  ip: { group: "actor", shape: "diamond", label: "IP address" },
  user: { group: "actor", shape: "ellipse", label: "Account" },
  process: { group: "execution", shape: "round-rectangle", label: "Process" },
  file: { group: "footprint", shape: "round-rectangle", label: "File" },
  registry: { group: "footprint", shape: "round-hexagon", label: "Registry key" },
  service: { group: "footprint", shape: "round-octagon", label: "Service" },
  task: { group: "footprint", shape: "round-tag", label: "Scheduled task" },
};
export const GROUP_VAR = { actor: "--grp-actor", execution: "--grp-exec", footprint: "--grp-foot" } as const;
export const EDGE_WORDS: Record<string, string> = {
  logged_in_as: "logged in as", spawned: "started", wrote: "wrote", connected_to: "connected to",
  created: "created", persisted_via: "persisted via", granted_admin: "granted admin to",
};
/** Relationship families: each gets one colour so the eye can follow "how" things are linked. */
export const EDGE_FAMILY: Record<string, { fam: "control" | "network" | "persist" | "write"; label: string }> = {
  spawned: { fam: "control", label: "started a program" },
  logged_in_as: { fam: "network", label: "access" }, connected_to: { fam: "network", label: "network" },
  persisted_via: { fam: "persist", label: "persistence" }, created: { fam: "persist", label: "persistence" }, granted_admin: { fam: "persist", label: "persistence" },
  wrote: { fam: "write", label: "wrote a file" },
};
const FAM_VAR = { control: "--ink-2", network: "--grp-actor", persist: "--tape", write: "--grp-foot" } as const;
export const FAMILIES: [keyof typeof FAM_VAR, string][] = [["network", "Access & network"], ["control", "Started a program"], ["write", "Wrote a file"], ["persist", "Persistence"]];
export const LANES = [
  { id: "lane:actor", title: "1 · WHO GOT IN", group: "actor" },
  { id: "lane:execution", title: "2 · WHAT RAN", group: "execution" },
  { id: "lane:footprint", title: "3 · WHAT STAYED BEHIND", group: "footprint" },
] as const;

/** Small white pictograms drawn inside each node (24-unit grid, 1.8 stroke) so a type reads without the legend. */
const ICON_PATH: Record<string, string> = {
  ip: '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.5 2.6 2.5 13.4 0 16M12 4c-2.5 2.6-2.5 13.4 0 16"/>',
  user: '<circle cx="12" cy="9" r="3.6"/><path d="M5 20c.8-3.8 3.6-5.6 7-5.6s6.2 1.8 7 5.6"/>',
  process: '<path d="M5 8l4 4-4 4M11 17h8"/>',
  file: '<path d="M7 3.5h7l4 4V20.5H7z"/><path d="M14 3.5v4h4M9.5 12.5h6M9.5 16h6"/>',
  registry: '<circle cx="8.5" cy="12" r="3.5"/><path d="M12 12h8.5M17.5 12v3M20.5 12v2"/>',
  service: '<circle cx="12" cy="12" r="3"/><path d="M12 4v3M12 17v3M4 12h3M17 12h3M6.3 6.3l2.1 2.1M15.6 15.6l2.1 2.1M6.3 17.7l2.1-2.1M15.6 8.4l2.1-2.1"/>',
  task: '<circle cx="12" cy="12" r="8"/><path d="M12 7.5V12l3 2"/>',
};
const iconUri = (t: string) => "data:image/svg+xml;utf8," + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="white" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${ICON_PATH[t] ?? '<circle cx="12" cy="12" r="4"/>'}</svg>`);

function cssRgb(name: string, alpha = 1) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return alpha === 1 ? `rgb(${v.split(" ").join(",")})` : `rgba(${v.split(" ").join(",")},${alpha})`;
}

export type GraphLayout = "lanes" | "dagre" | "cose";

/** Cytoscape attack graph (US-016). Data binding is unchanged: nodes/edges straight from /graph.
 *  Graph page extras: story lanes, replay cutoff, search, type filter, and an onReady handle for zoom/export. */
export function AttackGraph({ nodes, edges, highlightId, highlightEdgeEventId, onSelect, layout = "dagre", activeEventIds, compact = false,
  cutoff, liveEdgeId, query, hiddenTypes, onReady }:
  { nodes: GraphNode[]; edges: GraphEdge[]; highlightId?: string | null; highlightEdgeEventId?: number | null; onSelect?: (n: GraphNode | null) => void;
    layout?: GraphLayout; activeEventIds?: Set<number> | null; compact?: boolean;
    cutoff?: string | null; liveEdgeId?: number | null; query?: string; hiddenTypes?: Set<string>; onReady?: (c: Core | null) => void }) {
  const el = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const onSel = useRef(onSelect);
  onSel.current = onSelect;
  const ready = useRef(onReady);
  ready.current = onReady;
  const theme = useUi((s) => s.theme);
  const [tip, setTip] = useState<{ x: number; y: number; text: string } | null>(null);

  useEffect(() => {
    if (!el.current) return;
    const ink = cssRgb("--ink"), ink2 = cssRgb("--ink-2"), sheet = cssRgb("--sheet"), rule = cssRgb("--rule");
    const sev = { Critical: cssRgb("--sev-critical"), High: cssRgb("--sev-high") } as Record<string, string>;
    const grp = { actor: cssRgb(GROUP_VAR.actor), execution: cssRgb(GROUP_VAR.execution), footprint: cssRgb(GROUP_VAR.footprint) };
    const fam = Object.fromEntries(Object.entries(FAM_VAR).map(([k, v]) => [k, cssRgb(v)])) as Record<string, string>;
    const amber = cssRgb("--amber");
    const ids = new Set(nodes.map((n) => n.id));
    const deg = new Map<string, number>();
    edges.forEach((e) => { deg.set(e.source, (deg.get(e.source) ?? 0) + 1); deg.set(e.target, (deg.get(e.target) ?? 0) + 1); });
    const lanes = layout === "lanes" && !compact;
    const groupOf = (t: string) => NODE_STYLE[t]?.group ?? "footprint";
    const usedGroups = new Set(nodes.map((n) => groupOf(n.type)));
    const c = cytoscape({
      container: el.current,
      elements: [
        ...(lanes ? LANES.filter((l) => usedGroups.has(l.group)).map((l) => ({ data: { id: l.id, label: l.title, lane: l.group }, classes: "lane", selectable: false, grabbable: false })) : []),
        ...nodes.map((n) => {
          const st = NODE_STYLE[n.type];
          const size = compact ? 30 : Math.min(lanes ? 38 : 48, (lanes ? 28 : 32) + 3 * Math.max(0, (deg.get(n.id) ?? 1) - 1));
          return { data: { ...n, parent: lanes ? `lane:${groupOf(n.type)}` : undefined, fill: st ? grp[st.group] : ink2, shape: st?.shape ?? "ellipse",
            icon: iconUri(n.type), size, halo: sev[n.severity] ?? sheet, haloOp: sev[n.severity] ? (n.severity === "Critical" ? 0.32 : 0.2) : 0,
            short: n.label.length > 26 ? n.label.slice(0, 24) + "…" : n.label, first: firstTs(n, edges) } };
        }),
        ...edges.filter((e) => ids.has(e.source) && ids.has(e.target))
          .map((e) => ({ data: { id: `e${e.id}`, eid: e.id, source: e.source, target: e.target, label: e.type, event_id: e.event_id, ts: e.ts,
            color: fam[EDGE_FAMILY[e.type]?.fam ?? "control"] } })),
      ],
      style: ([
        // node: group colour fill + white pictogram; label below on a paper chip so edges never run through text
        { selector: "node", style: { "background-color": "data(fill)", shape: "data(shape)" as any, width: "data(size)", height: "data(size)",
          "background-image": "data(icon)", "background-width": "56%", "background-height": "56%", "background-clip": "none",
          "border-color": sheet, "border-width": 2,
          "underlay-color": "data(halo)", "underlay-opacity": "data(haloOp)" as any, "underlay-padding": 7, "underlay-shape": "ellipse" as any,
          label: "data(short)", color: ink, "font-size": compact ? 13.5 : 11.5, "font-family": "Instrument Sans Variable, sans-serif", "font-weight": 500 as any,
          "text-valign": "bottom", "text-margin-y": 7, "text-wrap": "wrap", "text-max-width": "120px",
          "text-background-color": sheet, "text-background-opacity": 0.92, "text-background-padding": "2px", "text-background-shape": "roundrectangle",
          "transition-property": "opacity, border-width, border-color, underlay-opacity", "transition-duration": 200 as any } },
        ...(lanes ? [{ selector: "node[!lane]", style: { "text-valign": "center", "text-halign": "right", "text-margin-x": 7, "text-margin-y": 0, "text-max-width": "170px", "font-size": 13 } }] : []),
        { selector: 'node[severity = "Critical"]', style: { "border-color": sev.Critical, "border-width": 2.5 } },
        // story lanes: quiet tinted columns with an uppercase caption, sitting under everything
        { selector: "node.lane", style: { shape: "round-rectangle", "background-color": rule, "background-opacity": 0.22, "background-image": "none",
          "border-width": 1, "border-style": "dashed", "border-color": rule, padding: "26px" as any, "underlay-opacity": 0,
          label: "data(label)", "text-valign": "top", "text-halign": "center", "text-margin-y": -8, color: ink2, "font-size": 13, "font-weight": 600 as any, "text-wrap": "none",
          "text-background-opacity": 0, "corner-radius": 14 as any, events: "no" as any } },
        { selector: "edge", style: { width: 2.2, "line-color": "data(color)", "target-arrow-color": "data(color)", "target-arrow-shape": "triangle", "arrow-scale": 0.95,
          "line-opacity": 0.75, "curve-style": "bezier", "control-point-step-size": 28,
          "transition-property": "opacity, line-color, width, line-opacity", "transition-duration": 200 as any } },
        { selector: 'edge[label = "persisted_via"], edge[label = "created"], edge[label = "granted_admin"]', style: { "line-style": "dashed", "line-dash-pattern": [7, 4] as any } },
        { selector: "node:selected", style: { "border-color": ink, "border-width": 4 } },
        { selector: ".faded", style: { opacity: 0.08 } },
        { selector: "node.lane.faded", style: { opacity: 1 } },
        { selector: "node.nb", style: { "border-color": amber, "border-width": 4 } },
        { selector: "edge.nb", style: { "line-color": amber, "target-arrow-color": amber, width: 3.2, "line-opacity": 1 } },
        { selector: "node.chain", style: { "border-color": amber, "border-width": 3.5 } },
        { selector: "edge.chain", style: { "line-opacity": 1, width: 3.2 } },
        { selector: "node.hl", style: { "border-color": amber, "border-width": 5, "underlay-color": amber, "underlay-opacity": 0.35, "underlay-padding": 10 } },
        { selector: "edge.hl", style: { "line-color": amber, "target-arrow-color": amber, width: 4, "line-opacity": 1 } },
        { selector: "node.match", style: { "underlay-color": amber, "underlay-opacity": 0.5, "underlay-padding": 11, "border-color": amber, "border-width": 3 } },
        { selector: ".dim", style: { opacity: 0.14 } },
        { selector: ".future", style: { opacity: 0.07 } },
        { selector: "edge.live", style: { "line-color": amber, "target-arrow-color": amber, width: 4.5, "line-opacity": 1, "line-style": "dashed", "line-dash-pattern": [10, 6] as any } },
        { selector: "node.live", style: { "border-color": amber, "border-width": 5, "underlay-color": amber, "underlay-opacity": 0.4, "underlay-padding": 12 } },
        { selector: ".off", style: { display: "none" } },
      ] as any),
      layout: lanes ? ({ name: "preset", positions: laneLayout(nodes, edges), padding: 30 } as any)
        : layout === "dagre" ? ({ name: "dagre", rankDir: "LR", nodeSep: compact ? 40 : 46, rankSep: compact ? 110 : 120, edgeSep: 18, padding: 24 } as any)
        : { name: "cose", padding: 28, animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 110 },
      wheelSensitivity: 0.2, minZoom: 0.2, maxZoom: 3,
    });
    routeAround(c);
    const real = "node[!lane]";
    // hover: fade the unconnected to 8 %, neighbours in amber (tldr-skill pattern)
    c.on("mouseover", real, (e) => {
      const n = e.target, nb = n.closedNeighborhood();
      c.elements().not(nb).not(".lane").addClass("faded");
      nb.not(n).addClass("nb");
      el.current && (el.current.style.cursor = "pointer");
    });
    c.on("mouseout", real, () => { c.elements().removeClass("faded nb"); el.current && (el.current.style.cursor = ""); });
    c.on("mouseover", "edge", (e) => {
      const d = e.target.data(), p = e.renderedPosition;
      const s = c.getElementById(d.source).data("label"), t = c.getElementById(d.target).data("label");
      setTip({ x: p.x, y: p.y, text: `${s} ${EDGE_WORDS[d.label] ?? d.label} ${t} · ${String(d.ts).slice(11, 19)} UTC` });
    });
    c.on("mouseout", "edge", () => setTip(null));
    c.on("tap", real, (e) => {
      // click: light up the whole attack chain running through this node (everything before and after it)
      const n = e.target;
      c.elements().removeClass("chain");
      if (!compact) n.predecessors().union(n.successors()).addClass("chain");
      onSel.current?.(n.data() as GraphNode);
    });
    c.on("tap", (e) => { if (e.target === c) { c.elements().removeClass("chain"); onSel.current?.(null); } });
    c.on("dbltap", real, (e) => c.animate({ fit: { eles: e.target.closedNeighborhood(), padding: 60 } } as any, { duration: 350 }));
    cy.current = c;
    (window as any).__fsGraph = c;  // read by the Playwright graph linter
    ready.current?.(c);
    const fit = () => { c.resize(); c.fit(undefined, 28); if (c.zoom() > 1.25) { c.zoom(1.25); c.center(); } };
    const ro = new ResizeObserver(fit);
    ro.observe(el.current);
    return () => { ro.disconnect(); ready.current?.(null); c.destroy(); cy.current = null; };
  }, [nodes, edges, layout, theme, compact]);

  // Story page + selection highlighting (unchanged behaviour)
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("hl dim");
    if (activeEventIds) {
      c.nodes("[!lane]").forEach((n) => { if (!(n.data("event_ids") as number[]).some((i) => activeEventIds.has(i))) n.addClass("dim"); });
      c.edges().forEach((e) => { if (!activeEventIds.has(e.data("event_id"))) e.addClass("dim"); });
    }
    if (highlightId) {
      const n = c.getElementById(highlightId);
      if (n.nonempty()) n.removeClass("dim").addClass("hl");
    }
    if (highlightEdgeEventId != null) c.edges().filter((e) => e.data("event_id") === highlightEdgeEventId).removeClass("dim").addClass("hl");
  }, [highlightId, highlightEdgeEventId, activeEventIds, nodes, theme]);

  // Replay: everything after the cutoff is a ghost; the live edge marches
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("future live");
    if (!cutoff) return;
    c.edges().forEach((e) => { if (e.data("ts") > cutoff) e.addClass("future"); });
    c.nodes("[!lane]").forEach((n) => { const f = n.data("first"); if (f && f > cutoff) n.addClass("future"); });
    if (liveEdgeId == null) return;
    const live = c.getElementById(`e${liveEdgeId}`);
    live.addClass("live"); live.connectedNodes().addClass("live");
    let off = 0, raf = 0;
    const tick = () => { off -= 0.8; live.style("line-dash-offset", off); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); live.removeStyle("line-dash-offset"); };
  }, [cutoff, liveEdgeId, nodes, theme]);

  // Search + type filter
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("match off");
    if (hiddenTypes?.size) c.nodes("[!lane]").filter((n) => hiddenTypes.has(n.data("type"))).addClass("off");
    c.nodes(".lane").forEach((l) => { if (l.children().not(".off").empty()) l.addClass("off"); });
    const q = query?.trim().toLowerCase();
    if (q) c.nodes("[!lane]").filter((n) => `${n.data("label")} ${n.data("value")}`.toLowerCase().includes(q)).addClass("match");
  }, [query, hiddenTypes, nodes, theme, layout]);

  return (
    <div className="relative w-full h-full min-h-[300px]">
      <div ref={el} className="absolute inset-0" data-testid="attack-graph" />
      {tip && (
        <div className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-[130%] rounded bg-rail text-rail-ink text-xs px-2 py-1 whitespace-nowrap shadow-lift"
          style={{ left: tip.x, top: tip.y }}>{tip.text}</div>
      )}
    </div>
  );
}

function firstTs(n: GraphNode, edges: GraphEdge[]) {
  let f = "";
  for (const e of edges) if ((e.source === n.id || e.target === n.id) && (!f || e.ts < f)) f = e.ts;
  return f;
}

/** "Story lanes": who got in (left) → what ran, as process trees (middle) → what stayed behind (right).
 *  Processes are laid out as trees ordered by time; actors and footprints sit level with what they touch. */
function laneLayout(nodes: GraphNode[], edges: GraphEdge[]) {
  const ROW = 46, COL = 250, GAP = 300;
  const pos: Record<string, { x: number; y: number }> = {};
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const first = new Map(nodes.map((n) => [n.id, firstTs(n, edges) || "9"]));
  const procs = nodes.filter((n) => n.type === "process");
  const kids = new Map<string, string[]>();
  const hasParent = new Set<string>();
  edges.filter((e) => e.type === "spawned" && byId.get(e.source)?.type === "process" && byId.get(e.target)?.type === "process").forEach((e) => {
    if (hasParent.has(e.target) || e.source === e.target) return;
    hasParent.add(e.target);
    kids.set(e.source, [...(kids.get(e.source) ?? []), e.target]);
  });
  const byTime = (a: string, b: string) => (first.get(a)! < first.get(b)! ? -1 : 1);
  let row = 0, maxDepth = 0;
  const seen = new Set<string>();
  const place = (id: string, depth: number) => {
    if (seen.has(id)) return;
    seen.add(id);
    maxDepth = Math.max(maxDepth, depth);
    const ch = (kids.get(id) ?? []).sort(byTime);
    const start = row;
    ch.forEach((k) => place(k, depth + 1));
    const y = ch.length ? (start + row - 1) / 2 : row++;
    pos[id] = { x: GAP + depth * COL, y: y * ROW };
  };
  procs.filter((p) => !hasParent.has(p.id)).map((p) => p.id).sort(byTime).forEach((id) => place(id, 0));
  procs.forEach((p) => place(p.id, 0));
  const footX = GAP + maxDepth * COL + GAP;
  // actors and footprints: level with the average of what they connect to, then pushed apart
  const settle = (list: GraphNode[], x: number) => {
    const want = list.map((n) => {
      const ys = edges.filter((e) => e.source === n.id || e.target === n.id).map((e) => pos[e.source === n.id ? e.target : e.source]?.y).filter((y): y is number => y != null);
      return { id: n.id, y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Infinity };
    }).sort((a, b) => a.y - b.y || byTime(a.id, b.id));
    let last = -Infinity;
    want.forEach((w) => { const next = last === -Infinity ? -Infinity : last + ROW; const y = Math.max(Number.isFinite(w.y) ? w.y : Math.max(next, 0), next); pos[w.id] = { x, y }; last = y; });
    // keep the column inside the height of the process trees where possible (a shorter canvas fits bigger)
    const ys = want.map((w) => pos[w.id].y), top = Math.min(...ys), bottom = Math.max(...ys);
    const pTop = Math.min(0, ...procs.map((p) => pos[p.id]?.y ?? 0)), pBottom = Math.max(0, ...procs.map((p) => pos[p.id]?.y ?? 0));
    const shift = bottom > pBottom ? Math.min(bottom - pBottom, Math.max(0, top - pTop)) : 0;
    want.forEach((w) => (pos[w.id].y -= shift));
  };
  const actors = nodes.filter((n) => NODE_STYLE[n.type]?.group === "actor");
  const foot = nodes.filter((n) => n.type !== "process" && NODE_STYLE[n.type]?.group !== "actor");
  if (procs.length) settle(foot, footX);
  else foot.forEach((n, i) => (pos[n.id] = { x: GAP * 1.5, y: i * ROW })); // no processes: footprints straight across
  settle(actors, 0);
  return pos;
}

/** Bow any edge that would pass behind an unrelated node (flowchart-skill rule), trying growing offsets
 *  on both sides until the path is clear. Runs once after layout; positions are static afterwards. */
function routeAround(c: Core) {
  const nodes = c.nodes("[!lane]").toArray();
  const hits = (e: cytoscape.EdgeSingular) => {
    let n = 0;
    const s = e.sourceEndpoint(), t = e.targetEndpoint(), m = e.midpoint();
    const cx = 2 * m.x - (s.x + t.x) / 2, cyy = 2 * m.y - (s.y + t.y) / 2;
    for (let k = 1; k < 24; k++) {
      const u = k / 24, x = (1 - u) ** 2 * s.x + 2 * (1 - u) * u * cx + u * u * t.x, y = (1 - u) ** 2 * s.y + 2 * (1 - u) * u * cyy + u * u * t.y;
      for (const o of nodes) {
        if (o.id() === e.source().id() || o.id() === e.target().id()) continue;
        const b = o.boundingBox({ includeLabels: true, includeOverlays: false, includeUnderlays: false } as any);
        if (x > b.x1 - 3 && x < b.x2 + 3 && y > b.y1 - 3 && y < b.y2 + 3) n++;
      }
    }
    return n;
  };
  const blocked = (e: cytoscape.EdgeSingular) => {
    const s = e.sourceEndpoint(), t = e.targetEndpoint(), m = e.midpoint();
    const cx = 2 * m.x - (s.x + t.x) / 2, cyy = 2 * m.y - (s.y + t.y) / 2;
    for (let k = 1; k < 24; k++) {
      const u = k / 24, x = (1 - u) ** 2 * s.x + 2 * (1 - u) * u * cx + u * u * t.x, y = (1 - u) ** 2 * s.y + 2 * (1 - u) * u * cyy + u * u * t.y;
      for (const n of nodes) {
        if (n.id() === e.source().id() || n.id() === e.target().id()) continue;
        const b = n.boundingBox({ includeLabels: true, includeOverlays: false, includeUnderlays: false } as any);
        if (x > b.x1 - 3 && x < b.x2 + 3 && y > b.y1 - 3 && y < b.y2 + 3) return true;
      }
    }
    return false;
  };
  c.edges().forEach((e) => {
    if (!blocked(e)) return;
    let best = 0, bestHits = Infinity;
    for (const d of [36, -36, 64, -64, 96, -96, 140, -140, 190, -190, 250, -250]) {
      e.style({ "curve-style": "unbundled-bezier", "control-point-distances": [d], "control-point-weights": [0.5] } as any);
      const h = hits(e);
      if (!h) return;
      if (h < bestHits) { best = d; bestHits = h; }
    }
    e.style({ "control-point-distances": [best] } as any);
  });
}

const SHAPE_CLS: Record<string, string> = { diamond: "rotate-45 scale-[.8] rounded-[1px]", ellipse: "rounded-full", "round-rectangle": "rounded-[3px]",
  "round-hexagon": "rounded-[4px]", "round-octagon": "rounded-[5px]", "round-tag": "rounded-r-full" };

/** Legend; with onToggle each type becomes a filter chip (click to hide/show that kind of entity). */
export function Legend({ hidden, onToggle, counts }: { hidden?: Set<string>; onToggle?: (t: string) => void; counts?: Record<string, number> }) {
  const swatch = (k: string) => `rgb(var(${GROUP_VAR[NODE_STYLE[k].group]}))`;
  const types = Object.entries(NODE_STYLE).filter(([k]) => !counts || counts[k]);
  return (
    <ul className="flex flex-wrap items-center gap-x-1.5 gap-y-1.5 text-xs text-ink-2" aria-label="Graph legend">
      {types.map(([k, v]) => {
        const off = hidden?.has(k);
        const body = <><span className={`w-3 h-3 inline-block shrink-0 ${SHAPE_CLS[v.shape] ?? ""}`} style={{ background: swatch(k), opacity: off ? 0.3 : 1 }} />
          <span className={off ? "line-through" : ""}>{v.label}</span>{counts && <span className="tnum text-ink-2/80">{counts[k]}</span>}</>;
        return (
          <li key={k}>
            {onToggle ? (
              <button onClick={() => onToggle(k)} aria-pressed={!off} title={off ? `Show ${v.label.toLowerCase()}s` : `Hide ${v.label.toLowerCase()}s`}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2 h-6 transition-colors ${off ? "border-rule text-ink-2/70" : "border-rule bg-paper text-ink hover:border-ink"}`}>{body}</button>
            ) : <span className="inline-flex items-center gap-1.5 px-1">{body}</span>}
          </li>
        );
      })}
      {!onToggle && <li className="inline-flex items-center gap-1.5 px-1"><span className="w-3 h-3 rounded-full bg-critical/30 ring-2 ring-critical" />Critical halo</li>}
    </ul>
  );
}

export function EdgeLegend() {
  const dash = (f: string) => f === "persist";
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2" aria-label="Relationship colours">
      {FAMILIES.map(([f, label]) => (
        <li key={f} className="inline-flex items-center gap-1.5">
          <svg width="22" height="8" aria-hidden><line x1="1" y1="4" x2="21" y2="4" stroke={`rgb(var(${FAM_VAR[f]}))`} strokeWidth="2.4" strokeDasharray={dash(f) ? "5 3" : undefined} /></svg>{label}
        </li>
      ))}
      <li className="inline-flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-critical/30 ring-2 ring-critical" />Critical</li>
      <li className="inline-flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-high/30" />High</li>
    </ul>
  );
}
