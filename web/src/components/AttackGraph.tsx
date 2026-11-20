import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import { useEffect, useRef, useState } from "react";
import type { GraphEdge, GraphNode } from "../api/types";
import { useUi } from "../stores/ui";

cytoscape.use(dagre);

/** Colour encodes three meaningful groups (flowchart skill: colour only for real groups);
 *  shape tells the types inside a group apart. Severity is a ring, never a fill. */
export const NODE_STYLE: Record<string, { group: "actor" | "execution" | "footprint"; shape: string; label: string }> = {
  ip: { group: "actor", shape: "diamond", label: "IP address" },
  user: { group: "actor", shape: "ellipse", label: "Account" },
  process: { group: "execution", shape: "round-rectangle", label: "Process" },
  file: { group: "footprint", shape: "rectangle", label: "File" },
  registry: { group: "footprint", shape: "hexagon", label: "Registry key" },
  service: { group: "footprint", shape: "octagon", label: "Service" },
  task: { group: "footprint", shape: "tag", label: "Scheduled task" },
};
const GROUP_VAR = { actor: "--grp-actor", execution: "--grp-exec", footprint: "--grp-foot" } as const;
export const EDGE_WORDS: Record<string, string> = {
  logged_in_as: "logged in as", spawned: "spawned", wrote: "wrote", connected_to: "connected to",
  created: "created", persisted_via: "persisted via", granted_admin: "granted admin to",
};

function cssRgb(name: string, alpha = 1) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return alpha === 1 ? `rgb(${v.split(" ").join(",")})` : `rgba(${v.split(" ").join(",")},${alpha})`;
}

/** Cytoscape attack graph (US-016). Props and data binding are unchanged from v1. */
export function AttackGraph({ nodes, edges, highlightId, highlightEdgeEventId, onSelect, layout = "dagre", activeEventIds, compact = false }:
  { nodes: GraphNode[]; edges: GraphEdge[]; highlightId?: string | null; highlightEdgeEventId?: number | null; onSelect?: (n: GraphNode | null) => void;
    layout?: "dagre" | "cose"; activeEventIds?: Set<number> | null; compact?: boolean }) {
  const el = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const onSel = useRef(onSelect);
  onSel.current = onSelect;
  const theme = useUi((s) => s.theme);
  const [tip, setTip] = useState<{ x: number; y: number; text: string } | null>(null);

  useEffect(() => {
    if (!el.current) return;
    const ink = cssRgb("--ink"), ink2 = cssRgb("--ink-2"), sheet = cssRgb("--sheet"), rule = cssRgb("--rule");
    const sev = { Critical: cssRgb("--sev-critical"), High: cssRgb("--sev-high") } as Record<string, string>;
    const grp = { actor: cssRgb(GROUP_VAR.actor), execution: cssRgb(GROUP_VAR.execution), footprint: cssRgb(GROUP_VAR.footprint) };
    const amber = cssRgb("--amber");
    const ids = new Set(nodes.map((n) => n.id));
    const c = cytoscape({
      container: el.current,
      elements: [
        ...nodes.map((n) => {
          const st = NODE_STYLE[n.type];
          const ring = sev[n.severity];
          return { data: { ...n, fill: st ? grp[st.group] : ink2, shape: st?.shape ?? "ellipse", ring: ring ?? sheet, rw: n.severity === "Critical" ? 4 : n.severity === "High" ? 2.5 : 1.5,
            short: n.label.length > 26 ? n.label.slice(0, 24) + "…" : n.label } };
        }),
        ...edges.filter((e) => ids.has(e.source) && ids.has(e.target))
          .map((e) => ({ data: { id: `e${e.id}`, source: e.source, target: e.target, label: e.type, event_id: e.event_id, ts: e.ts } })),
      ],
      style: [
        // standard node size per role; label below on a paper chip so edges never run through text
        { selector: "node", style: { "background-color": "data(fill)", shape: "data(shape)" as any, width: 30, height: 30,
          "border-color": "data(ring)", "border-width": "data(rw)" as any,
          label: "data(short)", color: ink, "font-size": compact ? 13 : 11.5, "font-family": "Instrument Sans Variable, sans-serif", "font-weight": 500 as any,
          "text-valign": "bottom", "text-margin-y": 6, "text-wrap": "wrap", "text-max-width": "120px",
          "text-background-color": sheet, "text-background-opacity": 0.92, "text-background-padding": "2px", "text-background-shape": "roundrectangle",
          "transition-property": "opacity, border-width, border-color", "transition-duration": 180 as any } },
        { selector: 'node[type = "process"]', style: { width: 38, height: 26 } },
        // edges: readable at fit, no labels on canvas (flowchart skill), arrow shows direction
        { selector: "edge", style: { width: 2, "line-color": rule, "target-arrow-color": ink2, "target-arrow-shape": "triangle", "arrow-scale": 0.9,
          "curve-style": "bezier", "control-point-step-size": 28, "transition-property": "opacity, line-color, width", "transition-duration": 180 as any } },
        { selector: "node:selected", style: { "border-color": ink, "border-width": 4 } },
        { selector: ".faded", style: { opacity: 0.08 } },
        { selector: "node.nb", style: { "border-color": amber, "border-width": 4 } },
        { selector: "edge.nb", style: { "line-color": amber, "target-arrow-color": amber, width: 3 } },
        { selector: ".hl", style: { "border-color": amber, "border-width": 6, "overlay-color": amber, "overlay-opacity": 0.18, "overlay-padding": 8 } },
        { selector: "edge.hl", style: { "line-color": amber, "target-arrow-color": amber, width: 4 } },
        { selector: ".dim", style: { opacity: 0.14 } },
      ],
      layout: layout === "dagre"
        ? ({ name: "dagre", rankDir: "LR", nodeSep: compact ? 40 : 46, rankSep: compact ? 110 : 120, edgeSep: 18, padding: 24 } as any)
        : { name: "cose", padding: 28, animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 110 },
      wheelSensitivity: 0.2, minZoom: 0.25, maxZoom: 2.5,
    });
    routeAround(c);
    // hover: fade the unconnected to 8 %, neighbours in amber (tldr-skill pattern)
    c.on("mouseover", "node", (e) => {
      const n = e.target, nb = n.closedNeighborhood();
      c.elements().not(nb).addClass("faded");
      nb.not(n).addClass("nb");
    });
    c.on("mouseout", "node", () => c.elements().removeClass("faded nb"));
    c.on("mouseover", "edge", (e) => {
      const d = e.target.data(), p = e.renderedPosition;
      const s = c.getElementById(d.source).data("label"), t = c.getElementById(d.target).data("label");
      setTip({ x: p.x, y: p.y, text: `${s} ${EDGE_WORDS[d.label] ?? d.label} ${t} · ${String(d.ts).slice(11, 19)} UTC` });
    });
    c.on("mouseout", "edge", () => setTip(null));
    c.on("tap", "node", (e) => onSel.current?.(e.target.data() as GraphNode));
    c.on("tap", (e) => { if (e.target === c) onSel.current?.(null); });
    cy.current = c;
    (window as any).__fsGraph = c;  // read by the Playwright graph linter
    const fit = () => { c.resize(); c.fit(undefined, 28); if (c.zoom() > 1.25) { c.zoom(1.25); c.center(); } };
    const ro = new ResizeObserver(fit);
    ro.observe(el.current);
    return () => { ro.disconnect(); c.destroy(); cy.current = null; };
  }, [nodes, edges, layout, theme, compact]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("hl dim");
    if (activeEventIds) {
      c.nodes().forEach((n) => { if (!(n.data("event_ids") as number[]).some((i) => activeEventIds.has(i))) n.addClass("dim"); });
      c.edges().forEach((e) => { if (!activeEventIds.has(e.data("event_id"))) e.addClass("dim"); });
    }
    if (highlightId) {
      const n = c.getElementById(highlightId);
      if (n.nonempty()) n.removeClass("dim").addClass("hl");
    }
    if (highlightEdgeEventId != null) c.edges().filter((e) => e.data("event_id") === highlightEdgeEventId).removeClass("dim").addClass("hl");
  }, [highlightId, highlightEdgeEventId, activeEventIds, nodes, theme]);

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

/** Bow any edge that would pass behind an unrelated node (flowchart-skill rule), trying growing offsets
 *  on both sides until the path is clear. Runs once after layout; positions are static afterwards. */
function routeAround(c: Core) {
  const nodes = c.nodes().toArray();
  const blocked = (e: cytoscape.EdgeSingular) => {
    const s = e.sourceEndpoint(), t = e.targetEndpoint(), m = e.midpoint();
    const cx = 2 * m.x - (s.x + t.x) / 2, cyy = 2 * m.y - (s.y + t.y) / 2;
    for (let k = 1; k < 24; k++) {
      const u = k / 24, x = (1 - u) ** 2 * s.x + 2 * (1 - u) * u * cx + u * u * t.x, y = (1 - u) ** 2 * s.y + 2 * (1 - u) * u * cyy + u * u * t.y;
      for (const n of nodes) {
        if (n.id() === e.source().id() || n.id() === e.target().id()) continue;
        const b = n.boundingBox({ includeLabels: true, includeOverlays: false });
        if (x > b.x1 - 3 && x < b.x2 + 3 && y > b.y1 - 3 && y < b.y2 + 3) return true;
      }
    }
    return false;
  };
  c.edges().forEach((e) => {
    if (!blocked(e)) return;
    for (const d of [36, -36, 64, -64, 96, -96, 140, -140]) {
      e.style({ "curve-style": "unbundled-bezier", "control-point-distances": [d], "control-point-weights": [0.5] } as any);
      if (!blocked(e)) return;
    }
  });
}

export function Legend() {
  const swatch = (k: string) => `rgb(var(${GROUP_VAR[NODE_STYLE[k].group]}))`;
  const shapeCls: Record<string, string> = { diamond: "rotate-45 scale-[.8] rounded-[1px]", ellipse: "rounded-full", "round-rectangle": "rounded-[3px] w-4",
    rectangle: "", hexagon: "rounded-[3px]", octagon: "rounded-[3px]", tag: "rounded-r-full" };
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2" aria-label="Graph legend">
      {Object.entries(NODE_STYLE).map(([k, v]) => (
        <li key={k} className="inline-flex items-center gap-1.5">
          <span className={`w-3 h-3 inline-block ${shapeCls[v.shape] ?? ""}`} style={{ background: swatch(k) }} />{v.label}
        </li>
      ))}
      <li className="inline-flex items-center gap-1.5"><span className="w-3 h-3 rounded-full border-[3px] border-critical" />Critical ring</li>
    </ul>
  );
}
