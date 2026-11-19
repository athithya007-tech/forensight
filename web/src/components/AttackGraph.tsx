import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import { useEffect, useRef } from "react";
import type { GraphEdge, GraphNode } from "../api/types";
import { SEV_COLOR } from "./SeverityBadge";

cytoscape.use(dagre);

export const NODE_STYLE: Record<string, { color: string; shape: string; icon: string }> = {
  ip: { color: "#A855F7", shape: "diamond", icon: "IP" },
  user: { color: "#22D3EE", shape: "ellipse", icon: "USR" },
  process: { color: "#F59E0B", shape: "round-rectangle", icon: "PROC" },
  file: { color: "#94A3B8", shape: "rectangle", icon: "FILE" },
  registry: { color: "#10B981", shape: "hexagon", icon: "REG" },
  service: { color: "#F472B6", shape: "octagon", icon: "SVC" },
  task: { color: "#60A5FA", shape: "tag", icon: "TASK" },
};

/** Cytoscape attack graph (US-016): typed nodes, red outline for Critical, highlight for replay. */
export function AttackGraph({ nodes, edges, highlightId, highlightEdgeEventId, onSelect, layout = "dagre", activeEventIds }:
  { nodes: GraphNode[]; edges: GraphEdge[]; highlightId?: string | null; highlightEdgeEventId?: number | null; onSelect?: (n: GraphNode | null) => void;
    layout?: "dagre" | "cose"; activeEventIds?: Set<number> | null }) {
  const el = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const onSel = useRef(onSelect);
  onSel.current = onSelect;

  useEffect(() => {
    if (!el.current) return;
    const text = getComputedStyle(document.documentElement).getPropertyValue("--text").trim().split(" ").join(",");
    const c = cytoscape({
      container: el.current,
      elements: [
        ...nodes.map((n) => ({ data: { ...n, color: NODE_STYLE[n.type]?.color ?? "#9CA3AF", shape: NODE_STYLE[n.type]?.shape ?? "ellipse",
          border: n.severity === "Critical" ? SEV_COLOR.Critical : n.severity === "High" ? SEV_COLOR.High : "transparent",
          bw: n.severity === "Critical" ? 4 : n.severity === "High" ? 2 : 0, short: n.label.length > 34 ? n.label.slice(0, 32) + "…" : n.label } })),
        ...edges.filter((e) => nodes.some((n) => n.id === e.source) && nodes.some((n) => n.id === e.target))
          .map((e) => ({ data: { id: `e${e.id}`, source: e.source, target: e.target, label: e.type, event_id: e.event_id } })),
      ],
      style: [
        { selector: "node", style: { "background-color": "data(color)", shape: "data(shape)" as any, width: 34, height: 34, label: "data(short)",
          color: `rgb(${text})`, "font-size": 10, "text-valign": "bottom", "text-margin-y": 5, "border-color": "data(border)", "border-width": "data(bw)" as any,
          "text-wrap": "wrap", "text-max-width": "140px", "font-family": "Inter, sans-serif", "transition-property": "opacity, border-width", "transition-duration": 200 as any } },
        { selector: "edge", style: { width: 1.6, "line-color": "#475569", "target-arrow-color": "#475569", "target-arrow-shape": "triangle", "curve-style": "bezier",
          label: "data(label)", "font-size": 8.5, color: "#94A3B8", "text-rotation": "autorotate", "text-background-color": "#0B0F17", "text-background-opacity": 0.7, "text-background-padding": "2px" } },
        { selector: "node:selected", style: { "overlay-color": "#22D3EE", "overlay-opacity": 0.25, "overlay-padding": 6 } },
        { selector: ".hl", style: { "border-color": "#22D3EE", "border-width": 6, "overlay-color": "#22D3EE", "overlay-opacity": 0.2, "overlay-padding": 8 } },
        { selector: "edge.hl", style: { "line-color": "#22D3EE", "target-arrow-color": "#22D3EE", width: 3.5, color: "#22D3EE" } },
        { selector: ".dim", style: { opacity: 0.15 } },
      ],
      layout: layout === "dagre" ? ({ name: "dagre", rankDir: "LR", nodeSep: 30, rankSep: 90, padding: 20 } as any) : { name: "cose", padding: 20, animate: false },
      wheelSensitivity: 0.25, minZoom: 0.2, maxZoom: 3,
    });
    c.on("tap", "node", (e) => onSel.current?.(e.target.data() as GraphNode));
    c.on("tap", (e) => { if (e.target === c) onSel.current?.(null); });
    cy.current = c;
    return () => { c.destroy(); cy.current = null; };
  }, [nodes, edges, layout]);

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
      if (n.nonempty()) { n.removeClass("dim").addClass("hl"); c.animate({ center: { eles: n }, zoom: Math.max(c.zoom(), 1) } as any, { duration: 350 }); }
    }
    if (highlightEdgeEventId != null) c.edges().filter((e) => e.data("event_id") === highlightEdgeEventId).removeClass("dim").addClass("hl");
  }, [highlightId, highlightEdgeEventId, activeEventIds, nodes]);

  return <div ref={el} className="w-full h-full min-h-[300px]" />;
}

export function Legend() {
  return (
    <div className="flex flex-wrap gap-3 text-[12px] text-muted">
      {Object.entries(NODE_STYLE).map(([k, v]) => (
        <span key={k} className="inline-flex items-center gap-1.5">
          <span className="w-3 h-3 inline-block" style={{ background: v.color, borderRadius: v.shape === "ellipse" ? 999 : v.shape === "diamond" ? 2 : 3, transform: v.shape === "diamond" ? "rotate(45deg) scale(.8)" : undefined }} />{k}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5"><span className="w-3 h-3 rounded-full border-2" style={{ borderColor: SEV_COLOR.Critical }} />critical</span>
    </div>
  );
}
