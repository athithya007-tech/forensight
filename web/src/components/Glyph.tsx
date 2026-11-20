/** Evidence Room icon set: one SVG file per symbol in src/assets/icons (see style-spec.json there).
 *  Files are inlined at build time so they inherit currentColor and need no network. */
const files = import.meta.glob("../assets/icons/*.svg", { query: "?raw", import: "default", eager: true }) as Record<string, string>;
const ICONS: Record<string, string> = Object.fromEntries(
  Object.entries(files).map(([p, svg]) => [p.split("/").pop()!.replace(".svg", ""), svg]),
);

export type GlyphName = "case-file" | "replay" | "timeline" | "string-board" | "exhibit-lens" | "attack-map" | "process-tree"
  | "host-links" | "baseline-diff" | "evidence-bag" | "signed-report" | "collector" | "ask" | "open-case" | "daylight" | "night-shift";

export function Glyph({ name, size = 18, className, title }: { name: GlyphName; size?: number; className?: string; title?: string }) {
  const svg = (ICONS[name] ?? "").replace(/width="24" height="24"/, `width="${size}" height="${size}"`)
    .replace("<svg ", `<svg aria-hidden="${title ? "false" : "true"}" focusable="false" `);
  return <span className={className} style={{ display: "inline-flex", lineHeight: 0 }} title={title} role={title ? "img" : undefined}
    aria-label={title} dangerouslySetInnerHTML={{ __html: svg }} />;
}
