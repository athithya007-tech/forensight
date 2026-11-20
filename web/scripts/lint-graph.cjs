/* Graph quality linter for the ForenSight attack graph, adapted from danshapiro/skill-flowchart's
 * lint_flowchart_html.js rules: no overlapping nodes, labels inside readable bounds and not on top of other
 * nodes or labels, edges never routed behind unrelated nodes, readable font at the default fit, no edge
 * labels on the canvas, nothing clipped by the container.
 * Usage: node scripts/lint-graph.cjs <url> [<url> ...]   (needs `forensight serve` running) */
const { chromium } = require("playwright");

function inter(a, b, pad = 0) {
  return a.x1 < b.x2 - pad && a.x2 > b.x1 + pad && a.y1 < b.y2 - pad && a.y2 > b.y1 + pad;
}

async function lint(page, url) {
  await page.goto(url, { waitUntil: "networkidle" });
  await page.waitForFunction(() => window.__fsGraph && window.__fsGraph.nodes().length > 0, null, { timeout: 15000 });
  await page.waitForTimeout(700);
  return page.evaluate(() => {
    const cy = window.__fsGraph, issues = [];
    const inter = (a, b, pad = 0) => a.x1 < b.x2 - pad && a.x2 > b.x1 + pad && a.y1 < b.y2 - pad && a.y2 > b.y1 + pad;
    const nodes = cy.nodes().filter((n) => n.visible());
    const body = (n) => n.boundingBox({ includeLabels: false, includeOverlays: false });
    const label = (n) => n.boundingBox({ includeNodes: false, includeEdges: false, includeLabels: true, includeOverlays: false });
    const arr = nodes.toArray();
    for (let i = 0; i < arr.length; i++) for (let j = i + 1; j < arr.length; j++) {
      const a = arr[i], b = arr[j];
      if (inter(body(a), body(b))) issues.push({ code: "node-overlap", msg: `${a.data("label")} overlaps ${b.data("label")}` });
      if (inter(label(a), label(b), 1)) issues.push({ code: "label-overlap", msg: `labels of ${a.data("label")} and ${b.data("label")} collide` });
      if (inter(label(a), body(b), 1)) issues.push({ code: "label-on-node", msg: `label of ${a.data("label")} sits on ${b.data("label")}` });
      if (inter(label(b), body(a), 1)) issues.push({ code: "label-on-node", msg: `label of ${b.data("label")} sits on ${a.data("label")}` });
    }
    cy.edges().forEach((e) => {
      if (e.style("label")) issues.push({ code: "edge-label", msg: `edge ${e.id()} renders a label on the canvas` });
      const s = e.sourceEndpoint(), t = e.targetEndpoint(), mid = e.midpoint();
      const pts = [];
      for (let k = 1; k < 20; k++) { const u = k / 20; // quadratic through the rendered midpoint approximates the bezier
        pts.push({ x: (1 - u) * (1 - u) * s.x + 2 * (1 - u) * u * (2 * mid.x - (s.x + t.x) / 2) + u * u * t.x,
                   y: (1 - u) * (1 - u) * s.y + 2 * (1 - u) * u * (2 * mid.y - (s.y + t.y) / 2) + u * u * t.y }); }
      arr.forEach((n) => {
        if (n.id() === e.source().id() || n.id() === e.target().id()) return;
        const b = body(n);
        if (pts.some((p) => p.x > b.x1 + 2 && p.x < b.x2 - 2 && p.y > b.y1 + 2 && p.y < b.y2 - 2))
          issues.push({ code: "edge-behind-node", msg: `${e.source().data("label")} → ${e.target().data("label")} passes behind ${n.data("label")}` });
      });
    });
    const fontPx = parseFloat(arr[0].style("font-size")) * cy.zoom();
    if (fontPx < 9) issues.push({ code: "font-too-small", msg: `labels render at ${fontPx.toFixed(1)}px at the default fit (min 9px)` });
    const ext = cy.extent(), all = cy.elements().boundingBox();
    if (all.x1 < ext.x1 - 1 || all.y1 < ext.y1 - 1 || all.x2 > ext.x2 + 1 || all.y2 > ext.y2 + 1) issues.push({ code: "clipped", msg: "graph extends beyond the visible canvas" });
    return { nodes: arr.length, edges: cy.edges().length, zoom: +cy.zoom().toFixed(2), fontPx: +fontPx.toFixed(1), issues };
  });
}

(async () => {
  const urls = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1366, height: 768 } });
  let bad = 0;
  for (const u of urls) {
    const r = await lint(page, u);
    console.log(`${u}\n  ${r.nodes} nodes, ${r.edges} edges, zoom ${r.zoom}, label ${r.fontPx}px, ${r.issues.length} issue(s)`);
    const seen = new Set();
    r.issues.forEach((i) => { const k = i.code + i.msg; if (!seen.has(k)) { seen.add(k); console.log(`   ✘ ${i.code}: ${i.msg}`); } });
    bad += r.issues.length;
  }
  await browser.close();
  process.exit(bad ? 1 : 0);
})();
