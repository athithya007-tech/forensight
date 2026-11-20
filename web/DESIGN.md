# ForenSight design system: "Evidence Room"

Operate-mode dashboard (Impeccable). The visual world comes from the investigator's own paperwork,
not from SOC-terminal tooling: chain-of-custody labels, case files, and the forensic photo scale
(ABFO-style ruler) that evidence is photographed against.

## Why light by default
The demo runs on a projector in a lit room; dark themes wash out there. "Night shift" (warm graphite)
is one toggle away and is remembered per browser.

## Tokens (src/theme/index.css, exposed through tailwind.config.js)
| Token | Light | Use |
|---|---|---|
| paper | #F3F0E9 | page ground |
| sheet | #FBFAF6 | panels |
| well | #ECE8DF | inputs, code, raw records |
| ink / ink-2 | #1C1B18 / #5F594E | text / secondary text (tinted, never plain grey) |
| rule | #D9D3C5 | hairlines |
| rail | #1E211F | navigation rail |
| tape | #C2281D | the single focal accent (Tufte): score marker, peak, Critical |
| amber | #D69614 | hover, neighbours, replay cursor, selection, focus ring |
| severity | critical #B3261E, high #C95B0C, medium #9C7300, low #346091, info #7D776C | swatch + word, never colour alone |

Type: Newsreader (case narrative, page titles), Instrument Sans (UI), IBM Plex Mono (hashes, times, PIDs,
paths only). All self-hosted via @fontsource because the lab network has no internet.
Scale: fixed rem, ratio about 1.2. Radius 4 px. Motion 150-250 ms, state changes only.

## Signature move: the forensic scale
`components/ForensicScale.tsx`. Alternating ink/paper segments with minute ticks.
- Summary: the attack window, one mark per notable event (click to replay from it).
- Story: the replay position (amber cursor) across the attack.
- Score: 0-100 with the Clean / Suspicious / Compromised bands.
- Live collection: one segment per module, filled as modules finish.

## Rules kept from the skills
- Impeccable refuse list: no gauges or progress rings, no hero-metric KPI tiles, no eyebrow labels,
  no side-stripe borders, no gradient text, no decorative glass.
- Tufte: one accent on the focal datum, range-framed sparkline, single-hue sequential heatmap,
  direct labels instead of legends where possible.
- Graph (skill-flowchart + tldr-skill): colour only for meaningful groups (actor / execution / footprint),
  shape for type, severity as a ring, no edge labels on the canvas (they live in the node panel and
  hover tooltip), hover fades unrelated elements to 8 % with neighbours in amber, edges re-routed around
  unrelated nodes, sparse overview on the Story page.
- Verification: `npm run lint:graph` (overlap, label collisions, edges behind nodes, min 9 px labels,
  clipping) and Playwright screenshots of every route at 1366x768 with role-based selectors.
