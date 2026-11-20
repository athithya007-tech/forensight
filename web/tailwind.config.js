/** "Evidence Room" design tokens. Values live as CSS variables in src/theme/index.css so the
 *  light (default, projector-friendly) and night-shift themes swap at runtime. */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper: v("paper"),        // page ground (warm evidence-room paper)
        sheet: v("sheet"),        // panels, raised on the paper
        well: v("well"),          // inset areas: inputs, code, table heads
        ink: v("ink"),            // primary text
        "ink-2": v("ink-2"),      // secondary text (tinted, never plain grey)
        rule: v("rule"),          // hairlines and borders
        rail: v("rail"),          // the shell's ink rail
        "rail-ink": v("rail-ink"),
        "rail-2": v("rail-2"),
        tape: v("tape"),          // evidence-tape red: the single focal accent
        amber: v("amber"),        // hover/neighbour highlight, selection
        critical: v("sev-critical"),
        high: v("sev-high"),
        medium: v("sev-medium"),
        low: v("sev-low"),
        info: v("sev-info"),
        ok: v("ok"),
      },
      fontFamily: {
        sans: ['"Instrument Sans Variable"', "system-ui", "sans-serif"],
        serif: ['"Newsreader"', "Georgia", "serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      fontSize: {
        // fixed rem scale, ratio ~1.2 (Impeccable operate.md)
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
        xs: ["0.75rem", { lineHeight: "1.1rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
        base: ["0.9375rem", { lineHeight: "1.45rem" }],
        lg: ["1.125rem", { lineHeight: "1.6rem" }],
        xl: ["1.375rem", { lineHeight: "1.8rem" }],
        "2xl": ["1.75rem", { lineHeight: "2.1rem" }],
        "3xl": ["2.25rem", { lineHeight: "2.6rem" }],
      },
      borderRadius: { DEFAULT: "4px", sm: "2px", md: "4px", lg: "6px" },
      boxShadow: {
        sheet: "0 1px 0 rgb(var(--rule) / 0.6), 0 6px 18px -12px rgb(var(--shadow) / 0.35)",
        lift: "0 2px 0 rgb(var(--rule)), 0 14px 28px -16px rgb(var(--shadow) / 0.45)",
      },
      transitionTimingFunction: { out: "cubic-bezier(0.16, 1, 0.3, 1)" },
    },
  },
  plugins: [],
};
