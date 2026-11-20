import { FastForward, Pause, Play, RotateCcw, SkipBack, SkipForward } from "lucide-react";
import { useEffect } from "react";
import type { TimelineEvent } from "../api/types";
import { REPLAY_STEP_MS, useReplay } from "../stores/replay";
import { SeverityBadge } from "./SeverityBadge";
import { cx } from "./ui";

/** Play / Pause / Prev / Next / speed (US-013). Reads & writes the Zustand replay store. */
export function ReplayControls({ count }: { count: number }) {
  const { playing, index, speed, includeAll, toggle, setIndex, setSpeed, setIncludeAll, pause, reset } = useReplay();
  useEffect(() => {
    if (!playing) return;
    if (index >= count - 1) { pause(); return; }
    const t = setTimeout(() => setIndex(index + 1), index < 0 ? 200 : REPLAY_STEP_MS / speed);
    return () => clearTimeout(t);
  }, [playing, index, speed, count, setIndex, pause]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName === "INPUT" || (e.target as HTMLElement)?.tagName === "TEXTAREA") return;
      if (e.code === "Space") { e.preventDefault(); toggle(); }
      if (e.key === "ArrowRight") setIndex(Math.min(count - 1, useReplay.getState().index + 1));
      if (e.key === "ArrowLeft") setIndex(Math.max(0, useReplay.getState().index - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [count, toggle, setIndex]);
  const btn = "w-8 h-8 grid place-items-center rounded text-ink-2 hover:text-ink hover:bg-well disabled:opacity-30 transition-colors duration-150";
  return (
    <div className="flex items-center gap-1">
      <button className={btn} onClick={reset} title="Restart" aria-label="Restart"><RotateCcw size={16} /></button>
      <button className={btn} disabled={index <= 0} onClick={() => setIndex(index - 1)} title="Step back (←)" aria-label="Step back"><SkipBack size={18} /></button>
      <button onClick={() => { if (index >= count - 1) setIndex(-1); toggle(); }} title="Play / Pause (space)" aria-label={playing ? "Pause" : "Play"}
        className="w-10 h-10 rounded-full bg-ink text-paper grid place-items-center hover:bg-tape transition-colors duration-150 active:scale-95">
        {playing ? <Pause size={20} /> : <Play size={20} className="ml-0.5" />}
      </button>
      <button className={btn} disabled={index >= count - 1} onClick={() => setIndex(index + 1)} title="Step forward (→)" aria-label="Step forward"><SkipForward size={18} /></button>
      <div className="flex items-center ml-2 rounded border border-rule overflow-hidden" role="group" aria-label="Replay speed">
        {[1, 2, 4].map((s) => (
          <button key={s} onClick={() => setSpeed(s as 1 | 2 | 4)} aria-pressed={speed === s}
            className={cx("px-2.5 h-7 text-xs font-medium tnum transition-colors duration-150", speed === s ? "bg-ink text-paper" : "text-ink-2 hover:text-ink")}>
            {s === 1 ? "1×" : s === 2 ? "2×" : <span className="inline-flex items-center">4×<FastForward size={11} className="ml-0.5" /></span>}
          </button>
        ))}
      </div>
      <label className="ml-3 inline-flex items-center gap-1.5 text-xs text-ink-2 cursor-pointer select-none">
        <input type="checkbox" checked={includeAll} onChange={(e) => setIncludeAll(e.target.checked)} className="accent-[rgb(var(--ink))]" />
        Include low-severity events
      </label>
      <span className="ml-3 text-xs text-ink-2 tnum">Event {Math.max(0, index + 1)} of {count}</span>
    </div>
  );
}

export function CaptionBar({ event }: { event?: TimelineEvent | null }) {
  return (
    <div className="flex items-center gap-3 min-w-0 flex-1">
      {event ? (
        <div key={event.id} className="flex items-center gap-3 min-w-0 slide-in">
          <span className="font-mono text-lg font-medium text-ink tnum">{event.timestamp_utc.slice(11, 19)}</span>
          <SeverityBadge severity={event.severity} />
          {event.attck_id && <span className="font-mono text-xs text-ink-2">{event.attck_id}</span>}
          <span className="truncate font-serif text-lg" title={event.description}>{event.description}</span>
        </div>
      ) : (
        <span className="font-serif text-lg text-ink-2 italic">Press play to walk through the attack one event at a time. Space toggles, arrow keys step.</span>
      )}
    </div>
  );
}
