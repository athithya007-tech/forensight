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
  const btn = "p-2 rounded-md hover:bg-surface2 text-muted hover:text-text disabled:opacity-30";
  return (
    <div className="flex items-center gap-1">
      <button className={btn} onClick={reset} title="Restart" aria-label="Restart"><RotateCcw size={16} /></button>
      <button className={btn} disabled={index <= 0} onClick={() => setIndex(index - 1)} title="Step back (←)" aria-label="Step back"><SkipBack size={18} /></button>
      <button onClick={() => { if (index >= count - 1) setIndex(-1); toggle(); }} title="Play / Pause (space)" aria-label={playing ? "Pause" : "Play"}
        className="w-11 h-11 rounded-full bg-accent text-[#0B0F17] grid place-items-center hover:brightness-110 shadow-lg shadow-accent/20">
        {playing ? <Pause size={20} /> : <Play size={20} className="ml-0.5" />}
      </button>
      <button className={btn} disabled={index >= count - 1} onClick={() => setIndex(index + 1)} title="Step forward (→)" aria-label="Step forward"><SkipForward size={18} /></button>
      <div className="flex items-center ml-2 rounded-md border border-border overflow-hidden">
        {[1, 2, 4].map((s) => (
          <button key={s} onClick={() => setSpeed(s as 1 | 2 | 4)} className={cx("px-2.5 py-1 text-[12px] font-semibold", speed === s ? "bg-accent/20 text-accent" : "text-muted hover:text-text")}>
            {s === 1 ? "1×" : s === 2 ? "2×" : <span className="inline-flex items-center">4×<FastForward size={11} className="ml-0.5" /></span>}
          </button>
        ))}
      </div>
      <label className="ml-3 inline-flex items-center gap-1.5 text-[12px] text-muted cursor-pointer select-none">
        <input type="checkbox" checked={includeAll} onChange={(e) => setIncludeAll(e.target.checked)} className="accent-[#22D3EE]" />
        all events
      </label>
      <span className="ml-3 text-[12px] text-muted tabular-nums">{Math.max(0, index + 1)} / {count}</span>
    </div>
  );
}

export function CaptionBar({ event }: { event?: TimelineEvent | null }) {
  return (
    <div className="flex items-center gap-3 min-w-0 flex-1">
      {event ? (
        <div key={event.id} className="flex items-center gap-3 min-w-0 slide-in">
          <span className="font-mono text-lg font-bold text-accent tabular-nums">{event.timestamp_utc.slice(11, 19)}</span>
          <span className="text-muted">—</span>
          <SeverityBadge severity={event.severity} />
          {event.attck_id && <span className="font-mono text-[12px] text-muted">{event.attck_id}</span>}
          <span className="truncate text-[15px] font-medium" title={event.description}>{event.description}</span>
        </div>
      ) : (
        <span className="text-muted">Press <b>Play</b> to watch the attack unfold event by event.</span>
      )}
    </div>
  );
}
