import { create } from "zustand";

/** Replay position for the Attack story page (FR-35): fixed 1.5 s per event at 1x. */
interface ReplayState {
  playing: boolean; index: number; speed: 1 | 2 | 4; includeAll: boolean;
  play: () => void; pause: () => void; toggle: () => void; setIndex: (i: number) => void;
  setSpeed: (s: 1 | 2 | 4) => void; setIncludeAll: (v: boolean) => void; reset: () => void;
}
export const useReplay = create<ReplayState>((set) => ({
  playing: false, index: -1, speed: 1, includeAll: false,
  play: () => set({ playing: true }), pause: () => set({ playing: false }),
  toggle: () => set((s) => ({ playing: !s.playing })),
  setIndex: (index) => set({ index }), setSpeed: (speed) => set({ speed }),
  setIncludeAll: (includeAll) => set({ includeAll, index: -1, playing: false }), reset: () => set({ index: -1, playing: false }),
}));
export const REPLAY_STEP_MS = 1500;
