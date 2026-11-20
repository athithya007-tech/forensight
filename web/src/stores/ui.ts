import { create } from "zustand";

function initialTheme(): "dark" | "light" {
  try { return (localStorage.getItem("fs-theme") as "dark" | "light") || "light"; } catch { return "light"; }
}
interface UiState {
  chatOpen: boolean; evidenceRef: string | null; theme: "dark" | "light"; sidebarOpen: boolean;
  setChat: (v: boolean) => void; openEvidence: (ref: string | null) => void; toggleTheme: () => void; setSidebar: (v: boolean) => void;
}
export const useUi = create<UiState>((set, get) => ({
  chatOpen: false, evidenceRef: null, theme: initialTheme(), sidebarOpen: false,
  setChat: (chatOpen) => set({ chatOpen }), openEvidence: (evidenceRef) => set({ evidenceRef }),
  setSidebar: (sidebarOpen) => set({ sidebarOpen }),
  toggleTheme: () => {
    const theme = get().theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("fs-theme", theme); } catch { /* storage blocked */ }
    set({ theme });
  },
}));
