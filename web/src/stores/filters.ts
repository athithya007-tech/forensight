import { create } from "zustand";
import type { Severity } from "../api/types";

export interface Filters { severity: Severity[]; source: string[]; tactic: string[]; from: string; to: string; q: string }
interface FilterState extends Filters { set: (f: Partial<Filters>) => void; clear: () => void }
const empty: Filters = { severity: [], source: [], tactic: [], from: "", to: "", q: "" };
export const useFilters = create<FilterState>((set) => ({ ...empty, set: (f) => set(f), clear: () => set(empty) }));
