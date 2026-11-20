import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  AttackColumn, CaseRow, Conn, DiffItem, EventsPage, Finding, Graph, Ioc, ManifestEntry, Proc, Summary, VerifyResult,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...init });
  if (!r.ok) {
    let msg = r.statusText;
    try { const j = await r.json(); msg = j.detail || msg; } catch { /* not json */ }
    throw new ApiError(r.status, msg);
  }
  return r.json();
}
const post = <T,>(path: string, body?: unknown) => api<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
const c = (id: string) => `/api/cases/${encodeURIComponent(id)}`;

export const useCases = () => useQuery({ queryKey: ["cases"], queryFn: () => api<CaseRow[]>("/api/cases"), refetchInterval: 5000 });
export const useSummary = (id: string) => useQuery({ queryKey: ["summary", id], queryFn: () => api<Summary>(`${c(id)}/summary`) });
export const useFindings = (id: string) => useQuery({ queryKey: ["findings", id], queryFn: () => api<Finding[]>(`${c(id)}/findings`) });
export const useGraph = (id: string) => useQuery({ queryKey: ["graph", id], queryFn: () => api<Graph>(`${c(id)}/graph`) });
export const useProcesses = (id: string) =>
  useQuery({ queryKey: ["processes", id], queryFn: () => api<{ roots: Proc[]; count: number; flagged: number }>(`${c(id)}/processes`) });
export const useNetwork = (id: string) => useQuery({ queryKey: ["network", id], queryFn: () => api<Conn[]>(`${c(id)}/network`) });
export const useAttack = (id: string) => useQuery({ queryKey: ["attack", id], queryFn: () => api<AttackColumn[]>(`${c(id)}/attack`) });
export const useIocs = (id: string) => useQuery({ queryKey: ["iocs", id], queryFn: () => api<Ioc[]>(`${c(id)}/iocs`) });
export const useDiff = (id: string) =>
  useQuery({ queryKey: ["diff", id], queryFn: () => api<{ available: boolean; items: DiffItem[]; categories: Record<string, Record<string, number>>; message?: string; baseline_taken?: string; incident_taken?: string }>(`${c(id)}/diff`) });
export const useEvidence = (id: string) =>
  useQuery({ queryKey: ["evidence", id], queryFn: () => api<{ entries: ManifestEntry[]; root_hash: string; signed: boolean; audit: string[] }>(`${c(id)}/evidence`) });
export const useEvidenceItem = (id: string, ref: string | null) =>
  useQuery({ queryKey: ["evidence-item", id, ref], enabled: !!ref, queryFn: () => api<any>(`${c(id)}/evidence/item?ref=${encodeURIComponent(ref!)}`) });
export const useReportStatus = (id: string) =>
  useQuery({ queryKey: ["report", id], queryFn: () => api<{ meta: any; files: Record<string, boolean> }>(`${c(id)}/report`) });

export interface EventQuery { severity?: string[]; source?: string[]; tactic?: string[]; from?: string; to?: string; q?: string; limit?: number }
export function useEvents(id: string, q: EventQuery = {}) {
  const p = new URLSearchParams();
  if (q.severity?.length) p.set("severity", q.severity.join(","));
  if (q.source?.length) p.set("source", q.source.join(","));
  if (q.tactic?.length) p.set("tactic", q.tactic.join(","));
  if (q.from) p.set("from", q.from);
  if (q.to) p.set("to", q.to);
  if (q.q) p.set("q", q.q);
  p.set("limit", String(q.limit ?? 5000));
  return useQuery({ queryKey: ["events", id, p.toString()], queryFn: () => api<EventsPage>(`${c(id)}/events?${p}`), placeholderData: (prev) => prev });
}

export const useVerify = (id: string) => {
  const qc = useQueryClient();
  return useMutation({ mutationFn: () => post<VerifyResult>(`${c(id)}/verify`), onSuccess: () => qc.invalidateQueries({ queryKey: ["evidence", id] }) });
};
export const createCase = (body: { name: string; investigator: string; notes?: string }) => post<any>("/api/cases", body);
export const startDemo = (steps: number[]) => post<{ case_id: string; job: string }>("/api/demo", { steps, analyze: true });
export const startCollect = (id: string, profile: string) => post<{ job: string }>(`${c(id)}/collect`, { profile, analyze: true });
export const startReport = (id: string, ai: boolean) => post<{ job: string }>(`${c(id)}/report`, { formats: ["pdf", "html"], ai, base_url: window.location.origin });
export const useHealth = () => useQuery({ queryKey: ["health"], queryFn: () => api<{ ok: boolean; version?: string; ollama: boolean; cases_root: string }>("/api/health"), staleTime: 30_000 });
export const startAnalyze = (id: string) => post<{ job: string }>(`${c(id)}/analyze`);
export const getJob = (jid: string) => api<{ status: string; error?: string; result?: any }>(`/api/jobs/${jid}`);
export const publicVerify = (id: string) => api<any>(`/api/verify/${encodeURIComponent(id)}`);
