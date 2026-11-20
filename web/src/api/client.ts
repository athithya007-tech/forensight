import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  AttackColumn, CaseRow, Conn, DiffItem, EventsPage, Finding, Graph, Ioc, ManifestEntry, Proc, Summary, VerifyResult,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** Static build (GitHub Pages): no server. Reads pre-exported JSON from <base>/demo-data and answers
 *  write actions with a friendly "install it" message. Built with `npm run build:pages`. */
export const STATIC = import.meta.env.VITE_STATIC === "1";
const BASE = import.meta.env.BASE_URL;  // "/" locally, "/<repo>/" on GitHub Pages
export const DEMO_MSG = "This is the read-only online demo. Install ForenSight on your computer to collect, analyze and generate reports.";
const cache = new Map<string, Promise<any>>();
function load(rel: string) {
  if (!cache.has(rel)) cache.set(rel, fetch(`${BASE}demo-data/${rel}`).then((r) => { if (!r.ok) throw new ApiError(404, "Not part of the online demo"); return r.json(); }));
  return cache.get(rel)!;
}
/** URL of a downloadable file (report PDF, CSV…) in both modes. */
export function fileUrl(id: string, name: string) {
  return STATIC ? `${BASE}demo-data/cases/${id}/report/file/${name}` : `/api/cases/${encodeURIComponent(id)}/report/file/${name}`;
}
export const pdfUrl = (id: string) => (STATIC ? fileUrl(id, "report.pdf") : `/api/cases/${encodeURIComponent(id)}/report/pdf`);

async function staticApi(path: string, init?: RequestInit): Promise<any> {
  const [p, qs] = path.split("?");
  const params = new URLSearchParams(qs ?? "");
  const rel = decodeURIComponent(p.replace(/^\/api\//, ""));
  const m = rel.match(/^cases\/([^/]+)\/(.+)$/);
  if (init?.method === "POST") {
    if (m && m[2] === "verify") return load(`cases/${m[1]}/verify.json`);
    if (m && m[2] === "chat") {
      const q = JSON.parse(String(init.body ?? "{}")).question as string;
      const answers = await load(`cases/${m[1]}/chat-answers.json`);
      return answers[q] ?? { type: "done", answer: "The online demo answers the suggested questions only. Install ForenSight to ask the evidence anything.", citations: [] };
    }
    throw new ApiError(403, DEMO_MSG);
  }
  if (m && m[2] === "events") {
    const all = await load(`cases/${m[1]}/events.json`);
    const list = (k: string) => params.get(k)?.split(",").filter(Boolean);
    const sev = list("severity"), src = list("source"), tac = list("tactic");
    const from = params.get("from"), to = params.get("to"), q = params.get("q")?.toLowerCase();
    const items = all.items.filter((e: any) => (!sev || sev.includes(e.severity)) && (!src || src.includes(e.source)) && (!tac || tac.includes(e.tactic))
      && (!from || e.timestamp_utc >= from) && (!to || e.timestamp_utc <= to)
      && (!q || `${e.description} ${JSON.stringify(e.raw ?? "")} ${e.event_type} ${e.attck_id ?? ""}`.toLowerCase().includes(q)));
    return { ...all, items, total: items.length };
  }
  if (m && m[2] === "evidence/item") {
    const items = await load(`cases/${m[1]}/evidence-items.json`);
    const it = items[params.get("ref") ?? ""];
    if (!it) throw new ApiError(404, "This exhibit is not part of the online demo");
    return it;
  }
  if (rel.startsWith("jobs/")) throw new ApiError(403, DEMO_MSG);
  return load(`${rel}.json`);
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  if (STATIC) return staticApi(path, init);
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
