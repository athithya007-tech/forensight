export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
export type Verdict = "Clean" | "Suspicious" | "Compromised";

export interface CaseRow {
  id: string; name: string; host: string; os: string; verdict?: Verdict; score?: number;
  created_at: string; status: string; investigator: string;
}
export interface Phase { index: number; label: string; start: string; end: string; tactics: string[]; events: number; severity: Severity }
export interface Finding {
  id: number; rule_id: string; title: string; description: string; severity: Severity; original_severity: Severity;
  confidence: number; attck_id: string | null; technique: string | null; tactic: string | null; playbook: string[];
  event_ids: number[]; evidence_refs: string[]; evidence: { ref: string; path: string; sha256?: string }[];
  first_seen: string; last_seen: string; pre_existing: boolean; engine: string;
}
export interface TechniqueCell { id: string; name: string; count: number; severity: Severity; finding_ids: number[] }
export interface AttackColumn { tactic: string; techniques: TechniqueCell[]; count: number }
export interface Summary {
  case: any; score: number; verdict: Verdict; severity_counts: Record<Severity, number>; findings: number; events: number;
  attack_start?: string; attack_end?: string; duration_seconds?: number; top_findings: Finding[]; host: any;
  phases: Phase[]; tactics: AttackColumn[]; techniques: string[]; analyzed: boolean; engines?: any; exec_summary?: string;
  collection?: any; artifacts: number;
}
export interface TimelineEvent {
  id: number; timestamp_utc: string; original_ts?: string; original_tz?: string; host: string; source: string;
  event_type: string; description: string; severity: Severity; attck_id: string | null; tactic: string | null;
  phase: string; phase_index: number; evidence_ref: string; rule_ids: string[]; raw_json: any; evidence_sha256?: string;
}
export interface EventsPage { items: TimelineEvent[]; total: number; sources: string[]; tactics: string[] }
export interface GraphNode { id: string; type: string; value: string; label: string; severity: Severity; event_ids: number[] }
export interface GraphEdge { id: number; source: string; target: string; type: string; event_id: number; ts: string }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[] }
export interface Proc {
  pid: number; ppid: number; name: string; path?: string; cmdline?: string; user?: string; start_time?: string; sha256?: string;
  sources: string[]; hidden: boolean; flagged: boolean; severity: Severity; reasons: string[]; event_ids: number[];
  children: Proc[]; exited?: string; evidence_ref: string; evidence_sha256?: string;
}
export interface Conn {
  proto: string; laddr: string; lport: number; raddr?: string; rport?: number; state: string; pid: number; process?: string;
  created?: string; sources: string[]; reputation?: string; reputation_source?: string; severity: Severity; event_id?: number;
  evidence_ref: string;
}
export interface DiffItem { category: string; key: string; change: "Added" | "Removed" | "Modified"; before: any; after: any }
export interface ManifestEntry {
  seq: number; path: string; size: number; sha256: string; collected_at: string; collector: string; module: string;
  prev_hash: string; entry_hash: string;
}
export interface VerifyEntry { seq: number; path: string; expected: string; actual?: string; status: "ok" | "mismatch"; problems: string[] }
export interface VerifyResult {
  ok: boolean; entries: VerifyEntry[]; total: number; mismatches: number; chain_ok: boolean; first_break?: number;
  unlisted_files: string[]; root_hash: string; manifest_signature: any; report_signature?: any; verified_at: string;
}
export interface Ioc { type: string; value: string; context: string; severity: Severity; first_seen: string }
export interface ProgressEvent { ts: string; module: string; status: string; pct?: number; file?: string; sha256?: string; message?: string }
export interface Citation { id: number; evidence_ref: string; ts: string; description: string; severity: Severity; attck_id?: string; sha256?: string }
export interface ChatMsg { role: "user" | "assistant"; content: string; citations: Citation[]; pending?: boolean; model?: string | null }
