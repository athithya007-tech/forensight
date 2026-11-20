import { Globe } from "lucide-react";
import { useParams } from "react-router-dom";
import { useNetwork } from "../api/client";
import type { Conn } from "../api/types";
import { DataTable } from "../components/DataTable";
import { EvidenceChip } from "../components/EvidenceChip";
import { SeverityBadge } from "../components/SeverityBadge";
import { Card, ErrorState, Loading, Mono, PageHeader } from "../components/ui";

const REP: Record<string, string> = { malicious: "rgb(var(--sev-critical))", suspicious: "rgb(var(--sev-high))", clean: "rgb(var(--ok))", internal: "rgb(var(--ink-2))", unknown: "rgb(var(--sev-info))" };
export function ReputationBadge({ rep, src }: { rep?: string; src?: string }) {
  if (!rep) return <span className="text-ink-2">—</span>;
  const c = REP[rep] ?? REP.unknown;
  return <span className="inline-flex items-center gap-1.5 text-xs" title={src ? `Source: ${src}` : undefined}><span className="w-2 h-2 rounded-full" style={{ background: c }} />{rep}</span>;
}

/** Remote endpoints as a simple radial "map" (host-only lab IPs have no geography). */
function RemoteMap({ rows }: { rows: Conn[] }) {
  const remotes = Array.from(new Map(rows.filter((r) => r.raddr).map((r) => [r.raddr!, r])).values()).slice(0, 16);
  const R = 120, cx = 180, cy = 150;
  return (
    <svg viewBox="0 0 360 300" className="w-full max-w-md mx-auto">
      <circle cx={cx} cy={cy} r={R} fill="none" stroke="rgb(var(--rule))" strokeDasharray="2 5" />
      {remotes.map((r, i) => {
        const a = (i / Math.max(1, remotes.length)) * Math.PI * 2 - Math.PI / 2, x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
        const c = r.severity !== "Info" ? "rgb(var(--tape))" : "rgb(var(--ink-2))";
        return (
          <g key={r.raddr}>
            <line x1={cx} y1={cy} x2={x} y2={y} stroke={c} strokeWidth={r.severity !== "Info" ? 2.5 : 1} opacity={0.8} />
            <circle cx={x} cy={y} r={r.severity !== "Info" ? 8 : 5} fill={c} />
            <text x={x} y={y + (y > cy ? 20 : -12)} textAnchor="middle" fontSize="10" fill="rgb(var(--ink))" fontFamily="IBM Plex Mono, monospace">{r.raddr}:{r.rport}</text>
          </g>
        );
      })}
      <circle cx={cx} cy={cy} r={20} fill="rgb(var(--ink))" />
      <text x={cx} y={cy + 4} textAnchor="middle" fontSize="10" fill="rgb(var(--paper))" fontWeight="600">host</text>
    </svg>
  );
}

export default function NetworkPage() {
  const { id = "" } = useParams();
  const q = useNetwork(id);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const rows = q.data!;
  return (
    <div className="space-y-4">
      <PageHeader title="Network" subtitle={`${rows.length} connections seen in live state and in memory (Volatility netscan). Flagged rows are tinted.`} />
      <div className="grid lg:grid-cols-[300px_1fr] gap-5 items-start">
        <Card title="Who this host talked to" note="Red lines are connections a rule flagged."><RemoteMap rows={rows} /></Card>
        <div className="min-w-0">
          <DataTable<Conn> rows={rows} searchText={(r) => `${r.raddr} ${r.process} ${r.rport} ${r.lport} ${r.state}`}
            rowClass={(r) => (r.severity !== "Info" ? "bg-critical/[0.06]" : "")}
            columns={[
              { key: "sev", header: "", width: "80px", render: (r) => r.severity !== "Info" ? <SeverityBadge severity={r.severity} /> : null },
              { key: "l", header: "Local", render: (r) => <span className="font-mono text-xs whitespace-nowrap">{r.laddr}:{r.lport}</span> },
              { key: "r", header: "Remote", sort: (r) => r.raddr ?? "", render: (r) => <span className="font-mono text-xs whitespace-nowrap">{r.raddr ? `${r.raddr}:${r.rport}` : "—"}</span> },
              { key: "st", header: "State", sort: (r) => r.state, render: (r) => <span className="text-xs">{r.state}</span> },
              { key: "p", header: "Process", sort: (r) => r.process ?? "", render: (r) => <span className="whitespace-nowrap">{r.process ?? "unknown"} <span className="font-mono text-2xs text-ink-2">{r.pid}</span></span> },
              { key: "rep", header: "Reputation", render: (r) => <ReputationBadge rep={r.reputation} src={r.reputation_source} /> },
              { key: "e", header: "Evidence", render: (r) => <span className="flex items-center gap-1"><EvidenceChip evidenceRef={r.evidence_ref} label={r.sources.join("+")} /></span> },
            ]} />
        </div>
      </div>
    </div>
  );
}
