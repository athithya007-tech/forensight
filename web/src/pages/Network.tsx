import { Globe } from "lucide-react";
import { useParams } from "react-router-dom";
import { useNetwork } from "../api/client";
import type { Conn } from "../api/types";
import { DataTable } from "../components/DataTable";
import { EvidenceChip } from "../components/EvidenceChip";
import { SeverityBadge } from "../components/SeverityBadge";
import { Card, ErrorState, Loading, Mono, PageHeader } from "../components/ui";

const REP: Record<string, string> = { malicious: "#EF4444", suspicious: "#F97316", clean: "#22C55E", internal: "#9CA3AF", unknown: "#6B7280" };
export function ReputationBadge({ rep, src }: { rep?: string; src?: string }) {
  if (!rep) return <span className="text-muted">—</span>;
  const c = REP[rep] ?? REP.unknown;
  return <span className="rounded px-1.5 py-0.5 text-[11px] font-semibold" title={src ? `source: ${src}` : undefined} style={{ color: c, border: `1px solid ${c}66`, background: `${c}1f` }}>{rep}</span>;
}

/** Remote endpoints as a simple radial "map" (host-only lab IPs have no geography). */
function RemoteMap({ rows }: { rows: Conn[] }) {
  const remotes = Array.from(new Map(rows.filter((r) => r.raddr).map((r) => [r.raddr!, r])).values()).slice(0, 16);
  const R = 120, cx = 180, cy = 150;
  return (
    <svg viewBox="0 0 360 300" className="w-full max-w-md mx-auto">
      <circle cx={cx} cy={cy} r={R} fill="none" stroke="rgb(var(--border))" strokeDasharray="3 4" />
      {remotes.map((r, i) => {
        const a = (i / Math.max(1, remotes.length)) * Math.PI * 2 - Math.PI / 2, x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
        const c = r.severity !== "Info" ? "#EF4444" : REP[r.reputation ?? "unknown"];
        return (
          <g key={r.raddr}>
            <line x1={cx} y1={cy} x2={x} y2={y} stroke={c} strokeWidth={r.severity !== "Info" ? 2.5 : 1} opacity={0.8} />
            <circle cx={x} cy={y} r={r.severity !== "Info" ? 8 : 5} fill={c} />
            <text x={x} y={y + (y > cy ? 20 : -12)} textAnchor="middle" fontSize="10" fill="rgb(var(--muted))" fontFamily="JetBrains Mono, monospace">{r.raddr}:{r.rport}</text>
          </g>
        );
      })}
      <circle cx={cx} cy={cy} r={18} fill="rgb(var(--accent) / .2)" stroke="rgb(var(--accent))" />
      <text x={cx} y={cy + 4} textAnchor="middle" fontSize="10" fill="rgb(var(--accent))" fontWeight="700">HOST</text>
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
      <PageHeader title="Network" subtitle={`${rows.length} connections from live state and memory (netscan)`} />
      <div className="grid lg:grid-cols-3 gap-4">
        <Card title={<span className="inline-flex items-center gap-1.5"><Globe size={13} />Remote endpoints</span>}><RemoteMap rows={rows} /></Card>
        <div className="lg:col-span-2">
          <DataTable<Conn> rows={rows} searchText={(r) => `${r.raddr} ${r.process} ${r.rport} ${r.lport} ${r.state}`}
            rowClass={(r) => (r.severity !== "Info" ? "bg-critical/10" : "")}
            columns={[
              { key: "sev", header: "", width: "80px", render: (r) => r.severity !== "Info" ? <SeverityBadge severity={r.severity} /> : null },
              { key: "l", header: "Local", render: (r) => <Mono>{r.laddr}:{r.lport}</Mono> },
              { key: "r", header: "Remote", sort: (r) => r.raddr ?? "", render: (r) => <Mono>{r.raddr ? `${r.raddr}:${r.rport}` : "—"}</Mono> },
              { key: "st", header: "State", sort: (r) => r.state, render: (r) => <span className="text-[12px]">{r.state}</span> },
              { key: "p", header: "Process", sort: (r) => r.process ?? "", render: (r) => <span>{r.process} <Mono className="text-muted">({r.pid})</Mono></span> },
              { key: "rep", header: "Reputation", render: (r) => <ReputationBadge rep={r.reputation} src={r.reputation_source} /> },
              { key: "e", header: "Evidence", render: (r) => <span className="flex items-center gap-1"><EvidenceChip evidenceRef={r.evidence_ref} label={r.sources.join("+")} /></span> },
            ]} />
        </div>
      </div>
    </div>
  );
}
