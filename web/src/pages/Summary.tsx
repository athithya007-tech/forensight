import { Clock, Cpu, Fingerprint, Monitor } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useSummary } from "../api/client";
import { SEVERITIES } from "../api/types";
import { EvidenceChip } from "../components/EvidenceChip";
import { ScoreGauge } from "../components/ScoreGauge";
import { SEV_COLOR, SeverityBadge, VerdictBadge } from "../components/SeverityBadge";
import { Card, Empty, ErrorState, Loading, Mono, fmtDateTime, fmtDuration, fmtTime } from "../components/ui";

export default function SummaryPage() {
  const { id = "" } = useParams();
  const q = useSummary(id);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const s = q.data!;
  if (!s.analyzed) return <Card><Empty title="This case has not been analyzed yet" hint={<>Collect evidence, then run <code className="font-mono">forensight analyze --case {id}</code>, or open <Link className="text-accent" to={`/cases/${id}/collect`}>Live collection</Link>.</>} /></Card>;
  const h = s.host || {};
  return (
    <div className="space-y-4">
      {/* Row 1: gauge + verdict + duration */}
      <div className="grid lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-1" bodyClass="flex flex-col items-center pt-6">
          <ScoreGauge score={s.score} verdict={s.verdict} />
          <div className="mt-2"><VerdictBadge verdict={s.verdict} size="lg" /></div>
        </Card>
        <Card className="lg:col-span-2" title="What happened">
          <p className="text-[14px] leading-relaxed">{s.exec_summary}</p>
          <div className="grid sm:grid-cols-3 gap-3 mt-4">
            <div className="rounded-md border border-border p-3"><div className="text-[12px] text-muted flex items-center gap-1"><Clock size={12} />Attack duration</div>
              <div className="text-xl font-bold mt-1">{fmtDuration(s.duration_seconds)}</div><div className="text-[12px] text-muted">{fmtTime(s.attack_start)} → {fmtTime(s.attack_end)} UTC</div></div>
            <div className="rounded-md border border-border p-3"><div className="text-[12px] text-muted">Findings / events</div>
              <div className="text-xl font-bold mt-1">{s.findings} <span className="text-muted text-base font-normal">/ {s.events}</span></div><div className="text-[12px] text-muted">{s.techniques.length} ATT&CK techniques</div></div>
            <div className="rounded-md border border-border p-3"><div className="text-[12px] text-muted flex items-center gap-1"><Fingerprint size={12} />Evidence</div>
              <div className="text-xl font-bold mt-1">{s.artifacts}</div><div className="text-[12px] text-muted">artifacts, SHA-256 chained</div></div>
          </div>
        </Card>
      </div>
      {/* Row 2: severity counts */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {SEVERITIES.slice(0, 4).map((sev) => (
          <Link key={sev} to={`/cases/${id}/findings`} className="bg-surface border border-border rounded-lg px-4 py-3 hover:border-accent/50" style={{ borderLeft: `4px solid ${SEV_COLOR[sev]}` }}>
            <div className="text-[12px] uppercase tracking-wide text-muted">{sev}</div>
            <div className="text-3xl font-extrabold tabular-nums mt-1" style={{ color: SEV_COLOR[sev] }}>{s.severity_counts[sev]}</div>
          </Link>
        ))}
      </div>
      {/* Row 3: top findings + host + tactic strip */}
      <div className="grid lg:grid-cols-3 gap-4">
        <Card title="Top 5 findings" className="lg:col-span-2" actions={<Link to={`/cases/${id}/findings`} className="text-accent text-[12px]">All findings →</Link>}>
          {!s.top_findings.length ? <Empty title="No findings" hint="Nothing suspicious detected." /> : (
            <ul className="divide-y divide-border">
              {s.top_findings.map((f) => (
                <li key={f.id} className="py-2.5 flex gap-3">
                  <SeverityBadge severity={f.severity} className="mt-0.5" />
                  <div className="min-w-0 flex-1">
                    <div className="font-medium">{f.title} <span className="font-mono text-[12px] text-muted">{f.attck_id}</span></div>
                    <div className="text-[13px] text-muted truncate" title={f.description}>{f.description}</div>
                    <div className="mt-1 flex flex-wrap gap-1">{f.evidence.slice(0, 2).map((e) => <EvidenceChip key={e.ref} evidenceRef={e.ref} />)}</div>
                  </div>
                  <span className="font-mono text-[12px] text-muted shrink-0">{fmtTime(f.first_seen)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <div className="space-y-4">
          <Card title="Host">
            <div className="space-y-1.5 text-[13px]">
              <div className="flex items-center gap-2 font-semibold text-base"><Monitor size={16} className="text-accent" />{h.hostname}</div>
              {[["OS", `${h.os ?? ""} ${h.os_version ?? ""}`], ["IP", h.ip], ["Timezone", h.timezone], ["Investigator", s.case.investigator], ["Opened", fmtDateTime(s.case.created_at)],
                ["Collection", s.collection?.profile]].filter(([, v]) => v).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3"><span className="text-muted">{k}</span><Mono>{v}</Mono></div>
              ))}
            </div>
          </Card>
          <Card title="Kill chain" actions={<Link to={`/cases/${id}/attack`} className="text-accent text-[12px]">Heatmap →</Link>}>
            <div className="flex flex-wrap items-center gap-1 text-[12px]">
              {s.tactics.map((t, i) => (
                <span key={t.tactic} className="inline-flex items-center gap-1">
                  <span className="rounded px-2 py-1 bg-accent/10 border border-accent/30 text-accent">{t.tactic} <b>{t.count}</b></span>
                  {i < s.tactics.length - 1 && <span className="text-muted">→</span>}
                </span>
              ))}
              {!s.tactics.length && <span className="text-muted">No techniques detected</span>}
            </div>
          </Card>
          {s.engines && (
            <Card title="Engines"><div className="text-[12px] text-muted space-y-1">
              <div className="flex items-center gap-1.5"><Cpu size={12} />Volatility 3: {s.engines.volatility ? "memory analysed" : "no memory output"}</div>
              <div>{s.engines.custom_rules} custom rules · {s.engines.sigma_rules} Sigma rules ({s.engines.chainsaw ? "Chainsaw" : "built-in engine"})</div>
              <div>Threat intel: {s.engines.online_intel ? "online (hash/IP only)" : "offline lists"}</div></div></Card>
          )}
        </div>
      </div>
    </div>
  );
}
