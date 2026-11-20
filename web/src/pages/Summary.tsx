import { ArrowRight } from "lucide-react";
import { useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Line, LineChart, ReferenceDot, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { useEvents, useSummary } from "../api/client";
import { SEVERITIES, type Severity } from "../api/types";
import { EvidenceChip } from "../components/EvidenceChip";
import { ScoreScale, SEV_VAR, TimeScale, TimeScaleLabels } from "../components/ForensicScale";
import { SeverityBadge, VERDICT_COLOR } from "../components/SeverityBadge";
import { Card, Empty, ErrorState, Loading, Mono, fmtDateTime, fmtDuration, fmtTime } from "../components/ui";
import { useReplay } from "../stores/replay";

const HEADLINE: Record<string, (h: string) => string> = {
  Compromised: (h) => `${h} was compromised.`,
  Suspicious: (h) => `${h} shows suspicious activity.`,
  Clean: (h) => `${h} looks clean.`,
};

/** Events per minute across the attack window: Tufte sparkline, range frame, accent on the peak only. */
function ActivityRate({ times, start, end }: { times: number[]; start: number; end: number }) {
  const data = useMemo(() => {
    const m = 60_000, s0 = Math.floor(start / m) * m, n = Math.max(1, Math.ceil((end - s0) / m) + 1);
    const bins = Array.from({ length: n }, (_, i) => ({ t: s0 + i * m, n: 0 }));
    times.forEach((t) => { const i = Math.floor((t - s0) / m); if (bins[i]) bins[i].n++; });
    return bins;
  }, [times, start, end]);
  const peak = data.reduce((a, b) => (b.n > a.n ? b : a), data[0]);
  return (
    <div className="flex items-end gap-4">
      <div className="h-14 flex-1 min-w-0">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
            <XAxis dataKey="t" hide /><YAxis hide domain={[0, "dataMax"]} />
            <Line type="stepAfter" dataKey="n" stroke="rgb(var(--ink))" strokeWidth={1.25} dot={false} isAnimationActive={false} />
            <ReferenceDot x={peak.t} y={peak.n} r={3.5} fill="rgb(var(--tape))" stroke="none" />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="text-xs text-ink-2 shrink-0 w-36 leading-snug">
        Peak <b className="text-ink tnum">{peak.n}</b> notable events in the minute from <span className="font-mono">{new Date(peak.t).toISOString().slice(11, 16)}</span>
      </div>
    </div>
  );
}

export default function SummaryPage() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const q = useSummary(id);
  const ev = useEvents(id, { severity: ["Critical", "High", "Medium", "Low"] });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const s = q.data!;
  if (!s.analyzed) return (
    <Empty title="This case has not been analyzed yet"
      hint={<>Collected evidence is waiting. Run <code className="font-mono text-xs">forensight analyze --case {id}</code>, or watch a collection arrive on the live page.</>}
      action={<Link to={`/cases/${id}/collect`} className="text-sm underline">Open live collection</Link>} />
  );
  const h = s.host || {};
  const events = ev.data?.items ?? [];
  const start = s.attack_start ? Date.parse(s.attack_start) : 0;
  const end = s.attack_end ? Date.parse(s.attack_end) : 0;
  const pad = Math.max(30_000, (end - start) * 0.03);
  const total = SEVERITIES.reduce((n, k) => n + (s.severity_counts[k] ?? 0), 0) || 1;
  const replayAt = (eid: number) => {
    const order = events.filter((e) => e.severity === "Critical" || e.severity === "High");
    const i = order.findIndex((e) => e.id === eid);
    useReplay.getState().setIndex(i);
    nav(`/cases/${id}/story`);
  };

  return (
    <div className="max-w-[1180px] space-y-6">
      {/* the case, stated plainly */}
      <section className="grid lg:grid-cols-[1fr_360px] gap-x-10 gap-y-6 rise">
        <div className="min-w-0">
          <h1 className="h-display text-3xl" style={{ textWrap: "balance" } as any}>
            {(HEADLINE[s.verdict] ?? HEADLINE.Clean)(h.hostname ?? s.case.host)}
          </h1>
          <p className="font-serif text-lg leading-relaxed text-ink mt-3 max-w-[64ch]">{(s.exec_summary ?? "").split(" Sequence (UTC):")[0]}</p>
          <div className="flex flex-wrap gap-2 mt-4">
            <Link to={`/cases/${id}/story`} className="inline-flex items-center gap-1.5 rounded bg-ink text-paper px-3 h-8 text-sm font-medium hover:bg-tape transition-colors">
              Replay the attack<ArrowRight size={14} /></Link>
            <Link to={`/cases/${id}/report`} className="inline-flex items-center rounded border border-rule bg-sheet px-3 h-8 text-sm font-medium hover:border-ink-2 transition-colors">Open the signed report</Link>
          </div>
        </div>
        <div className="space-y-5 lg:pt-1">
          <div>
            <div className="flex items-baseline justify-between">
              <span className="text-sm text-ink-2">Compromise score</span>
              <span className="tnum"><b className="text-2xl font-semibold" style={{ color: VERDICT_COLOR[s.verdict] }}>{s.score}</b><span className="text-ink-2 text-sm"> of 100</span></span>
            </div>
            <ScoreScale score={s.score} />
          </div>
          <table className="w-full text-sm" aria-label="Findings by severity">
            <tbody>
              {SEVERITIES.slice(0, 4).map((k: Severity) => (
                <tr key={k} className="border-t border-rule first:border-t-0">
                  <td className="py-1.5 w-24"><SeverityBadge severity={k} /></td>
                  <td className="py-1.5"><div className="h-1.5 rounded-full" style={{ width: `${(100 * (s.severity_counts[k] ?? 0)) / total}%`, minWidth: s.severity_counts[k] ? 4 : 0, background: SEV_VAR[k] }} /></td>
                  <td className="py-1.5 w-10 text-right tnum font-medium">{s.severity_counts[k] ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* signature: the attack measured on the forensic scale */}
      {s.attack_start && (
        <Card title={`The attack lasted ${fmtDuration(s.duration_seconds)}`}
          note={<>From <span className="font-mono">{fmtTime(s.attack_start)}</span> to <span className="font-mono">{fmtTime(s.attack_end)}</span> UTC on {s.attack_start.slice(0, 10)}. Each mark is a notable event; tall marks are High or Critical. Click one to replay from there.</>}>
          <TimeScale start={start - pad} end={end + pad} onMark={replayAt}
            marks={events.map((e) => ({ t: Date.parse(e.timestamp_utc), severity: e.severity, id: e.id, label: e.description.slice(0, 80) }))} />
          <TimeScaleLabels start={start - pad} end={end + pad} count={7} />
          <div className="mt-4 pt-4 border-t border-rule grid md:grid-cols-[1fr_auto] gap-6 items-end">
            <ActivityRate times={events.map((e) => Date.parse(e.timestamp_utc))} start={start} end={end} />
            <dl className="flex gap-6 text-sm">
              <div><dt className="label">Findings</dt><dd className="text-lg font-semibold tnum">{s.findings}</dd></div>
              <div><dt className="label">Timeline events</dt><dd className="text-lg font-semibold tnum">{s.events}</dd></div>
              <div><dt className="label">Hashed artifacts</dt><dd className="text-lg font-semibold tnum">{s.artifacts}</dd></div>
            </dl>
          </div>
        </Card>
      )}

      <div className="grid lg:grid-cols-[1fr_360px] gap-6">
        <Card title="Look at these first" actions={<Link to={`/cases/${id}/findings`} className="text-sm underline text-ink-2 hover:text-ink">All {s.findings} findings</Link>}>
          {!s.top_findings.length ? <Empty title="Nothing to look at" hint="No rule matched on this host. The full timeline is still available for manual review." /> : (
            <ol className="divide-y divide-rule -mt-1">
              {s.top_findings.map((f) => (
                <li key={f.id} className="py-3 grid grid-cols-[5.5rem_1fr] gap-x-4">
                  <div className="pt-0.5"><SeverityBadge severity={f.severity} /><div className="font-mono text-2xs text-ink-2 mt-1">{fmtTime(f.first_seen)}</div></div>
                  <div className="min-w-0">
                    <div className="font-medium text-ink">{f.title} <span className="font-mono text-2xs text-ink-2 ml-1">{f.attck_id}</span></div>
                    <div className="text-sm text-ink-2 line-clamp-2 break-words mt-0.5">{f.description}</div>
                    <div className="mt-2 flex flex-wrap gap-1.5">{f.evidence.slice(0, 2).map((e) => <EvidenceChip key={e.ref} evidenceRef={e.ref} />)}</div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Card>
        <div className="space-y-6">
          <Card title="Host">
            <div className="font-serif text-xl -mt-1 mb-2">{h.hostname}</div>
            <dl className="grid grid-cols-[6.5rem_1fr] gap-y-1.5 text-sm">
              {[["System", `${h.os ?? ""} ${h.os_version ?? ""}`], ["Address", h.ip], ["Time zone", h.timezone], ["Investigator", s.case.investigator],
                ["Case opened", fmtDateTime(s.case.created_at)], ["Collection", s.collection?.profile]].filter(([, v]) => v && String(v).trim()).map(([k, v]) => (
                <div key={k} className="contents"><dt className="text-ink-2">{k}</dt><dd><Mono className="text-ink">{v}</Mono></dd></div>
              ))}
            </dl>
          </Card>
          <Card title="Path through ATT&CK" actions={<Link to={`/cases/${id}/attack`} className="text-sm underline text-ink-2 hover:text-ink">Map</Link>}>
            {!s.tactics.length ? <p className="text-sm text-ink-2">No techniques detected.</p> : (
              <ol className="relative ml-1.5 border-l border-ink/70 space-y-2 -mt-1">
                {s.tactics.map((t) => (
                  <li key={t.tactic} className="pl-4 relative text-sm">
                    <span className="absolute -left-[4.5px] top-[7px] w-2 h-2 rounded-full bg-ink" aria-hidden />
                    <span className="font-medium">{t.tactic}</span>
                    <span className="text-ink-2"> · {t.techniques.map((x) => x.id).join(", ")}</span>
                  </li>
                ))}
              </ol>
            )}
          </Card>
          {s.engines && (
            <p className="text-xs text-ink-2 leading-relaxed px-1">
              Analysed with {s.engines.custom_rules} custom rules and {s.engines.sigma_rules} Sigma rules ({s.engines.chainsaw ? "Chainsaw" : "built-in engine"}),
              YARA, {s.engines.volatility ? "Volatility 3 memory analysis" : "no memory analysis"} and {s.engines.online_intel ? "online" : "offline"} threat intel.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
