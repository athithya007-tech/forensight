import { Bot, Send, Sparkles, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { ChatMsg, Citation } from "../api/types";
import { useUi } from "../stores/ui";
import { EvidenceChip } from "./EvidenceChip";
import { cx } from "./ui";

/** AI investigator chat (US-017): answers only from case evidence, every claim carries an EvidenceChip. */
export function ChatDrawer({ caseId }: { caseId: string }) {
  const open = useUi((s) => s.chatOpen);
  const setChat = useUi((s) => s.setChat);
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [suggested, setSuggested] = useState<string[]>([]);
  const [model, setModel] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    api<{ messages: any[]; suggested: string[]; model: string | null }>(`/api/cases/${caseId}/chat`).then((d) => {
      setMsgs(d.messages.map((m) => ({ role: m.role, content: m.content, citations: m.citations || [] })));
      setSuggested(d.suggested); setModel(d.model);
    }).catch(() => undefined);
  }, [open, caseId]);
  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  async function ask(question: string) {
    if (!question.trim() || busy) return;
    setQ(""); setBusy(true);
    setMsgs((m) => [...m, { role: "user", content: question, citations: [] }, { role: "assistant", content: "", citations: [], pending: true }]);
    const update = (fn: (m: ChatMsg) => ChatMsg) => setMsgs((all) => [...all.slice(0, -1), fn(all[all.length - 1])]);
    try {
      const r = await fetch(`/api/cases/${caseId}/chat`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question }) });
      const reader = r.body!.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const p = JSON.parse(line);
          if (p.type === "token") update((m) => ({ ...m, content: m.content + p.text }));
          if (p.type === "reset") update((m) => ({ ...m, content: "" }));
          if (p.type === "done") update(() => ({ role: "assistant", content: p.answer, citations: p.citations, model: p.model }));
        }
      }
    } catch (e) {
      update(() => ({ role: "assistant", content: `Chat failed: ${(e as Error).message}`, citations: [] }));
    } finally { setBusy(false); }
  }

  if (!open) return null;
  return (
    <aside className="fixed right-0 top-0 h-full w-full max-w-md z-40 bg-surface border-l border-border shadow-2xl flex flex-col slide-in">
      <header className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div>
          <div className="font-semibold flex items-center gap-2"><Sparkles size={16} className="text-accent" />Ask the evidence</div>
          <div className="text-[11.5px] text-muted">{model ? `Local model ${model} via Ollama · nothing leaves this machine` : "No local model running · answers are direct evidence summaries"}</div>
        </div>
        <button onClick={() => setChat(false)} className="text-muted hover:text-text" aria-label="Close chat"><X size={18} /></button>
      </header>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {!msgs.length && (
          <div className="space-y-2">
            <p className="text-muted text-[13px]">Answers use only this case's timeline and findings. Every claim links to its evidence.</p>
            {suggested.map((s) => (
              <button key={s} onClick={() => ask(s)} className="block w-full text-left rounded-md border border-border px-3 py-2 text-[13px] hover:border-accent hover:text-accent">{s}</button>
            ))}
          </div>
        )}
        {msgs.map((m, i) => <Message key={i} m={m} />)}
        <div ref={end} />
      </div>
      <form className="p-3 border-t border-border flex gap-2" onSubmit={(e) => { e.preventDefault(); ask(q); }}>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. Which accounts did the attacker use?" disabled={busy}
          className="flex-1 bg-bg border border-border rounded-md px-3 py-2 text-[13px] focus:outline-none focus:border-accent" />
        <button type="submit" disabled={busy || !q.trim()} className="rounded-md bg-accent text-[#0B0F17] px-3 disabled:opacity-40" aria-label="Send"><Send size={16} /></button>
      </form>
    </aside>
  );
}

function Message({ m }: { m: ChatMsg }) {
  if (m.role === "user") return <div className="ml-10 rounded-lg bg-accent/15 border border-accent/30 px-3 py-2 text-[13px]">{m.content}</div>;
  const byId = new Map<number, Citation>((m.citations || []).map((c) => [c.id, c]));
  const parts = m.content.split(/(\[E\d+\])/g);
  return (
    <div className="flex gap-2">
      <Bot size={18} className="text-accent shrink-0 mt-0.5" />
      <div className="min-w-0 flex-1 text-[13px] leading-relaxed">
        {m.pending && !m.content && <span className="text-muted animate-pulse">Searching the evidence…</span>}
        <div className="whitespace-pre-wrap">
          {parts.map((p, i) => {
            const mm = p.match(/^\[E(\d+)\]$/);
            if (!mm) return <span key={i}>{p}</span>;
            const c = byId.get(+mm[1]);
            return c ? <EvidenceChip key={i} evidenceRef={c.evidence_ref} label={`E${c.id}`} className="mx-0.5 align-middle" /> : <span key={i} className="text-muted">{p}</span>;
          })}
        </div>
        {!m.pending && m.citations?.length > 0 && (
          <div className={cx("mt-2 flex flex-wrap gap-1")}>
            {m.citations.map((c) => <EvidenceChip key={c.id} evidenceRef={c.evidence_ref} />)}
          </div>
        )}
      </div>
    </div>
  );
}
