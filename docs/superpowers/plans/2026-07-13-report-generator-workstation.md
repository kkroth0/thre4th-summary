# Report Generator Workstation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign `/daily-bulletin` ("Gerador de Relatorios") from a single column into a full-width two-pane workstation: work column (generate, queue, suggestions) on the left, persistent report pane on the right.

**Architecture:** Pure front-end refactor of one page plus one new presentational component. `DailyBulletin.tsx` keeps all state, polling, and persistence logic; a new `ReportPane.tsx` owns the report toolbar, title, empty state, and wraps the existing `BoletimView`. `BoletimView` loses its meta row (TLP/date/source), which moves to the pane toolbar.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, lucide-react, sonner.

**Spec:** `docs/superpowers/specs/2026-07-13-report-generator-workstation-design.md`

## Global Constraints

- No backend/API changes. All `threatApi` calls, 3s polling, `CLIENT_TIMEOUT_MS` (25 min), `ts-bulletins-v1` localStorage key, and `MAX_HISTORY` (40) stay exactly as they are.
- All user-facing strings follow the existing dual-language pattern: `pt ? "…" : "…"`.
- No new unit tests (per spec): the new logic is thin UI glue. Verification is `npm run ci` (lint + typecheck + build) per task plus rendered QA in Task 4.
- Comments in code follow the repo's existing mixed pt-BR/English comment style; keep existing comments where the code they describe survives.
- `BoletimView` must stay tolerant of missing/partial report fields.

---

### Task 1: Strip the meta row out of BoletimView

`ReportPane` (Task 2) will render TLP, date, and source in its toolbar, so `BoletimView` keeps only the content sections. `DailyBulletin.tsx` is the only consumer, so nothing else changes.

**Files:**
- Modify: `src/components/BoletimView.tsx`

**Interfaces:**
- Consumes: nothing new.
- Produces: `BoletimView({ report: BoletimReport })` — same signature, but no longer renders TLP badge, generated date, or source link, and no longer draws its own `border-t` top frame. Task 2 relies on this.

- [ ] **Step 1: Remove the meta row and top-border wrapper**

In `src/components/BoletimView.tsx`, replace this block (the wrapper `div` opening plus the whole `{/* meta */}` block):

```tsx
  return (
    <div className="mt-3 border-t pt-3 text-sm">
      {/* meta */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {r.tlp && <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">TLP:{r.tlp}</Badge>}
        {r.generated_at && <span className="text-muted-foreground">{fmtDate(r.generated_at)}</span>}
        {r.source_url && (
          <a href={r.source_url} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:underline inline-flex items-center gap-1 truncate max-w-[60%]">
            fonte <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        )}
      </div>

      {r.sumario_executivo && (
```

with:

```tsx
  return (
    <div className="mt-4 text-sm">
      {r.sumario_executivo && (
```

Then delete the now-unused `fmtDate` helper:

```tsx
const fmtDate = (iso?: string) => {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(+d) ? "" : d.toLocaleDateString("pt-BR");
};
```

Keep the `ExternalLink` import (still used by the references section) and the `Badge` import (still used by technology/KEV badges). Update the file's top comment to drop the meta mention:

```tsx
// Visualizador inline do JSON do boletim — mostra o que foi coletado (sumário,
// produto/CVE, IOCs por Pirâmide da Dor, TTPs MITRE, referências). O meta
// (TLP/data/fonte) fica com quem embute (ReportPane). Tolerante a campos
// ausentes e aos dois deck_types.
```

- [ ] **Step 2: Verify it compiles and lints**

Run: `npm run lint && npm run typecheck`
Expected: both exit 0. If `fmtDate` or an import were left dangling, eslint's unused-var rule fails — remove the leftover.

- [ ] **Step 3: Commit**

```bash
git add src/components/BoletimView.tsx
git commit -m "refactor: move boletim meta out of BoletimView"
```

---

### Task 2: ReportPane component

New right-pane component: empty state when nothing is selected; otherwise toolbar (TLP, type, date, source, admin draft action, JSON download), title, and `BoletimView` body.

**Files:**
- Create: `src/components/ReportPane.tsx`

**Interfaces:**
- Consumes: `BoletimView({ report })` (Task 1 shape, no meta row), `PostEditor({ initial, trigger, onSaved })`, `boletimToDraft(json): { title, summary, body, tags }`, `BrandMark({ className })`, `BoletimJob` from `@/services/threatApi`.
- Produces (Task 3 relies on these exact names):
  - `ReportPane({ job: BoletimJob | null, isAdmin: boolean, onDownload: (job: BoletimJob) => void })` — renders empty state when `job` is `null`.
  - `hostOf(url?: string): string` — named export, returns URL host or `""`.

- [ ] **Step 1: Create the component**

Create `src/components/ReportPane.tsx`:

```tsx
import React from "react";
import { Download, ExternalLink, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BrandMark } from "@/components/BrandMark";
import { BoletimView } from "@/components/BoletimView";
import { PostEditor } from "@/components/PostEditor";
import { boletimToDraft } from "@/services/boletimMarkdown";
import { useLanguage } from "@/contexts/LanguageContext";
import type { BoletimJob } from "@/services/threatApi";

// Host da URL pra exibição compacta ("fortiguard.com" em vez do link inteiro).
export const hostOf = (url?: string): string => {
  try { return url ? new URL(url).host : ""; } catch { return ""; }
};

const fmtDate = (iso?: string) => {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(+d) ? "" : d.toLocaleDateString("pt-BR");
};

// Painel de leitura da workstation: toolbar com meta/ações + BoletimView.
// `job === null` (ou sem JSON) mostra o estado vazio.
export function ReportPane({ job, isAdmin, onDownload }: {
  job: BoletimJob | null;
  isAdmin: boolean;
  onDownload: (job: BoletimJob) => void;
}) {
  const { language } = useLanguage();
  const pt = language === "pt";

  if (!job || !job.json) {
    return (
      <div className="flex min-h-[420px] flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border/60 p-8 text-center">
        <BrandMark className="h-11 w-11 opacity-80" />
        <div>
          <div className="text-sm font-medium">{pt ? "Nenhum relatório aberto" : "No report open"}</div>
          <p className="mt-1 max-w-[36ch] text-xs text-muted-foreground">
            {pt
              ? "Selecione um relatório pronto na lista ou cole uma URL para gerar um novo."
              : "Select a finished report from the list or paste a URL to generate a new one."}
          </p>
        </div>
      </div>
    );
  }

  const r = job.json;
  return (
    <div className="rounded-xl border bg-card/40 p-5 lg:p-6">
      {/* toolbar: meta à esquerda, ações à direita */}
      <div className="flex flex-wrap items-center gap-2">
        {r.tlp && (
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
            TLP:{r.tlp}
          </Badge>
        )}
        <Badge variant="secondary" className="font-mono text-[10px] uppercase">{job.type}</Badge>
        {r.generated_at && <span className="text-xs text-muted-foreground">{fmtDate(r.generated_at)}</span>}
        {r.source_url && (
          <a
            href={r.source_url} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
          >
            {hostOf(r.source_url)} <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        )}
        <div className="ml-auto flex items-center gap-2">
          {isAdmin && (
            <PostEditor
              key={job.id}
              initial={boletimToDraft(r)}
              trigger={
                <Button variant="outline" size="sm" className="gap-1.5">
                  <Sparkles className="h-3.5 w-3.5" />
                  {pt ? "Salvar como Advisory" : "Save as Advisory"}
                </Button>
              }
              onSaved={() => toast.success(pt ? "Rascunho salvo em Advisories" : "Draft saved to Advisories")}
            />
          )}
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onDownload(job)}>
            <Download className="h-3.5 w-3.5" /> JSON
          </Button>
        </div>
      </div>

      <h2 className="mt-4 text-lg font-semibold leading-snug">
        {r.titulo || job.title || job.url}
      </h2>

      <BoletimView report={r} />
    </div>
  );
}

export default ReportPane;
```

Note: the pane title prefers the report's own `titulo` (the engine fills it), falling back to the job title, then the URL.

- [ ] **Step 2: Verify it compiles and lints**

Run: `npm run lint && npm run typecheck`
Expected: both exit 0 (component is not yet imported anywhere — that's fine).

- [ ] **Step 3: Commit**

```bash
git add src/components/ReportPane.tsx
git commit -m "feat: add ReportPane for the report workstation"
```

---

### Task 3: DailyBulletin workstation layout

Rewrite the page: `max-w-7xl`, two-column grid on `lg+`, job cards with select/deselect + auto-select + retry, compact suggestions, sticky right pane.

**Files:**
- Modify: `src/pages/DailyBulletin.tsx` (full rewrite below)

**Interfaces:**
- Consumes: `ReportPane` and `hostOf` from `@/components/ReportPane` (Task 2), `PageLayout width` prop, existing `threatApi` functions.
- Produces: final page. Behavior contract: click done job → opens in pane; click again → deselects; pending→done transition with nothing selected → auto-select; error rows expose retry.

- [ ] **Step 1: Replace the page**

Replace the entire contents of `src/pages/DailyBulletin.tsx` with:

```tsx
import React, { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import {
  RefreshCw, ShieldAlert, Loader2, Sparkles, Trash2, KeyRound,
  CheckCircle2, ArrowRight, RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader,
  AlertDialogFooter, AlertDialogTitle, AlertDialogDescription, AlertDialogAction,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { PageLayout } from "@/components/PageLayout";
import { PageHeader } from "@/components/PageHeader";
import { ReportPane, hostOf } from "@/components/ReportPane";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  fetchDailySuggestions, generateBoletim, fetchJob,
  type DailySuggestion, type BoletimJob, type DeckType,
} from "@/services/threatApi";

const slug = (s: string) => (s || "boletim").normalize("NFKD").replace(/[^\w\s-]/g, "").trim().toLowerCase().replace(/[\s_-]+/g, "-").slice(0, 50) || "boletim";

// Após esse tempo um job ainda "pending" vira erro no front (worker caiu, ou o
// backend reiniciou e perdeu o job -> 404). Evita "gerando…" eterno. Casado com
// o JOB_TTL_MS do servidor (25 min) pra não expirar antes dele numa fila cheia.
const CLIENT_TIMEOUT_MS = 25 * 60 * 1000;

// Histórico dos relatórios gerados, persistido no navegador (sobrevive a sair da
// página / recarregar) — assim você não regenera nem gasta API ao voltar.
const STORAGE_KEY = "ts-bulletins-v1";
const MAX_HISTORY = 40;

// Fases estimadas pelo tempo decorrido (mapeiam o pipeline real: coleta ~10-15s,
// análise LLM ~15-30s). Não é progresso real, mas dá feedback agradável.
const PHASES = [
  { pt: "Coletando a página…", en: "Fetching the page…" },
  { pt: "Analisando com IA…", en: "Analyzing with AI…" },
  { pt: "Montando o boletim…", en: "Assembling the bulletin…" },
];
const phaseIndex = (elapsedMs: number) => (elapsedMs < 15000 ? 0 : elapsedMs < 40000 ? 1 : 2);

// Minimal status: a small dot + a muted label. Colour only where it means
// something (amber = working, emerald = ready, red = failed).
const JOB_STATUS: Record<string, { dot: string; text: string; pt: string; en: string }> = {
  pending: { dot: "bg-amber-500", text: "text-amber-600 dark:text-amber-400", pt: "Gerando", en: "Generating" },
  done: { dot: "bg-emerald-500", text: "text-emerald-600 dark:text-emerald-400", pt: "Pronto", en: "Ready" },
  error: { dot: "bg-red-500", text: "text-red-600 dark:text-red-400", pt: "Erro", en: "Error" },
};

// Tiny severity dot for suggestion rows (kept subtle for the minimal look).
const SEV_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-slate-400",
};

// "há 12 min" / "12 min ago" pros cards prontos. Grosseiro de propósito.
const timeAgo = (iso: string, pt: boolean) => {
  const min = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (min < 1) return pt ? "agora" : "just now";
  if (min < 60) return pt ? `há ${min} min` : `${min} min ago`;
  const h = Math.round(min / 60);
  if (h < 24) return pt ? `há ${h} h` : `${h} h ago`;
  const d = Math.round(h / 24);
  return pt ? `há ${d} d` : `${d} d ago`;
};

// Card de job na coluna de trabalho. Pronto (com JSON) é clicável e abre no
// painel; gerando mostra fase + barra; erro expõe "tentar de novo".
const JobListItem: React.FC<{
  job: BoletimJob;
  selected: boolean;
  nowMs: number;
  pt: boolean;
  onSelect: (job: BoletimJob) => void;
  onRetry: (job: BoletimJob) => void;
}> = ({ job: j, selected, nowMs, pt, onSelect, onRetry }) => {
  const st = JOB_STATUS[j.status] || JOB_STATUS.pending;
  const elapsed = Math.max(0, nowMs - new Date(j.createdAt).getTime());
  const clickable = j.status === "done" && !!j.json;
  return (
    <div
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={clickable ? () => onSelect(j) : undefined}
      onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(j); } } : undefined}
      className={cn(
        "rounded-lg border px-3 py-2.5 transition-colors animate-fade-in",
        selected ? "border-primary/40 bg-primary/5" : "border-transparent",
        clickable && "cursor-pointer",
        clickable && !selected && "hover:bg-muted/40"
      )}
    >
      <div className="flex items-center gap-3">
        <span className={`h-2 w-2 rounded-full shrink-0 ${st.dot} ${j.status === "pending" ? "animate-pulse" : ""}`} />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium truncate">{j.title || j.url}</div>
          <div className="text-xs text-muted-foreground truncate">
            <span className={st.text}>{pt ? st.pt : st.en}</span>
            {j.status === "done" ? ` · ${timeAgo(j.updatedAt || j.createdAt, pt)}` : ""}
            {" · "}{hostOf(j.url) || j.url}
          </div>
        </div>
        {j.status === "pending" && (
          <span className="text-xs text-muted-foreground shrink-0 tabular-nums">{Math.floor(elapsed / 1000)}s</span>
        )}
        {j.status === "done" && (
          <span className="rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground shrink-0">{j.type}</span>
        )}
      </div>
      {j.status === "error" && (
        <div className="mt-1.5 flex items-center gap-2 pl-5">
          <span className="min-w-0 flex-1 truncate text-xs text-red-500/90">{j.error || (pt ? "falhou" : "failed")}</span>
          <Button
            size="sm" variant="ghost" className="h-6 px-2 text-xs text-muted-foreground hover:text-foreground shrink-0"
            onClick={(e) => { e.stopPropagation(); onRetry(j); }}
          >
            <RotateCcw className="h-3 w-3 mr-1" /> {pt ? "tentar de novo" : "retry"}
          </Button>
        </div>
      )}
      {j.status === "pending" && (
        <div className="mt-2 pl-5">
          <div className="relative h-1 w-full overflow-hidden rounded-full bg-muted">
            <span className="absolute top-0 h-full rounded-full bg-primary/70 animate-indeterminate" />
          </div>
          <div className="mt-1.5 text-xs text-muted-foreground">
            {j.queuePosition && j.queuePosition > 0
              ? (pt ? `Na fila, ${j.queuePosition} na sua frente` : `In queue, ${j.queuePosition} ahead of you`)
              : (pt ? PHASES[phaseIndex(elapsed)].pt : PHASES[phaseIndex(elapsed)].en)}
          </div>
        </div>
      )}
    </div>
  );
};

const DailyBulletin: React.FC = () => {
  const { language } = useLanguage();
  const pt = language === "pt";

  const [suggestions, setSuggestions] = useState<DailySuggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const [pasteUrl, setPasteUrl] = useState("");
  const [pasteType, setPasteType] = useState<DeckType>("vuln");
  const [jobs, setJobs] = useState<BoletimJob[]>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? (JSON.parse(raw) as BoletimJob[]) : [];
    } catch { return []; }
  });
  const [nowMs, setNowMs] = useState(Date.now());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const paneRef = useRef<HTMLDivElement | null>(null);

  // Sessão compartilhada (GitHub + BYOK). Identidade e chave vivem em /profile;
  // aqui a gente só usa o estado pra liberar (ou barrar) o gerador.
  const { auth } = useAuth();

  const loadSuggestions = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchDailySuggestions(36, 12);
      setSuggestions(data.suggestions || []);
    } catch {
      toast.error(pt ? "Falha ao carregar sugestões" : "Failed to load suggestions");
    } finally {
      setLoading(false);
    }
  }, [pt]);

  useEffect(() => { loadSuggestions(); }, [loadSuggestions]);

  // Persiste o histórico no navegador a cada mudança (guarda só os mais recentes).
  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(jobs.slice(0, MAX_HISTORY))); }
    catch { /* quota cheia: ignora */ }
  }, [jobs]);

  // Poll dos jobs não-terminais a cada 3s. Quando um job termina e nada está
  // aberto no painel, ele é selecionado sozinho (você estava esperando ele).
  useEffect(() => {
    const tick = async () => {
      const open = jobs.filter((j) => j.status === "pending");
      if (!open.length) return;
      const updated = await Promise.all(open.map(async (j) => {
        const tooOld = Date.now() - new Date(j.createdAt).getTime() > CLIENT_TIMEOUT_MS;
        try {
          const u = await fetchJob(j.id);
          if (u.status === "pending" && tooOld) return { ...u, status: "error" as const, error: "tempo esgotado" };
          return u;
        } catch {
          // 404 (servidor reiniciou e perdeu o job) ou rede: só marca erro depois do tempo
          return tooOld ? { ...j, status: "error" as const, error: "job perdido (servidor reiniciou?)" } : null;
        }
      }));
      const finished = updated.find((u) => u && u.status === "done" && u.json);
      if (finished) setSelectedId((cur) => cur ?? finished.id);
      setJobs((prev) => prev.map((j) => {
        const u = updated.find((x) => x && x.id === j.id);
        return u || j;
      }));
    };
    if (jobs.some((j) => j.status === "pending")) {
      pollRef.current = setInterval(tick, 3000);
      return () => { if (pollRef.current) clearInterval(pollRef.current); };
    }
  }, [jobs]);

  // Ticker de 1s só enquanto há job gerando — alimenta a animação de fases.
  useEffect(() => {
    if (!jobs.some((j) => j.status === "pending")) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [jobs]);

  const generate = async (url: string, type: DeckType, title: string) => {
    if (!auth?.authenticated) { toast.error(pt ? "Entre com o GitHub para gerar" : "Sign in with GitHub to generate"); return; }
    if (!/^https?:\/\//i.test(url)) { toast.error(pt ? "URL inválida" : "Invalid URL"); return; }
    try {
      const { id } = await generateBoletim(url, type, title);
      const now = new Date().toISOString();
      setJobs((prev) => [
        { id, url, type, title, status: "pending", json: null, error: null, createdAt: now, updatedAt: now },
        ...prev,
      ]);
      toast.success(pt ? "Começou. O relatório abre aqui quando ficar pronto." : "Started. The report opens here when it's ready.");
    } catch (e) {
      toast.error((e as Error).message || (pt ? "Falha ao iniciar" : "Failed to start"));
    }
  };

  const download = (job: BoletimJob) => {
    const blob = new Blob([JSON.stringify(job.json, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `boletim-${job.type}-${slug(job.title || job.url)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Apaga o histórico de relatórios (estado + localStorage, via efeito de persistência).
  const clearHistory = () => {
    setJobs([]);
    setSelectedId(null);
    toast.success(pt ? "Histórico apagado" : "History cleared");
  };

  // Abre/fecha um relatório no painel. Em telas menores (colunas empilhadas) o
  // painel fica abaixo da lista, então rola até ele ao abrir.
  const selectJob = (j: BoletimJob) => {
    const next = selectedId === j.id ? null : j.id;
    setSelectedId(next);
    if (next && typeof window !== "undefined" && window.innerWidth < 1024) {
      setTimeout(() => paneRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    }
  };

  const retryJob = (j: BoletimJob) => { generate(j.url, j.type, j.title); };

  // Report currently opened on the right pane.
  const selectedJob = jobs.find((j) => j.id === selectedId && j.status === "done" && j.json) || null;

  return (
    <PageLayout width="max-w-7xl">
      <PageHeader
        title={pt ? "Gerador de Relatorios" : "Report Generator"}
        subtitle={pt
          ? "Cole o link de um relatório ou notícia de segurança. Ele é resumido sozinho e você baixa o JSON pronto pro seu slide."
          : "Paste a link to a security report or news post. It gets summarized on its own and you download the JSON for your slide."}
      />

      <div className="grid gap-10 lg:grid-cols-[400px_1fr] lg:items-start lg:gap-8">
        {/* ── work column ───────────────────────────────────────────── */}
        <div className="min-w-0 space-y-10">
          {/* Generator — one calm input row, no card chrome */}
          <section>
            {auth.authenticated ? (
              <div className="space-y-3">
                <div className="flex flex-col gap-2 rounded-xl bg-muted/40 p-2">
                  <Input
                    placeholder={pt ? "Cole uma URL…" : "Paste a URL…"}
                    value={pasteUrl}
                    onChange={(e) => setPasteUrl(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && pasteUrl.trim()) { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); } }}
                    className="flex-1 border-0 bg-transparent shadow-none focus-visible:ring-0 px-2"
                  />
                  <div className="flex gap-2">
                    <Select value={pasteType} onValueChange={(v) => setPasteType(v as DeckType)}>
                      <SelectTrigger className="w-[140px] border-0 bg-transparent shadow-none focus:ring-0"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="vuln">{pt ? "Vulnerabilidade" : "Vulnerability"}</SelectItem>
                        <SelectItem value="campaign">{pt ? "Campanha" : "Campaign"}</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button onClick={() => { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); }} disabled={!pasteUrl.trim()} className="ml-auto gap-2">
                      <Sparkles className="h-4 w-4" /> {pt ? "Gerar" : "Generate"}
                    </Button>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 px-1 text-xs text-muted-foreground">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                  <span className="truncate">{auth.login} · {pt ? "pronto para gerar" : "ready to generate"}</span>
                  <Link to="/settings" className="ml-auto shrink-0 hover:text-foreground">{pt ? "Configurações" : "Settings"}</Link>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-4 rounded-xl bg-muted/40 p-5">
                <KeyRound className="h-5 w-5 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium">{pt ? "Entre para gerar" : "Sign in to generate"}</div>
                  <div className="text-xs text-muted-foreground">{pt ? "Requer login com GitHub (acesso liberado)." : "Requires GitHub sign-in (approved access)."}</div>
                </div>
                <Button asChild variant="outline" size="sm" className="shrink-0">
                  <Link to="/login">{pt ? "Entrar" : "Sign in"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
                </Button>
              </div>
            )}
          </section>

          {/* Your reports — selectable job cards */}
          <section>
            <div className="flex items-center justify-between mb-1.5">
              <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                {pt ? "Seus relatorios" : "Your reports"}{jobs.length > 0 ? ` · ${jobs.length}` : ""}
              </h2>
              {jobs.length > 0 && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-muted-foreground hover:text-destructive">
                      <Trash2 className="h-3.5 w-3.5 mr-1.5" /> {pt ? "Limpar" : "Clear"}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{pt ? "Limpar histórico de relatorios?" : "Clear report history?"}</AlertDialogTitle>
                      <AlertDialogDescription>
                        {pt
                          ? "Isso apaga todos os relatórios desta lista (incluindo os JSON gerados) deste navegador. Não dá pra desfazer."
                          : "This removes all reports from this list (including the generated JSON) on this browser. This can't be undone."}
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{pt ? "Cancelar" : "Cancel"}</AlertDialogCancel>
                      <AlertDialogAction onClick={clearHistory}>{pt ? "Apagar" : "Delete"}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}
            </div>

            {jobs.length === 0 ? (
              <p className="py-10 text-center text-sm text-muted-foreground">
                {pt ? "Nenhum relatorio ainda. Cole uma URL ou gere a partir de uma sugestão." : "No reports yet. Paste a URL or generate from a suggestion."}
              </p>
            ) : (
              <div className="space-y-1.5">
                {jobs.map((j) => (
                  <JobListItem
                    key={j.id}
                    job={j}
                    selected={selectedId === j.id}
                    nowMs={nowMs}
                    pt={pt}
                    onSelect={selectJob}
                    onRetry={retryJob}
                  />
                ))}
              </div>
            )}
          </section>

          {/* Suggestions — quiet hairline list, action on hover */}
          <section>
            <div className="flex items-center justify-between mb-1.5">
              <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{pt ? "Sugestões do dia" : "Today's suggestions"}</h2>
              <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground" onClick={loadSuggestions} disabled={loading} title={pt ? "Atualizar" : "Refresh"}>
                {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
              </Button>
            </div>
            {suggestions.length > 0 ? (
              <div className="divide-y divide-border/60">
                {suggestions.map((s) => (
                  <div key={s.url} className="group flex items-center gap-3 py-2.5">
                    <span className={`h-2 w-2 rounded-full shrink-0 ${SEV_DOT[s.severity] || SEV_DOT.Low}`} title={s.severity} />
                    <a href={s.url} target="_blank" rel="noopener noreferrer" className="min-w-0 flex-1 truncate text-sm hover:underline" title={s.title}>
                      {s.title}
                    </a>
                    {s.kev && <ShieldAlert className="h-3.5 w-3.5 text-red-500 shrink-0" aria-label="CISA KEV" />}
                    {s.cves?.[0] && <span className="hidden xl:inline text-[11px] font-mono text-muted-foreground shrink-0">{s.cves[0]}</span>}
                    <Button size="sm" variant="ghost" onClick={() => generate(s.url, s.suggestedType, s.title)} className="h-7 px-2 text-primary shrink-0 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
                      <Sparkles className="h-3.5 w-3.5 mr-1" /> {pt ? "Gerar" : "Generate"}
                    </Button>
                  </div>
                ))}
              </div>
            ) : loading ? (
              <div className="py-10 text-center"><Loader2 className="h-4 w-4 animate-spin mx-auto text-muted-foreground" /></div>
            ) : (
              <p className="py-10 text-center text-sm text-muted-foreground">{pt ? "Nenhuma sugestão no momento." : "No suggestions right now."}</p>
            )}
          </section>
        </div>

        {/* ── report pane ───────────────────────────────────────────── */}
        <div
          ref={paneRef}
          className="min-w-0 scroll-mt-24 lg:sticky lg:top-20 lg:max-h-[calc(100vh-7rem)] lg:overflow-y-auto"
        >
          <ReportPane job={selectedJob} isAdmin={!!auth.isAdmin} onDownload={download} />
        </div>
      </div>
    </PageLayout>
  );
};

export default DailyBulletin;
```

Layout notes baked into the code above:

- `lg:grid-cols-[400px_1fr]` — fixed 400px work column, fluid pane, per the approved mockup.
- The pane sits after the whole work column in the DOM, so on stacked (mobile) layouts it renders below generator/list/suggestions; `selectJob` scrolls it into view (`scroll-mt-24` clears the fixed header).
- The suggestion CVE chip moved from `sm:` to `xl:` because the column is now 400px — at `lg` there is no room for it.
- The generator input group is stacked vertically (`flex-col`) since it lives in a 400px column now; `Gerar` right-aligns via `ml-auto`.
- The source host in job rows uses `hostOf` so long URLs don't dominate the card.

- [ ] **Step 2: Full static check**

Run: `npm run ci`
Expected: lint, typecheck, and build all exit 0.

- [ ] **Step 3: Commit**

```bash
git add src/pages/DailyBulletin.tsx
git commit -m "feat: report generator workstation layout"
```

---

### Task 4: Rendered QA

**Files:**
- Modify only if QA finds a defect in files from Tasks 1–3.

- [ ] **Step 1: Run the app**

Run: `npm run dev` (background). The generator page is at `http://localhost:8080/daily-bulletin` (confirm port from Vite output).

- [ ] **Step 2: Desktop QA (≥1280px viewport)**

Using Playwright (installed) or the browser, verify:

1. Two columns render; work column ≈400px; pane shows the empty state (BrandMark + "Nenhum relatório aberto") when nothing is selected.
2. With seeded history (paste into DevTools console, then reload):

```js
localStorage.setItem("ts-bulletins-v1", JSON.stringify([
  { id: "t1", url: "https://example.com/advisory", type: "vuln", title: "Exemplo RCE",
    status: "done", error: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    json: { tlp: "CLEAR", titulo: "Exemplo RCE crítico", sumario_executivo: "Resumo de teste.",
      generated_at: new Date().toISOString(), source_url: "https://example.com/advisory",
      iocs: [{ categoria: "Rede", tipo: "IPv4", valor: "203.0.113.7" }],
      mitre_ttps: [{ id: "T1190", nome: "Exploit Public-Facing Application" }] } },
  { id: "t2", url: "https://example.com/fail", type: "campaign", title: "Job com erro",
    status: "error", error: "tempo esgotado", json: null,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
]));
```

   - Click "Exemplo RCE" → opens in pane (TLP badge, type chip, date, source host, title, sections); card gets the blue selected treatment.
   - Click it again → deselects, empty state returns.
   - Error card shows "tentar de novo" (clicking while signed out shows the sign-in toast — acceptable).
   - JSON button downloads `boletim-vuln-exemplo-rce.json`.
3. Light and dark themes both look right (toggle in header).
4. No console errors.

- [ ] **Step 3: Mobile QA (375px viewport)**

1. Columns stack: generator → reports → suggestions → pane.
2. Selecting the done job scrolls to the pane below.
3. Suggestion "Gerar" buttons are visible without hover.

- [ ] **Step 4: Clean up QA state and commit any fixes**

Remove seeded state: `localStorage.removeItem("ts-bulletins-v1")` in the console. Stop the dev server. If defects were found and fixed:

```bash
git add -A src/
git commit -m "fix: report workstation QA adjustments"
```

---

## Self-Review

- **Spec coverage:** layout/grid (Task 3), left-column states incl. retry + auto-select (Task 3), ReportPane toolbar/empty state (Task 2), BoletimView meta removal (Task 1), mobile stacking + scroll (Task 3), verification (per-task `ci` + Task 4). Suggestions "always visible on touch" was already the existing behavior (`sm:` prefix) — kept.
- **Placeholder scan:** none; every code step carries complete code.
- **Type consistency:** `ReportPane({ job, isAdmin, onDownload })` and `hostOf` match between Task 2 (producer) and Task 3 (consumer); `BoletimView({ report })` unchanged.
- **Deviation from spec (intentional):** pane title prefers `json.titulo` over `job.title` (engine-provided headline beats the often-empty job title); noted in Task 2.
