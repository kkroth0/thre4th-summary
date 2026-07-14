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
                      <SelectTrigger className="flex-1 min-w-0 border-0 bg-transparent shadow-none focus:ring-0"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="vuln">{pt ? "Vulnerabilidade" : "Vulnerability"}</SelectItem>
                        <SelectItem value="campaign">{pt ? "Campanha" : "Campaign"}</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button onClick={() => { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); }} disabled={!pasteUrl.trim()} className="shrink-0 gap-2">
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
          <ReportPane job={selectedJob} onDownload={download} />
        </div>
      </div>
    </PageLayout>
  );
};

export default DailyBulletin;
