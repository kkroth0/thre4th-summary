import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  RefreshCw, ShieldAlert, Loader2, Sparkles, Trash2, KeyRound,
  ArrowRight, RotateCcw, Download, SlidersHorizontal,
  AlertTriangle, ExternalLink, FileText, Plus, Search, X, ArrowLeft,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Switch } from "@/components/ui/switch";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader,
  AlertDialogFooter, AlertDialogTitle, AlertDialogDescription, AlertDialogAction,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { PageLayout } from "@/components/PageLayout";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ReportPane, hostOf } from "@/components/ReportPane";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  fetchDailySuggestions, generateBoletim, fetchJob, fetchJobList, deleteJob,
  type DailySuggestion, type BoletimJob, type DeckType, type DeckTemplate, type DeckSubtype,
  loadDeckTemplate, saveDeckTemplate, loadDeckSubtype, saveDeckSubtype,
} from "@/services/threatApi";
import { exportBoletimJSON } from "@/utils/boletimExport";
import {
  canOpenReport, filterSuggestions, filterReportLibrary, DEFAULT_SUGGESTION_PREFS, type SuggestionPrefs, canOpenJob, explainFailure, reportTitle, parseReportSources, MAX_REPORT_SOURCES } from "./dailyBulletinView";

const PREFS_KEY = "daily-suggestion-prefs";
const loadPrefs = (): SuggestionPrefs => {
  try {
    return { ...DEFAULT_SUGGESTION_PREFS, ...JSON.parse(localStorage.getItem(PREFS_KEY) || "{}") };
  } catch {
    return DEFAULT_SUGGESTION_PREFS;
  }
};

// Após esse tempo um job ainda "pending" vira erro no front (worker caiu, ou o
// backend reiniciou e perdeu o job -> 404). Evita "gerando…" eterno. Casado com
// o JOB_TTL_MS do servidor (25 min) pra não expirar antes dele numa fila cheia.
const CLIENT_TIMEOUT_MS = 25 * 60 * 1000;

// Fases estimadas pelo tempo decorrido (mapeiam o pipeline real: coleta ~10-15s,
// análise LLM ~15-30s). Não é progresso real, mas dá feedback agradável.
const PHASES = [
  { pt: "Coletando a página…", en: "Fetching the page…" },
  { pt: "Analisando com IA…", en: "Analyzing with AI…" },
  { pt: "Montando o boletim…", en: "Assembling the bulletin…" },
];
const phaseIndex = (elapsedMs: number) => (elapsedMs < 15000 ? 0 : elapsedMs < 40000 ? 1 : 2);
// Teto do worker, o mesmo que aparece na mensagem de falha ("timeout após 240s").
const JOB_TIMEOUT_S = 240;

// Minimal status: a small dot + a muted label. Colour only where it means
// something. DEN-06 da auditoria: os tons -600 mediam 3,77:1 em 12px, abaixo do
// mínimo AA de 4,5:1 — subiram para -700 no tema claro; no escuro os -400 já
// passam sobre o fundo escuro.
// something (amber = working, emerald = ready, red = failed).
const JOB_STATUS: Record<string, { dot: string; text: string; pt: string; en: string }> = {
  pending: { dot: "bg-amber-500", text: "text-amber-700 dark:text-amber-400", pt: "Gerando", en: "Generating" },
  done: { dot: "bg-emerald-500", text: "text-emerald-700 dark:text-emerald-400", pt: "Pronto", en: "Ready" },
  error: { dot: "bg-red-500", text: "text-red-700 dark:text-red-400", pt: "Erro", en: "Error" },
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
// Painel de diagnóstico da falha. Antes, clicar num item com erro abria
// "Nenhum relatório aberto" — o analista via que falhou e não descobria por quê:
// a mensagem só existia truncada na linha da lista.
const FailurePane: React.FC<{ job: BoletimJob; pt: boolean; onRetry: (job: BoletimJob) => void }> = ({ job, pt, onRetry }) => {
  const ajuda = explainFailure(job.error, pt);
  return (
    <div className="rounded-lg border border-red-500/25 bg-red-500/[0.04] p-5">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-700 dark:text-red-400" />
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold leading-snug">{reportTitle(job)}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {pt ? "Falhou" : "Failed"} {timeAgo(job.updatedAt || job.createdAt, pt)} · {hostOf(job.url) || job.url}
          </p>
        </div>
      </div>

      <p className="mt-4 text-sm font-medium">{ajuda.resumo}</p>
      <p className="mt-1 text-sm text-muted-foreground">{ajuda.causa}</p>

      <div className="mt-4 flex flex-wrap gap-2">
        <Button size="sm" onClick={() => onRetry(job)} className="gap-1.5">
          <RotateCcw className="h-3.5 w-3.5" /> {ajuda.acoes[0]}
        </Button>
        {ajuda.acoes.slice(1).map((acao) => (
          <span key={acao} className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
            {acao}
          </span>
        ))}
        <a
          href={job.url} target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1 rounded-full border border-border px-3 py-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ExternalLink className="h-3 w-3" /> {pt ? "Abrir a fonte" : "Open the source"}
        </a>
      </div>

      {/* A mensagem crua fica, inteira: é o que o analista cola no chamado. */}
      {job.error && (
        <pre className="mt-4 overflow-x-auto whitespace-pre-wrap rounded-lg border border-border bg-muted/40 p-3 font-mono text-xs text-muted-foreground">
          {job.error}
        </pre>
      )}
    </div>
  );
};

const JobListItem: React.FC<{
  job: BoletimJob;
  selected: boolean;
  picked: boolean;
  nowMs: number;
  pt: boolean;
  onSelect: (job: BoletimJob) => void;
  onPick: (id: string, picked: boolean) => void;
  onRetry: (job: BoletimJob) => void;
  onCancel: (job: BoletimJob) => void;
}> = ({ job: j, selected, picked, nowMs, pt, onSelect, onPick, onRetry, onCancel }) => {
  const st = JOB_STATUS[j.status] || JOB_STATUS.pending;
  const elapsed = Math.max(0, nowMs - new Date(j.createdAt).getTime());
  const clickable = canOpenJob(j);
  return (
    <div
      role={clickable ? "button" : undefined}
      aria-pressed={clickable ? selected : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={clickable ? () => onSelect(j) : undefined}
      onKeyDown={clickable ? (e) => { if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onSelect(j); } } : undefined}
      className={cn(
        "rounded-sm border px-3 py-3 transition-colors",
        selected ? "border-primary/40 bg-primary/5" : "border-transparent border-b-border/60",
        clickable && "cursor-pointer",
        clickable && !selected && "hover:bg-muted/40"
      )}
    >
      <div className="flex items-center gap-3">
        <span onClick={(e) => e.stopPropagation()}>
          <Checkbox
            checked={picked}
            onCheckedChange={(value) => onPick(j.id, Boolean(value))}
            aria-label={pt ? `Selecionar ${reportTitle(j)}` : `Select ${reportTitle(j)}`}
          />
        </span>
        <span className={`h-2 w-2 rounded-full shrink-0 ${st.dot} ${j.status === "pending" ? "animate-pulse" : ""}`} />
        <div className="min-w-0 flex-1">
          <div className="break-words text-sm font-medium leading-snug" title={reportTitle(j)}>{reportTitle(j)}</div>
          <div className="text-xs text-muted-foreground truncate">
            <span className={st.text}>{pt ? st.pt : st.en}</span>
            {j.status === "done" ? ` · ${timeAgo(j.updatedAt || j.createdAt, pt)}` : ""}
            {" · "}{hostOf(j.url) || j.url}
            {(j.urls?.length ?? 0) > 1 && ` · ${j.urls!.length} ${pt ? "fontes" : "sources"}`}
          </div>
        </div>
        {j.status === "pending" && (
          // EST-02: o número sozinho não diz se está perto do fim. O limite do
          // worker é 240s, então o tempo aparece contra ele.
          <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
            {Math.floor(elapsed / 1000)}s / {JOB_TIMEOUT_S}s
          </span>
        )}
      </div>
        {j.status === "done" && (
          <div className="mt-2 pl-12 text-[10px] text-muted-foreground">
            {j.type}{j.template ? ` · ${j.template === "basico" ? (pt ? "básico" : "basic") : j.template === "premium" ? "premium" : (pt ? "avançado" : "advanced")}` : ""}
            {j.subtype && j.subtype !== "auto" ? ` · ${j.subtype}` : ""}
          </div>
        )}
      {j.status === "error" && (
        <div className="mt-1.5 flex items-center gap-2 pl-12">
          {/* Resumo em uma linha; a mensagem inteira e o que fazer ficam no
              painel ao lado, que agora abre ao clicar. DEN-06: vermelho cheio
              em vez de /90, que ficava em 3,76:1. */}
          <span className="min-w-0 flex-1 truncate text-xs text-red-700 dark:text-red-400">
            {explainFailure(j.error, pt).resumo}
          </span>
          <Button
            size="sm" variant="ghost" className="h-6 px-2 text-xs text-muted-foreground hover:text-foreground shrink-0"
            onClick={(e) => { e.stopPropagation(); onRetry(j); }}
          >
            <RotateCcw className="h-3 w-3 mr-1" /> {pt ? "tentar de novo" : "retry"}
          </Button>
        </div>
      )}
      {j.status === "pending" && (
        <div className="mt-2 pl-12">
          <div className="relative h-1 w-full overflow-hidden rounded-full bg-muted">
            <span className="absolute top-0 h-full rounded-full bg-primary/70 animate-indeterminate" />
          </div>
          <div className="mt-1.5 flex items-center gap-2 text-xs text-muted-foreground">
            <span className="min-w-0 flex-1 truncate">
              {j.queuePosition && j.queuePosition > 0
                ? (pt ? `Na fila, ${j.queuePosition} na sua frente` : `In queue, ${j.queuePosition} ahead of you`)
                : (pt ? PHASES[phaseIndex(elapsed)].pt : PHASES[phaseIndex(elapsed)].en)}
            </span>
            <Button
              size="sm" variant="ghost"
              className="h-6 shrink-0 px-2 text-xs text-muted-foreground hover:text-foreground"
              onClick={(e) => { e.stopPropagation(); onCancel(j); }}
            >
              {pt ? "Cancelar" : "Cancel"}
            </Button>
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
  // Knowledge manda a fonte pra cá via ?url=… — só preenche o campo, quem
  // dispara a geração continua sendo o usuário.
  const [searchParams] = useSearchParams();
  const requestedJobId = searchParams.get("job") || "";
  const [mobileReading, setMobileReading] = useState(() => Boolean(requestedJobId));
  const [pasteUrl, setPasteUrl] = useState(() => searchParams.get("url") || "");
  const [composerOpen, setComposerOpen] = useState(() => Boolean(searchParams.get("url")));
  const [submitting, setSubmitting] = useState(false);
  const [libraryMode, setLibraryMode] = useState("reports");
  const [librarySearch, setLibrarySearch] = useState("");
  const [jobStatus, setJobStatus] = useState("all");
  const urlInputRef = useRef<HTMLTextAreaElement | null>(null);
  const sourceInput = parseReportSources(pasteUrl);
  const [deckTemplate, setDeckTemplate] = useState<DeckTemplate>(loadDeckTemplate);
  const [deckSubtype, setDeckSubtype] = useState<DeckSubtype>(loadDeckSubtype);
  const [jobs, setJobs] = useState<BoletimJob[]>([]);
  const [picked, setPicked] = useState<string[]>([]);
  const [prefs, setPrefs] = useState<SuggestionPrefs>(loadPrefs);
  const [nowMs, setNowMs] = useState(Date.now());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const paneRef = useRef<HTMLDivElement | null>(null);

  // Sessão compartilhada (GitHub + BYOK). Identidade e chave vivem em /profile;
  // aqui a gente só usa o estado pra liberar (ou barrar) o gerador.
  const { auth } = useAuth();

  // Busca uma janela maior do que cabe na tela: os cortes por severidade/KEV/
  // palavra-chave acontecem aqui, então vale ter folga pra filtrar.
  const loadSuggestions = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchDailySuggestions(prefs.hours, 40);
      setSuggestions(data.suggestions || []);
    } catch {
      toast.error(pt ? "Falha ao carregar sugestões" : "Failed to load suggestions");
    } finally {
      setLoading(false);
    }
  }, [pt, prefs.hours]);

  useEffect(() => { loadSuggestions(); }, [loadSuggestions]);

  const savePrefs = (next: Partial<SuggestionPrefs>) => {
    setPrefs((current) => {
      const merged = { ...current, ...next };
      try { localStorage.setItem(PREFS_KEY, JSON.stringify(merged)); } catch { /* sem persistência, segue */ }
      return merged;
    });
  };

  const shownSuggestions = useMemo(
    () => filterReportLibrary(filterSuggestions(suggestions, prefs), librarySearch),
    [suggestions, prefs, librarySearch],
  );
  const visibleJobs = useMemo(() => filterReportLibrary(jobs, librarySearch)
    .filter((job) => jobStatus === "all" || job.status === jobStatus), [jobs, librarySearch, jobStatus]);
  const openComposer = () => { setComposerOpen(true); requestAnimationFrame(() => urlInputRef.current?.focus()); };
  const addSource = (url: string) => {
    const urls = [...new Set([...sourceInput.urls, url])];
    if (urls.length > MAX_REPORT_SOURCES) {
      toast.error(pt ? "Limite de 5 fontes por relatório." : "Limit of 5 sources per report.");
      return;
    }
    setPasteUrl(urls.join("\n"));
    openComposer();
  };

  // A lista vem do servidor — antes vivia só no localStorage, então o histórico
  // era por navegador e sumia. Chega sem o JSON do boletim; o corpo é buscado
  // sob demanda ao abrir um relatório.
  useEffect(() => {
    if (!auth?.authenticated) return;
    fetchJobList()
      .then(async (list) => {
        if (requestedJobId && list.some((job) => job.id === requestedJobId && job.hasReport)) {
          const full = await fetchJob(requestedJobId);
          list = list.map((job) => job.id === requestedJobId ? { ...job, json: full.json } : job);
          setSelectedId(requestedJobId);
        }
        setJobs(list);
      })
      .catch(() => toast.error(pt ? "Falha ao carregar seus relatórios" : "Failed to load your reports"));
  }, [auth?.authenticated, pt, requestedJobId]);

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
      // 10s, não 3s: a geração leva ~2 min, e a 3s o poll estoura o rate limit
      // do próprio site (150 req / 15 min) em 7min30 de espera — daí em diante
      // fetchJob só devolve 429, a tela congela e o boletim PARECE travado.
      pollRef.current = setInterval(tick, 10000);
      return () => { if (pollRef.current) clearInterval(pollRef.current); };
    }
  }, [jobs]);

  // Ticker de 1s só enquanto há job gerando — alimenta a animação de fases.
  useEffect(() => {
    if (!jobs.some((j) => j.status === "pending")) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [jobs]);

  const generate = async (
    source: string | string[], type: DeckType, title: string, template: DeckTemplate = deckTemplate,
    subtype: DeckSubtype = deckSubtype,
  ) => {
    if (!auth?.authenticated) { toast.error(pt ? "Entre com o GitHub para gerar" : "Sign in with GitHub to generate"); return false; }
    const { urls, error } = parseReportSources(Array.isArray(source) ? source.join("\n") : source);
    if (error) {
      toast.error(error === "limit"
        ? (pt ? `Use até ${MAX_REPORT_SOURCES} fontes por relatório.` : `Use up to ${MAX_REPORT_SOURCES} sources per report.`)
        : (pt ? "Informe links HTTP ou HTTPS válidos, um por linha." : "Enter valid HTTP or HTTPS links, one per line."));
      return false;
    }
    const url = urls[0];
    try {
      const { id } = await generateBoletim(urls, type, title, template, subtype);
      const now = new Date().toISOString();
      setJobs((prev) => [
        { id, url, urls, type, template, subtype, title, status: "pending", json: null, error: null, createdAt: now, updatedAt: now },
        ...prev,
      ]);
      setLibraryMode("reports");
      setJobStatus("all");
      setLibrarySearch("");
      toast.success(pt ? "Geração iniciada. Acompanhe na biblioteca." : "Generation started. Follow it in the library.");
      return true;
    } catch (e) {
      toast.error((e as Error).message || (pt ? "Falha ao iniciar" : "Failed to start"));
      return false;
    }
  };
  const submitSource = async () => {
    if (submitting) return;
    setSubmitting(true);
    try {
      if (await generate(pasteUrl.trim(), "auto", "")) { setPasteUrl(""); setComposerOpen(false); }
    } finally { setSubmitting(false); }
  };

  const togglePick = (id: string, on: boolean) =>
    setPicked((prev) => (on ? [...new Set([...prev, id])] : prev.filter((value) => value !== id)));

  // Baixa o JSON de cada selecionado. A listagem chega sem o boletim, então o
  // que ainda não foi aberto é buscado antes de virar arquivo.
  const downloadPicked = async () => {
    const targets = jobs.filter((j) => picked.includes(j.id) && canOpenReport(j));
    if (!targets.length) { toast.error(pt ? "Nenhum relatório pronto selecionado" : "No finished report selected"); return; }
    let falhas = 0;
    for (const job of targets) {
      try {
        const full = job.json ? job : { ...job, json: (await fetchJob(job.id)).json };
        exportBoletimJSON(full);
      } catch { falhas += 1; }
    }
    if (falhas) toast.error(pt ? `Falha ao baixar ${falhas} relatório(s)` : `Failed to download ${falhas} report(s)`);
    else toast.success(pt ? `${targets.length} relatório(s) baixado(s)` : `${targets.length} report(s) downloaded`);
  };

  // Apaga no servidor. Antes só dava pra limpar tudo; agora o que some é o que
  // foi marcado.
  const deletePicked = async () => {
    const alvo = jobs.filter((j) => picked.includes(j.id));
    setJobs((prev) => prev.filter((j) => !picked.includes(j.id)));
    if (selectedId && picked.includes(selectedId)) setSelectedId(null);
    setPicked([]);
    const erros = (await Promise.all(alvo.map((j) => deleteJob(j.id).then(() => 0).catch(() => 1))))
      .reduce((a: number, b) => a + b, 0);
    if (erros) {
      setJobs(await fetchJobList().catch(() => alvo));
      toast.error(pt ? `Falha ao apagar ${erros} relatório(s)` : `Failed to delete ${erros} report(s)`);
    } else {
      toast.success(pt ? `${alvo.length} relatório(s) apagado(s)` : `${alvo.length} report(s) deleted`);
    }
  };

  // Abre um relatório no painel. A lista vem sem o boletim, então na
  // primeira abertura busca o JSON e guarda no estado. Em telas menores
  // (colunas empilhadas) o painel fica abaixo da lista, então rola até ele.
  const selectJob = async (j: BoletimJob) => {
    const next = j.id;
    setMobileReading(true);
    setSelectedId(next);
    if (next && !j.json && j.hasReport) {
      try {
        const full = await fetchJob(j.id);
        if (!full.json) throw new Error("Report body unavailable");
        setJobs((prev) => prev.map((x) => (x.id === j.id ? { ...x, json: full.json } : x)));
      } catch {
        setSelectedId((current) => current === j.id ? null : current);
        toast.error(pt ? "Falha ao abrir o relatório" : "Failed to open the report");
      }
    }
    if (next && typeof window !== "undefined" && window.innerWidth < 1024) {
      setTimeout(() => paneRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    }
  };

  const retryJob = (j: BoletimJob) => {
    generate(j.urls?.length ? j.urls : j.url, j.type, j.title, j.template ?? deckTemplate, j.subtype ?? deckSubtype);
  };

  // EST-02: a geração leva minutos e não tinha como desistir. Apagar o job é o
  // que o servidor já sabe fazer; o worker que estiver rodando termina sozinho e
  // o resultado é descartado por não ter mais dono na lista.
  const cancelJob = async (j: BoletimJob) => {
    setJobs((current) => current.filter((job) => job.id !== j.id));
    if (selectedId === j.id) setSelectedId("");
    try {
      await deleteJob(j.id);
      toast.success(pt ? "Geração cancelada" : "Generation cancelled");
    } catch {
      toast.error(pt ? "Falha ao cancelar" : "Failed to cancel");
    }
  };

  // Report currently opened on the right pane.
  const selectedJob = jobs.find((j) => j.id === selectedId && j.status === "done" && j.json) || null;
  // O item que falhou não tem relatório para o ReportPane, mas tem diagnóstico.
  const selectedFailure = jobs.find((j) => j.id === selectedId && j.status === "error") || null;

  return (
    <PageLayout width="max-w-[1600px]">
      <PageHeader
        title={pt ? "Relatórios de inteligência" : "Intelligence reports"}
        subtitle={pt ? "Transforme fontes em análises e mantenha sua biblioteca de inteligência." : "Turn sources into analysis and maintain your intelligence library."}
        actions={<div className="flex items-center gap-3"><span className="hidden text-xs text-muted-foreground sm:inline">{jobs.filter((job) => job.status === "done").length} {pt ? "prontos" : "ready"}</span><Button size="sm" onClick={openComposer} aria-expanded={composerOpen} aria-controls="report-composer" className="gap-2"><Plus className="h-4 w-4" />{pt ? "Novo relatório" : "New report"}</Button></div>}
      />

      <nav aria-label={pt ? 'Tipos de relatório' : 'Report types'} className="mb-5 flex gap-2"><Button variant="secondary" size="sm">{pt ? 'Relatórios por fonte' : 'Source reports'}</Button><Button asChild variant="outline" size="sm"><Link to="/relatorios?view=weekly">{pt ? 'Relatório semanal' : 'Weekly report'}</Link></Button></nav>

      {(composerOpen || !auth.authenticated) && <section id="report-composer" className="mb-5 rounded-md border bg-card p-4">
        {auth.authenticated ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between"><h2 className="text-sm font-semibold">{pt ? "Reunir fontes para o relatório" : "Gather report sources"}</h2><Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setComposerOpen(false)} aria-label={pt ? "Fechar criação" : "Close composer"}><X className="h-4 w-4" /></Button></div>
            <div
              data-testid="report-generator-command-bar"
              className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_auto]"
            >
              <Textarea
                ref={urlInputRef}
                aria-label={pt ? "Links das fontes, um por linha" : "Source links, one per line"}
                aria-describedby="report-sources-help"
                aria-invalid={Boolean(pasteUrl.trim() && sourceInput.error)}
                placeholder={pt
                  ? "Cole até 5 links de notícias, advisories ou pesquisas, um por linha"
                  : "Paste up to 5 news, advisory or research links, one per line"}
                value={pasteUrl}
                onChange={(e) => setPasteUrl(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && pasteUrl.trim()) { e.preventDefault(); void submitSource(); } }}
                rows={4}
                className="min-w-0 bg-background text-sm sm:col-span-3"
              />
              <p id="report-sources-help" className="text-xs text-muted-foreground sm:col-span-3" role="status">
                {sourceInput.error && pasteUrl.trim()
                  ? (sourceInput.error === "limit"
                    ? (pt ? "Limite de 5 fontes por relatório." : "Limit of 5 sources per report.")
                    : (pt ? "Revise os links: use HTTP ou HTTPS, um por linha." : "Check the links: use HTTP or HTTPS, one per line."))
                  : (pt ? `${sourceInput.urls.length}/5 fontes. A IA combina os insumos em um único relatório.` : `${sourceInput.urls.length}/5 sources. AI combines the inputs into one report.`)}
              </p>
              {/* Tipo (vulnerabilidade/campanha) não tem seletor PRÓPRIO: o motor
                  classifica sozinho por padrão (mesma heurística do CLI), e um
                  subtipo concreto do seletor abaixo já implica o tipo (phishing é
                  sempre campanha, cve_unica é sempre vulnerabilidade) -- não faz
                  sentido escolher os dois separado quando um decide o outro. */}
              <div className="space-y-1.5"><span className="block text-xs text-muted-foreground">{pt ? "Tipo de análise" : "Analysis type"}</span>
              <Select
                value={deckSubtype}
                onValueChange={(v) => { setDeckSubtype(v as DeckSubtype); saveDeckSubtype(v as DeckSubtype); }}
              >
                <SelectTrigger
                  data-testid="report-generator-subtype-trigger"
                  aria-label={pt ? "Subtipo da ameaça" : "Threat subtype"}
                  title={pt ? "Escolha o subtipo (ou deixe automático)" : "Choose the subtype (or leave it automatic)"}
                  className="h-9 w-full bg-background text-xs"
                >
                  <span className="truncate">
                    {{
                      auto: pt ? "Automático" : "Automatic",
                      malware: "Malware",
                      phishing: "Phishing",
                      ransomware: "Ransomware",
                      cve_unica: pt ? "CVE única" : "Single CVE",
                      cve_varias: pt ? "Várias CVEs" : "Multi-CVE",
                    }[deckSubtype]}
                  </span>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">{pt ? "Automático (padrão)" : "Automatic (default)"}</SelectItem>
                  <SelectItem value="malware">Malware/Infostealer</SelectItem>
                  <SelectItem value="phishing">Phishing</SelectItem>
                  <SelectItem value="ransomware">Ransomware/APT</SelectItem>
                  <SelectItem value="cve_unica">{pt ? "Vulnerabilidade (CVE única)" : "Vulnerability (single CVE)"}</SelectItem>
                  <SelectItem value="cve_varias">{pt ? "Vulnerabilidade (várias CVEs)" : "Vulnerability (multiple CVEs)"}</SelectItem>
                </SelectContent>
              </Select>
              </div>
              {/* Rótulo sempre visível: o seletor é a única pista de que dá pra
                  trocar o design do deck, e o aria-label só ajuda quem usa leitor
                  de tela. Sem isso, "Avançado"/"Básico"/"Premium" sozinho não diz
                  a que se refere até o analista clicar. */}
              <div className="space-y-1.5"><span className="block text-xs text-muted-foreground">{pt ? "Formato do relatório" : "Report format"}</span>
              <Select
                value={deckTemplate}
                onValueChange={(v) => { setDeckTemplate(v as DeckTemplate); saveDeckTemplate(v as DeckTemplate); }}
              >
                <SelectTrigger
                  data-testid="report-generator-template-trigger"
                  aria-label={pt ? "Template do deck" : "Deck template"}
                  title={pt ? "Selecione o template do deck" : "Select the deck template"}
                  className="h-9 w-full bg-background text-xs"
                >
                  <span className="truncate">
                    {deckTemplate === "avancado"
                      ? (pt ? "Avançado" : "Advanced")
                      : deckTemplate === "premium"
                        ? "Premium"
                        : (pt ? "Básico" : "Basic")}
                  </span>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="avancado">{pt ? "Template Avançado" : "Advanced template"}</SelectItem>
                  <SelectItem value="basico">{pt ? "Template Básico (V2)" : "Basic template (V2)"}</SelectItem>
                  <SelectItem value="premium">{pt ? "Template Premium (por subtipo)" : "Premium template (per subtype)"}</SelectItem>
                </SelectContent>
              </Select>
              </div>
              <Button onClick={() => void submitSource()} disabled={submitting || Boolean(sourceInput.error)} className="h-9 gap-2 px-4">
                {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />} {pt ? "Gerar relatório" : "Generate report"}
              </Button>
            </div>
            {/* O botão fica desabilitado sem URL, e a linha dizia "pronto para
                gerar" — dois sinais opostos ao mesmo tempo. Agora ela diz o que
                falta. DEN-06: o cinza de rótulo sobe de text-muted-foreground
                para um tom que passa 4,5:1. */}
            <div data-testid="report-generator-status-row" className="flex items-center gap-1.5 px-1 text-xs text-slate-600 dark:text-slate-300">
              <span>{pt ? "A geração aparece na biblioteca. Você pode continuar lendo enquanto aguarda." : "Generation appears in the library. You can keep reading while you wait."}</span>
              {/* Leva a origem, para Configurações poder oferecer a volta (FLX-06). */}
              <Link to="/settings?from=/relatorios" className="ml-auto shrink-0 hover:text-foreground">{pt ? "Configurações" : "Settings"}</Link>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-4 rounded-lg bg-muted/40 p-5">
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
      </section>}

      <div className="grid gap-4 lg:grid-cols-[340px_minmax(0,1fr)] lg:items-start">
        {/* ── work column ───────────────────────────────────────────── */}
        <Tabs value={libraryMode} onValueChange={setLibraryMode} className={cn("min-w-0 rounded-md border bg-card lg:sticky lg:top-20", mobileReading && "hidden lg:block")}>
          <div className="space-y-3 border-b p-3">
            <TabsList className="grid w-full grid-cols-2"><TabsTrigger value="reports" className="gap-2">{pt ? "Biblioteca" : "Library"}<span className="text-[10px] tabular-nums text-muted-foreground">{jobs.length}</span></TabsTrigger><TabsTrigger value="suggestions" className="gap-2">{pt ? "Sugestões" : "Suggestions"}<span className="text-[10px] tabular-nums text-muted-foreground">{suggestions.length}</span></TabsTrigger></TabsList>
            <div className="relative"><Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" /><Input value={librarySearch} onChange={(event) => setLibrarySearch(event.target.value)} aria-label={pt ? "Buscar na biblioteca e sugestões" : "Search library and suggestions"} placeholder={pt ? "Buscar título, fonte ou CVE" : "Search title, source or CVE"} className="h-9 bg-background pl-8 text-xs" /></div>
          </div>
          <TabsContent value="reports" className="mt-0">
            <div className="flex items-center gap-3 border-b px-3 py-2"><span className="text-xs text-muted-foreground">{visibleJobs.length} {pt ? "relatórios" : "reports"}</span><select aria-label={pt ? "Status do relatório" : "Report status"} value={jobStatus} onChange={(event) => setJobStatus(event.target.value)} className="ml-auto rounded-sm border bg-background px-2 py-1 text-xs"><option value="all">{pt ? "Todos os status" : "All statuses"}</option><option value="done">{pt ? "Prontos" : "Ready"}</option><option value="pending">{pt ? "Em geração" : "Generating"}</option><option value="error">{pt ? "Com erro" : "Failed"}</option></select></div>

            {jobs.length > 0 && (
              <div className="mb-1.5 flex items-center gap-2 rounded-lg bg-muted/40 px-3 py-1.5">
                <Checkbox
                  checked={visibleJobs.length > 0 && visibleJobs.every((job) => picked.includes(job.id))}
                  disabled={!visibleJobs.length}
                  onCheckedChange={(value) => setPicked((current) => value ? [...new Set([...current, ...visibleJobs.map((job) => job.id)])] : current.filter((id) => !visibleJobs.some((job) => job.id === id)))}
                  aria-label={pt ? "Selecionar relatórios visíveis" : "Select visible reports"}
                />
                {/* DEN-06: text-muted-foreground mede 4,35:1 em 12px, abaixo
                    do mínimo AA. Mesmo tom da linha de status acima. */}
                <span className="text-xs text-slate-600 dark:text-slate-300">
                  {picked.length
                    ? (pt ? `${picked.length} selecionado(s)` : `${picked.length} selected`)
                    : (pt ? "Selecionar" : "Select")}
                </span>
                <div className="ml-auto flex items-center gap-1">
                  <Button
                    variant="ghost" size="sm" disabled={!picked.length}
                    className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => void downloadPicked()}
                  >
                    <Download className="mr-1.5 h-3.5 w-3.5" /> JSON
                  </Button>
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button
                        variant="ghost" size="sm" disabled={!picked.length}
                        className="h-7 px-2 text-xs text-muted-foreground hover:text-destructive"
                      >
                        <Trash2 className="mr-1.5 h-3.5 w-3.5" /> {pt ? "Apagar" : "Delete"}
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>
                          {pt ? `Apagar ${picked.length} relatorio(s)?` : `Delete ${picked.length} report(s)?`}
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                          {pt
                            ? "Some do servidor junto com o JSON gerado. Não dá pra desfazer."
                            : "They go from the server along with the generated JSON. This can't be undone."}
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>{pt ? "Cancelar" : "Cancel"}</AlertDialogCancel>
                        <AlertDialogAction onClick={() => void deletePicked()}>{pt ? "Apagar" : "Delete"}</AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </div>
            )}

            <div className="max-h-[480px] overflow-y-auto p-2 lg:max-h-[calc(100dvh-20rem)]">
            {visibleJobs.length === 0 ? (
              <EmptyState
                icon={FileText}
                bare
                title={jobs.length ? (pt ? "Nenhum resultado" : "No results") : (pt ? "Nenhum relatório ainda" : "No reports yet")}
                description={pt
                  ? "Use Novo relatório ou escolha uma sugestão. Ajuste a busca para encontrar análises salvas."
                  : "Use New report or choose a suggestion. Adjust search to find saved analysis."}
              />
            ) : (
              <div className="space-y-1.5">
                {visibleJobs.map((j) => (
                  <JobListItem
                    key={j.id}
                    job={j}
                    selected={selectedId === j.id}
                    picked={picked.includes(j.id)}
                    nowMs={nowMs}
                    pt={pt}
                    onSelect={selectJob}
                    onPick={togglePick}
                    onRetry={retryJob}
                    onCancel={cancelJob}
                  />
                ))}
              </div>
            )}
            </div>
          </TabsContent>

          {/* Suggestions — quiet hairline list, action on hover */}
          <TabsContent value="suggestions" className="mt-0">
            <div className="flex items-center justify-between border-b px-3 py-2">
              <h2 className="text-xs text-muted-foreground">
                {shownSuggestions.length} {pt ? "fontes disponíveis" : "available sources"}
              </h2>
              <div className="flex items-center gap-1">
                {/* Personalização do feed: janela no servidor, o resto filtra na
                    tela. Fica no navegador — é preferência, não configuração. */}
                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground" aria-label={pt ? "Filtrar sugestões" : "Filter suggestions"} title={pt ? "Filtrar sugestões" : "Filter suggestions"}>
                      <SlidersHorizontal className="h-3.5 w-3.5" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent align="end" className="w-72 space-y-4">
                    <div className="space-y-1.5">
                      <Label className="text-xs">{pt ? "Janela" : "Window"}</Label>
                      <Select value={String(prefs.hours)} onValueChange={(value) => savePrefs({ hours: Number(value) })}>
                        <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="24">{pt ? "Últimas 24 h" : "Last 24 h"}</SelectItem>
                          <SelectItem value="36">{pt ? "Últimas 36 h" : "Last 36 h"}</SelectItem>
                          <SelectItem value="72">{pt ? "Últimos 3 dias" : "Last 3 days"}</SelectItem>
                          <SelectItem value="168">{pt ? "Última semana" : "Last week"}</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">{pt ? "Severidade mínima" : "Minimum severity"}</Label>
                      <Select value={prefs.minSeverity} onValueChange={(value) => savePrefs({ minSeverity: value as SuggestionPrefs["minSeverity"] })}>
                        <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">{pt ? "Qualquer" : "Any"}</SelectItem>
                          <SelectItem value="Medium">Medium</SelectItem>
                          <SelectItem value="High">High</SelectItem>
                          <SelectItem value="Critical">Critical</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <Label htmlFor="sugestoes-kev" className="text-xs">{pt ? "Só CISA KEV" : "CISA KEV only"}</Label>
                      <Switch id="sugestoes-kev" checked={prefs.kevOnly} onCheckedChange={(value) => savePrefs({ kevOnly: value })} />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="sugestoes-kw" className="text-xs">{pt ? "Palavras-chave" : "Keywords"}</Label>
                      <Input
                        id="sugestoes-kw"
                        value={prefs.keywords}
                        onChange={(e) => savePrefs({ keywords: e.target.value })}
                        placeholder={pt ? "fortinet, sap, ransomware" : "fortinet, sap, ransomware"}
                        className="h-9"
                      />
                      <p className="text-[11px] text-muted-foreground">
                        {pt ? "Separadas por vírgula. Vazio mostra tudo." : "Comma separated. Empty shows everything."}
                      </p>
                    </div>
                    <Button variant="ghost" size="sm" className="h-7 w-full text-xs" onClick={() => savePrefs(DEFAULT_SUGGESTION_PREFS)}>
                      {pt ? "Restaurar padrão" : "Reset to default"}
                    </Button>
                  </PopoverContent>
                </Popover>
                <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground" onClick={loadSuggestions} disabled={loading} aria-label={pt ? "Atualizar sugestões" : "Refresh suggestions"} title={pt ? "Atualizar" : "Refresh"}>
                  {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                </Button>
              </div>
            </div>
            <div className="max-h-[480px] overflow-y-auto p-2 lg:max-h-[calc(100dvh-16rem)]">
            {shownSuggestions.length > 0 ? (
              <div className="divide-y divide-border/60">
                {shownSuggestions.map((s) => (
                  <div key={s.url} className="space-y-2 px-2 py-3">
                    <div className="flex items-start gap-2">
                    <span className={`h-2 w-2 rounded-full shrink-0 ${SEV_DOT[s.severity] || SEV_DOT.Low}`} title={s.severity} />
                    <a href={s.url} target="_blank" rel="noopener noreferrer" className="line-clamp-3 min-w-0 flex-1 text-sm font-medium leading-snug hover:underline" title={s.title}>
                      {s.title}
                    </a>
                    {s.kev && <ShieldAlert className="h-3.5 w-3.5 text-red-500 shrink-0" aria-label="CISA KEV" />}
                    </div><div className="pl-4 text-[11px] text-muted-foreground">{hostOf(s.url)}{s.cves?.[0] && <span className="ml-2 font-mono">{s.cves[0]}</span>}</div>
                    {/* subtype "auto" explícito: suggestedType já vem resolvido pelo
                        próprio servidor, e herdar o subtipo manual da barra (se houver
                        um concreto) forçaria um tipo que pode contradizer suggestedType. */}
                    <Button size="sm" variant="ghost" disabled={!auth.authenticated} onClick={() => addSource(s.url)} className="ml-4 h-7 gap-1.5 px-2 text-xs">
                      <Plus className="h-3 w-3" /> {pt ? "Adicionar ao relatório" : "Add to report"}
                    </Button>
                    <Button size="sm" variant="outline" disabled={!auth.authenticated} onClick={() => generate(s.url, s.suggestedType, s.title, deckTemplate, "auto")} className="h-7 gap-1.5 px-2 text-xs">
                      <FileText className="h-3 w-3" /> {pt ? "Gerar relatório" : "Generate report"}
                    </Button>
                  </div>
                ))}
              </div>
            ) : loading ? (
              <div className="py-10 text-center"><Loader2 className="h-4 w-4 animate-spin mx-auto text-muted-foreground" /></div>
            ) : (
              <EmptyState
                bare
                title={suggestions.length
                  ? (pt ? "Nenhuma sugestão passa pelos filtros" : "No suggestion matches your filters")
                  : (pt ? "Nenhuma sugestão no momento" : "No suggestions right now")}
                description={suggestions.length
                  ? (pt ? "Afrouxe a severidade mínima ou as fontes nas preferências de sugestão." : "Loosen the minimum severity or the sources in the suggestion preferences.")
                  : (pt ? "As sugestões vêm da coleta de notícias. Volte depois da próxima rodada." : "Suggestions come from the news collection. Come back after the next round.")}
              />
            )}
            </div>
          </TabsContent>
        </Tabs>

        {/* ── report pane ───────────────────────────────────────────── */}
        <div
          ref={paneRef}
          className={cn("min-w-0 scroll-mt-24 lg:sticky lg:top-20 lg:max-h-[calc(100dvh-7rem)] lg:overflow-y-auto", !mobileReading && "hidden lg:block")}
        >
          <Button variant="ghost" size="sm" className="mb-3 gap-2 px-0 lg:hidden" onClick={() => setMobileReading(false)}><ArrowLeft className="h-3.5 w-3.5" />{pt ? "Voltar à biblioteca" : "Back to library"}</Button>
          {selectedFailure ? (
            <FailurePane job={selectedFailure} pt={pt} onRetry={retryJob} />
          ) : selectedId && !selectedJob ? (
            <div role="status" className="flex min-h-[420px] items-center justify-center gap-2 rounded-md border bg-card text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />{pt ? "Abrindo relatório…" : "Opening report…"}</div>
          ) : (
            <ReportPane job={selectedJob} onCreate={openComposer} />
          )}
        </div>
      </div>
    </PageLayout>
  );
};

export default DailyBulletin;
