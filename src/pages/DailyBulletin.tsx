import React, { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, Download, ShieldAlert, Loader2, Sparkles, Eye, ChevronDown, Trash2, KeyRound, CheckCircle2, ArrowRight } from "lucide-react";
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
import { BoletimView } from "@/components/BoletimView";
import { PostEditor } from "@/components/PostEditor";
import { boletimToDraft } from "@/services/boletimMarkdown";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
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
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

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

  // Poll dos jobs não-terminais a cada 3s.
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
    if (!auth?.hasKey) { toast.error(pt ? "Adicione sua chave OpenRouter antes de gerar" : "Add your OpenRouter key before generating"); return; }
    if (!/^https?:\/\//i.test(url)) { toast.error(pt ? "URL inválida" : "Invalid URL"); return; }
    try {
      const { id } = await generateBoletim(url, type, title);
      const now = new Date().toISOString();
      setJobs((prev) => [
        { id, url, type, title, status: "pending", json: null, error: null, createdAt: now, updatedAt: now },
        ...prev,
      ]);
      toast.success(pt ? "Começou. O JSON vai aparecer aqui." : "Started. The JSON will show up here.");
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
    setExpandedId(null);
    toast.success(pt ? "Histórico apagado" : "History cleared");
  };

  // Report currently opened for the large render on the right pane.
  const selectedJob = jobs.find((j) => j.id === expandedId && j.status === "done" && j.json);

  return (
    <PageLayout width="max-w-3xl">
        <PageHeader
          title={pt ? "Gerador de Relatorios" : "Report Generator"}
          subtitle={pt
            ? "Cole o link de um relatório ou notícia de segurança. Ele é resumido sozinho e você baixa o JSON pronto pro seu slide."
            : "Paste a link to a security report or news post. It gets summarized on its own and you download the JSON for your slide."}
        />

        {/* Generator — one calm input row, no card chrome */}
        <section className="mb-12">
          {auth.hasKey ? (
            <div className="space-y-3">
              <div className="flex flex-col sm:flex-row gap-2 rounded-xl bg-muted/40 p-2">
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
                  <Button onClick={() => { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); }} disabled={!pasteUrl.trim()} className="gap-2">
                    <Sparkles className="h-4 w-4" /> {pt ? "Gerar" : "Generate"}
                  </Button>
                </div>
              </div>
              <div className="flex items-center gap-1.5 px-1 text-xs text-muted-foreground">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                <span className="truncate">{auth.login} · {pt ? "chave OpenRouter ativa" : "OpenRouter key active"}</span>
                <Link to="/settings" className="ml-auto shrink-0 hover:text-foreground">{pt ? "Gerenciar" : "Manage"}</Link>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-4 rounded-xl bg-muted/40 p-5">
              <KeyRound className="h-5 w-5 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">{pt ? "Adicione sua chave OpenRouter" : "Add your OpenRouter key"}</div>
                <div className="text-xs text-muted-foreground">{pt ? "Necessária (BYOK) para gerar relatórios." : "Required (BYOK) to generate reports."}</div>
              </div>
              <Button asChild variant="outline" size="sm" className="shrink-0">
                <Link to="/settings">{pt ? "Configurações" : "Settings"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
              </Button>
            </div>
          )}
        </section>

        {/* Your reports — hairline list, no boxes */}
        <section className="mb-12">
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
            <div className="divide-y divide-border/60">
              {jobs.map((j) => {
                const elapsed = Math.max(0, nowMs - new Date(j.createdAt).getTime());
                const pidx = phaseIndex(elapsed);
                const st = JOB_STATUS[j.status] || JOB_STATUS.pending;
                const isSel = expandedId === j.id;
                return (
                  <div key={j.id} className="py-3 animate-fade-in">
                    <div className="flex items-center gap-3">
                      <span className={`h-2 w-2 rounded-full shrink-0 ${st.dot} ${j.status === "pending" ? "animate-pulse" : ""}`} />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium truncate">{j.title || j.url}</div>
                        <div className="text-xs text-muted-foreground truncate">
                          <span className={st.text}>{pt ? st.pt : st.en}</span> · {j.type} · {j.url}
                        </div>
                      </div>
                      {j.status === "pending" && (
                        <span className="text-xs text-muted-foreground shrink-0 tabular-nums">{Math.floor(elapsed / 1000)}s</span>
                      )}
                      {j.status === "done" && (
                        <div className="flex items-center gap-1 shrink-0">
                          <Button size="sm" variant="ghost" className="h-8 px-2 text-muted-foreground hover:text-foreground" onClick={() => setExpandedId((id) => (id === j.id ? null : j.id))} title={isSel ? (pt ? "Ocultar" : "Hide") : (pt ? "Ver" : "View")}>
                            {isSel ? <ChevronDown className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </Button>
                          <Button size="sm" variant="ghost" className="h-8 px-2 text-muted-foreground hover:text-foreground" onClick={() => download(j)} title="JSON">
                            <Download className="h-4 w-4" />
                          </Button>
                        </div>
                      )}
                    </div>
                    {j.status === "error" && j.error && (
                      <p className="mt-1.5 pl-5 text-xs text-red-500/90">{j.error}</p>
                    )}
                    {j.status === "pending" && (
                      <div className="mt-2 pl-5">
                        <div className="relative h-1 w-full overflow-hidden rounded-full bg-muted">
                          <span className="absolute top-0 h-full rounded-full bg-primary/70 animate-indeterminate" />
                        </div>
                        <div className="mt-1.5 text-xs text-muted-foreground">
                          {j.queuePosition && j.queuePosition > 0
                            ? (pt ? `Na fila, ${j.queuePosition} na sua frente` : `In queue, ${j.queuePosition} ahead of you`)
                            : (pt ? PHASES[pidx].pt : PHASES[pidx].en)}
                        </div>
                      </div>
                    )}
                    {isSel && selectedJob && selectedJob.id === j.id && selectedJob.json && (
                      <div className="mt-3 pl-5">
                        {auth.isAdmin && (
                          <div className="mb-3">
                            <PostEditor
                              key={selectedJob.id}
                              initial={boletimToDraft(selectedJob.json)}
                              trigger={
                                <Button variant="outline" size="sm" className="gap-1.5">
                                  <Sparkles className="h-4 w-4" />
                                  {pt ? "Salvar como rascunho de Advisory" : "Save as Advisory draft"}
                                </Button>
                              }
                              onSaved={() => toast.success(pt ? "Rascunho salvo em Advisories" : "Draft saved to Advisories")}
                            />
                          </div>
                        )}
                        <BoletimView report={selectedJob.json} />
                      </div>
                    )}
                  </div>
                );
              })}
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
                  {s.cves?.[0] && <span className="hidden sm:inline text-[11px] font-mono text-muted-foreground shrink-0">{s.cves[0]}</span>}
                  <span className="hidden md:inline text-xs text-muted-foreground shrink-0 tabular-nums">{s.source}</span>
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
    </PageLayout>
  );
};

export default DailyBulletin;
