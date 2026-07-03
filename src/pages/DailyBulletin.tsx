import React, { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, Download, ShieldAlert, Loader2, FileText, Sparkles, AlertTriangle, Eye, ChevronDown, Trash2, Github, KeyRound, CheckCircle2, ArrowRight, Plus, Inbox, X, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader,
  AlertDialogFooter, AlertDialogTitle, AlertDialogDescription, AlertDialogAction,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { BoletimView } from "@/components/BoletimView";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
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

// Histórico dos boletins gerados, persistido no navegador (sobrevive a sair da
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

// Status pill styling per job state — carries the at-a-glance hierarchy.
const JOB_STATUS: Record<string, { cls: string; dot: string; pt: string; en: string }> = {
  pending: { cls: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/25", dot: "bg-amber-500", pt: "Gerando", en: "Generating" },
  done: { cls: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/25", dot: "bg-emerald-500", pt: "Pronto", en: "Ready" },
  error: { cls: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/25", dot: "bg-red-500", pt: "Erro", en: "Error" },
};

// Left-accent per severity for the suggestion rows.
const SEVERITY_ACCENT: Record<string, string> = {
  Critical: "border-l-red-500",
  High: "border-l-orange-500",
  Medium: "border-l-yellow-500",
  Low: "border-l-slate-400",
};

const DailyBulletin: React.FC = () => {
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
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
    if (!auth?.hasKey) { toast.error(pt ? "Adicione sua chave Groq antes de gerar" : "Add your Groq key before generating"); return; }
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

  // Apaga o histórico de boletins (estado + localStorage, via efeito de persistência).
  const clearHistory = () => {
    setJobs([]);
    setExpandedId(null);
    toast.success(pt ? "Histórico apagado" : "History cleared");
  };

  // Brief currently opened for the large render on the right pane.
  const selectedJob = jobs.find((j) => j.id === expandedId && j.status === "done" && j.json);

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-6xl">
        {/* Title */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <FileText className="h-7 w-7 text-primary" />
            Threat Brief
          </h1>
          <p className="text-muted-foreground mt-2 max-w-2xl">
            {pt
              ? "Cole o link de um relatório ou notícia de segurança. Ele é resumido sozinho e você baixa o JSON pronto pro seu slide."
              : "Paste a link to a security report or news post. It gets summarized on its own and you download the JSON for your slide."}
          </p>
        </div>

        <div className="flex flex-col lg:flex-row gap-6 items-start">
          {/* ── LEFT RAIL: create + suggestions ───────────────────── */}
          <aside className="w-full lg:w-[360px] lg:shrink-0 space-y-4 lg:sticky lg:top-6">
            {/* Generator — the primary action, up front */}
            <Card className="border-primary/25 bg-gradient-to-b from-primary/[0.07] to-transparent shadow-sm">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <span className="p-1.5 rounded-md bg-primary/15 text-primary"><Plus className="h-4 w-4" /></span>
                  {pt ? "Novo boletim" : "New brief"}
                </CardTitle>
                <CardDescription className="text-xs">
                  {pt ? "Cole a URL de um relatório ou notícia." : "Paste a report or news URL."}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2.5">
                {auth.hasKey ? (
                  <>
                    <Input
                      placeholder="https://…"
                      value={pasteUrl}
                      onChange={(e) => setPasteUrl(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter" && pasteUrl.trim()) { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); } }}
                    />
                    <Select value={pasteType} onValueChange={(v) => setPasteType(v as DeckType)}>
                      <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="vuln">{pt ? "Vulnerabilidade" : "Vulnerability"}</SelectItem>
                        <SelectItem value="campaign">{pt ? "Campanha" : "Campaign"}</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button className="w-full gap-2" onClick={() => { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); }} disabled={!pasteUrl.trim()}>
                      <Sparkles className="h-4 w-4" /> {pt ? "Gerar boletim" : "Generate brief"}
                    </Button>
                    <div className="flex items-center justify-between gap-2 pt-0.5 text-[11px] text-muted-foreground">
                      <span className="inline-flex items-center gap-1 min-w-0">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                        <span className="truncate">{auth.login} · {pt ? "chave ativa" : "key active"}</span>
                      </span>
                      <Link to="/settings" className="shrink-0 hover:text-foreground inline-flex items-center gap-1">
                        <KeyRound className="h-3 w-3" /> {pt ? "Gerenciar" : "Manage"}
                      </Link>
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center text-center gap-3 py-2">
                    <span className="p-2 rounded-lg bg-primary/10 text-primary"><KeyRound className="h-6 w-6" /></span>
                    <div>
                      <div className="font-medium text-sm">{pt ? "Adicione sua chave Groq" : "Add your Groq key"}</div>
                      <div className="text-xs text-muted-foreground">{pt ? "Necessária (BYOK) para gerar boletins." : "Required (BYOK) to generate briefs."}</div>
                    </div>
                    <Button asChild size="sm" className="w-full">
                      <Link to="/settings"><KeyRound className="h-4 w-4 mr-2" /> {pt ? "Ir para configurações" : "Go to settings"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Suggestions — pick and generate */}
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between gap-2">
                  <CardTitle className="text-sm">{pt ? "Sugestões do dia" : "Today's suggestions"}</CardTitle>
                  <Button variant="ghost" size="sm" className="h-7 px-2" onClick={loadSuggestions} disabled={loading} title={pt ? "Atualizar" : "Refresh"}>
                    {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {suggestions.length > 0 ? (
                  <div className="divide-y max-h-[560px] overflow-y-auto">
                    {suggestions.map((s) => (
                      <div key={s.url} className={`border-l-2 ${SEVERITY_ACCENT[s.severity] || SEVERITY_ACCENT.Low} px-3 py-2 hover:bg-muted/40 transition-colors`}>
                        <a href={s.url} target="_blank" rel="noopener noreferrer" className="block text-sm font-medium leading-snug hover:underline line-clamp-2" title={s.title}>
                          {s.title}
                        </a>
                        <div className="mt-1 flex items-center gap-1.5 flex-wrap text-[11px] text-muted-foreground">
                          <span className="font-semibold text-foreground/80">{s.severity}</span>
                          {s.kev && <span className="inline-flex items-center gap-0.5 text-red-500 font-semibold"><ShieldAlert className="h-3 w-3" />KEV</span>}
                          {s.cves?.[0] && <Badge variant="secondary" className="text-[10px] font-mono">{s.cves[0]}</Badge>}
                          <span className="tabular-nums truncate">· {s.source}</span>
                          <Button size="sm" variant="ghost" onClick={() => generate(s.url, s.suggestedType, s.title)} className="ml-auto h-6 px-2 text-primary text-[11px]">
                            <Sparkles className="h-3 w-3 mr-1" /> {pt ? "Gerar" : "Generate"}
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : loading ? (
                  <div className="p-6 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin mx-auto" /></div>
                ) : (
                  <p className="p-6 text-center text-sm text-muted-foreground">{pt ? "Nenhuma sugestão no momento." : "No suggestions right now."}</p>
                )}
              </CardContent>
            </Card>
          </aside>

          {/* ── RIGHT: your briefs ────────────────────────────────── */}
          <section className="flex-1 min-w-0 w-full space-y-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                {pt ? "Seus boletins" : "Your briefs"}
                {jobs.length > 0 && <Badge variant="secondary" className="tabular-nums">{jobs.length}</Badge>}
              </h2>
              {jobs.length > 0 && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive">
                      <Trash2 className="h-4 w-4 mr-2" /> {pt ? "Limpar" : "Clear"}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{pt ? "Limpar histórico de boletins?" : "Clear brief history?"}</AlertDialogTitle>
                      <AlertDialogDescription>
                        {pt
                          ? "Isso apaga todos os boletins desta lista (incluindo os JSON gerados) deste navegador. Não dá pra desfazer."
                          : "This removes all briefs from this list (including the generated JSON) on this browser. This can't be undone."}
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

            {/* Selected brief, rendered large */}
            {selectedJob && selectedJob.json && (
              <Card className="border-primary/30">
                <CardHeader className="pb-3 flex-row items-start justify-between gap-3 space-y-0">
                  <div className="min-w-0">
                    <CardTitle className="text-base truncate">{selectedJob.title || selectedJob.url}</CardTitle>
                    <CardDescription className="truncate text-xs">{selectedJob.type} · {selectedJob.url}</CardDescription>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Button size="sm" variant="outline" onClick={() => download(selectedJob)}><Download className="h-4 w-4 mr-2" /> JSON</Button>
                    <Button size="sm" variant="ghost" onClick={() => setExpandedId(null)} aria-label={pt ? "Fechar" : "Close"}><X className="h-4 w-4" /></Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <BoletimView report={selectedJob.json} />
                </CardContent>
              </Card>
            )}

            {/* Job list / empty state */}
            {jobs.length === 0 ? (
              <div className="rounded-xl border border-dashed p-12 text-center">
                <Inbox className="h-10 w-10 text-muted-foreground/40 mx-auto mb-3" />
                <p className="text-sm font-medium text-muted-foreground">{pt ? "Nenhum boletim ainda" : "No briefs yet"}</p>
                <p className="text-xs text-muted-foreground/80 mt-1">{pt ? "Cole uma URL ou gere a partir de uma sugestão ao lado." : "Paste a URL or generate from a suggestion on the left."}</p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {jobs.map((j) => {
                  const elapsed = Math.max(0, nowMs - new Date(j.createdAt).getTime());
                  const pidx = phaseIndex(elapsed);
                  const st = JOB_STATUS[j.status] || JOB_STATUS.pending;
                  const isSel = expandedId === j.id;
                  return (
                    <div key={j.id} className={`rounded-lg border p-3 animate-fade-in transition-colors ${isSel ? "border-primary/50 bg-primary/5" : "hover:border-primary/30"}`}>
                      <div className="flex items-center gap-3">
                        <span className={`inline-flex items-center gap-1.5 shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${st.cls}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${st.dot} ${j.status === "pending" ? "animate-pulse" : ""}`} />
                          {pt ? st.pt : st.en}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium truncate">{j.title || j.url}</div>
                          <div className="text-xs text-muted-foreground truncate">{j.type} · {j.url}</div>
                        </div>
                        {j.status === "pending" && (
                          <span className="text-xs text-muted-foreground inline-flex items-center gap-1 shrink-0 tabular-nums"><Clock className="h-3 w-3" />{Math.floor(elapsed / 1000)}s</span>
                        )}
                        {j.status === "done" && (
                          <div className="flex items-center gap-2 shrink-0">
                            <Button size="sm" variant={isSel ? "default" : "outline"} onClick={() => setExpandedId((id) => (id === j.id ? null : j.id))}>
                              {isSel
                                ? <><ChevronDown className="h-4 w-4 mr-2" /> {pt ? "Ocultar" : "Hide"}</>
                                : <><Eye className="h-4 w-4 mr-2" /> {pt ? "Ver" : "View"}</>}
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => download(j)}><Download className="h-4 w-4 mr-2" /> JSON</Button>
                          </div>
                        )}
                      </div>
                      {j.status === "error" && j.error && (
                        <div className="mt-2 text-xs text-red-500/90 flex items-start gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          <span>{j.error}</span>
                        </div>
                      )}
                      {j.status === "pending" && (
                        <div className="mt-3">
                          <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-muted">
                            <span className="absolute top-0 h-full rounded-full bg-primary animate-indeterminate" />
                          </div>
                          <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                            <Sparkles className="h-3.5 w-3.5 text-primary animate-pulse" />
                            <span>
                              {j.queuePosition && j.queuePosition > 0
                                ? (pt ? `Na fila, ${j.queuePosition} na sua frente` : `In queue, ${j.queuePosition} ahead of you`)
                                : (pt ? PHASES[pidx].pt : PHASES[pidx].en)}
                            </span>
                            <span className="ml-auto flex gap-1">
                              {PHASES.map((_, i) => (
                                <span key={i} className={`h-1.5 w-1.5 rounded-full transition-colors ${i <= pidx ? "bg-primary" : "bg-muted-foreground/30"}`} />
                              ))}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default DailyBulletin;
