import React, { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, Download, ShieldAlert, Loader2, FileText, Sparkles, AlertTriangle, Eye, ChevronDown, Trash2, Github, KeyRound, CheckCircle2, ArrowRight } from "lucide-react";
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

const SEVERITY_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-slate-400",
};

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
      toast.success(pt ? "Geração iniciada — aguarde o JSON" : "Generation started — wait for the JSON");
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

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-5xl">
        <div className="mb-6">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <FileText className="h-7 w-7 text-primary" />
            Threat Brief
          </h1>
          <p className="text-muted-foreground mt-2">
            {pt
              ? "Transforme qualquer relatório, advisory ou notícia em um brief de inteligência estruturado. Cole a URL — a análise roda automaticamente e você baixa o JSON pronto para o slide oficial."
              : "Turn any report, advisory or news item into a structured intelligence brief. Paste a URL — the analysis runs automatically and you download a ready-to-render JSON for the official deck."}
          </p>
        </div>

        {/* Gate da chave Groq (a sessão já é garantida pelo PremiumRoute).
            A chave é gerida em /settings. */}
        {!auth.hasKey ? (
          <Card className="mb-6">
            <CardContent className="p-6 flex flex-col items-center text-center gap-3">
              <KeyRound className="h-8 w-8 text-primary" />
              <div>
                <div className="font-medium">{pt ? "Adicione sua chave Groq" : "Add your Groq key"}</div>
                <div className="text-sm text-muted-foreground">{pt ? "Você precisa de uma chave Groq (BYOK) nas configurações para gerar boletins." : "You need a Groq key (BYOK) in settings to generate bulletins."}</div>
              </div>
              <Button asChild>
                <Link to="/settings"><KeyRound className="h-4 w-4 mr-2" /> {pt ? "Ir para configurações" : "Go to settings"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
              </Button>
            </CardContent>
          </Card>
        ) : (
          <>
            <div className="mb-3 flex items-center justify-between gap-2 text-sm text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                {pt ? "Conectado como" : "Signed in as"} <strong className="text-foreground">{auth.login}</strong> · {pt ? "chave Groq ativa" : "Groq key active"}
              </span>
              <Button asChild variant="ghost" size="sm">
                <Link to="/settings"><KeyRound className="h-3.5 w-3.5 mr-1" /> {pt ? "Gerenciar" : "Manage"}</Link>
              </Button>
            </div>
            {/* Colar URL avulsa */}
            <Card className="mb-6">
              <CardContent className="p-4 flex flex-col sm:flex-row gap-2">
                <Input
                  placeholder={pt ? "Cole uma URL de relatório/notícia…" : "Paste a report/news URL…"}
                  value={pasteUrl}
                  onChange={(e) => setPasteUrl(e.target.value)}
                  className="flex-1"
                />
                <Select value={pasteType} onValueChange={(v) => setPasteType(v as DeckType)}>
                  <SelectTrigger className="w-full sm:w-[150px]"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="vuln">{pt ? "Vulnerabilidade" : "Vulnerability"}</SelectItem>
                    <SelectItem value="campaign">{pt ? "Campanha" : "Campaign"}</SelectItem>
                  </SelectContent>
                </Select>
                <Button onClick={() => { generate(pasteUrl.trim(), pasteType, ""); setPasteUrl(""); }} disabled={!pasteUrl.trim()}>
                  <Sparkles className="h-4 w-4 mr-2" /> {pt ? "Gerar boletim" : "Generate"}
                </Button>
              </CardContent>
            </Card>
          </>
        )}

        {/* Jobs em andamento / prontos */}
        {!!jobs.length && (
          <Card className="mb-6">
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <CardTitle className="text-lg">{pt ? "Seus boletins" : "Your bulletins"}</CardTitle>
                  <CardDescription>
                    {pt ? "Quando ficar pronto, baixe o JSON e rode o gerar_slide local." : "When ready, download the JSON and run gerar_slide locally."}
                  </CardDescription>
                </div>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="ghost" size="sm" className="shrink-0 text-muted-foreground hover:text-destructive">
                      <Trash2 className="h-4 w-4 mr-2" /> {pt ? "Limpar histórico" : "Clear history"}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{pt ? "Limpar histórico de boletins?" : "Clear bulletin history?"}</AlertDialogTitle>
                      <AlertDialogDescription>
                        {pt
                          ? "Isso apaga todos os boletins desta lista (incluindo os JSON gerados) deste navegador. Não dá pra desfazer."
                          : "This removes all bulletins from this list (including the generated JSON) on this browser. This can't be undone."}
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{pt ? "Cancelar" : "Cancel"}</AlertDialogCancel>
                      <AlertDialogAction onClick={clearHistory}>{pt ? "Apagar" : "Delete"}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {jobs.map((j) => {
                const elapsed = Math.max(0, nowMs - new Date(j.createdAt).getTime());
                const pidx = phaseIndex(elapsed);
                return (
                  <div key={j.id} className="rounded-md border p-3 animate-fade-in">
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-sm font-medium truncate">{j.title || j.url}</div>
                        <div className="text-xs text-muted-foreground truncate">{j.type} · {j.url}</div>
                      </div>
                      {j.status === "pending" && (
                        <span className="text-xs text-primary inline-flex items-center gap-1.5 shrink-0 tabular-nums">
                          <span className="relative flex h-2 w-2">
                            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />
                            <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
                          </span>
                          {Math.floor(elapsed / 1000)}s
                        </span>
                      )}
                      {j.status === "done" && (
                        <div className="flex items-center gap-2 shrink-0">
                          <Button size="sm" variant="outline" onClick={() => setExpandedId((id) => (id === j.id ? null : j.id))}>
                            {expandedId === j.id
                              ? <><ChevronDown className="h-4 w-4 mr-2" /> {pt ? "Ocultar" : "Hide"}</>
                              : <><Eye className="h-4 w-4 mr-2" /> {pt ? "Ver" : "View"}</>}
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => download(j)}>
                            <Download className="h-4 w-4 mr-2" /> JSON
                          </Button>
                        </div>
                      )}
                      {j.status === "error" && (
                        <span className="text-xs text-red-500 inline-flex items-center gap-1 shrink-0" title={j.error || ""}>
                          <AlertTriangle className="h-3 w-3" /> {pt ? "erro" : "error"}
                        </span>
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
                              ? (pt ? `Na fila — ${j.queuePosition} na sua frente` : `In queue — ${j.queuePosition} ahead of you`)
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
                    {j.status === "done" && expandedId === j.id && j.json && (
                      <BoletimView report={j.json} />
                    )}
                  </div>
                );
              })}
            </CardContent>
          </Card>
        )}

        {/* Sugestões do feed */}
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">{pt ? "Sugestões do dia" : "Today's suggestions"}</h2>
          <Button variant="outline" size="sm" onClick={loadSuggestions} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            {pt ? "Atualizar" : "Refresh"}
          </Button>
        </div>
        {suggestions.length > 0 && (
        <div className="rounded-md border divide-y">
          {suggestions.map((s) => (
            <div key={s.url} className="flex items-center gap-2 px-3 py-2 hover:bg-muted/30">
              <span className={`h-2 w-2 rounded-full shrink-0 ${SEVERITY_DOT[s.severity] || SEVERITY_DOT.Low}`} title={s.severity} />
              <a href={s.url} target="_blank" rel="noopener noreferrer"
                 className="flex-1 min-w-0 truncate text-sm font-medium hover:underline" title={s.title}>
                {s.title}
              </a>
              {s.kev && <ShieldAlert className="h-3.5 w-3.5 text-red-500 shrink-0" aria-label="CISA KEV" />}
              {s.cves?.[0] && <Badge variant="secondary" className="text-[10px] shrink-0 hidden sm:inline-flex">{s.cves[0]}</Badge>}
              <span className="text-xs text-muted-foreground shrink-0 hidden md:inline tabular-nums">{s.source} · {s.score}</span>
              <Button size="sm" variant="ghost" onClick={() => generate(s.url, s.suggestedType, s.title)} className="shrink-0 h-7 px-2 text-primary">
                <Sparkles className="h-3.5 w-3.5 mr-1" /> {pt ? "Gerar" : "Generate"}
              </Button>
            </div>
          ))}
        </div>
        )}
        {!loading && !suggestions.length && (
          <p className="text-center text-muted-foreground py-8">{pt ? "Nenhuma sugestão no momento." : "No suggestions right now."}</p>
        )}
      </main>
      <Footer />
    </div>
  );
};

export default DailyBulletin;
