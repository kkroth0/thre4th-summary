import React, { useState, useEffect, useCallback, useRef } from "react";
import { RefreshCw, Download, ShieldAlert, Loader2, ExternalLink, CalendarDays, Sparkles, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { toast } from "sonner";
import {
  fetchDailySuggestions, generateBoletim, fetchJob,
  type DailySuggestion, type BoletimJob, type DeckType,
} from "@/services/threatApi";

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-500 border-red-500/20",
  High: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  Medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  Low: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

const slug = (s: string) => (s || "boletim").normalize("NFKD").replace(/[^\w\s-]/g, "").trim().toLowerCase().replace(/[\s_-]+/g, "-").slice(0, 50) || "boletim";

// Após esse tempo um job ainda "pending" vira erro no front (worker caiu, ou o
// backend reiniciou e perdeu o job -> 404). Evita "gerando…" eterno.
const CLIENT_TIMEOUT_MS = 10 * 60 * 1000;

const DailyBulletin: React.FC = () => {
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
  const pt = language === "pt";

  const [suggestions, setSuggestions] = useState<DailySuggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const [pasteUrl, setPasteUrl] = useState("");
  const [pasteType, setPasteType] = useState<DeckType>("vuln");
  const [jobs, setJobs] = useState<BoletimJob[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

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

  const generate = async (url: string, type: DeckType, title: string) => {
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

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-5xl">
        <div className="mb-6">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <CalendarDays className="h-7 w-7 text-primary" />
            {pt ? "Gerar Boletim" : "Generate Bulletin"}
          </h1>
          <p className="text-muted-foreground mt-2">
            {pt
              ? "Escolha (ou cole) uma URL. A VPS faz a coleta + análise e devolve o JSON; baixe e preencha o PPT oficial localmente com o template confidencial."
              : "Pick (or paste) a URL. The VPS scrapes + analyzes and returns the JSON; download it and fill the official PPT locally with the confidential template."}
          </p>
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

        {/* Jobs em andamento / prontos */}
        {!!jobs.length && (
          <Card className="mb-6">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg">{pt ? "Seus boletins" : "Your bulletins"}</CardTitle>
              <CardDescription>
                {pt ? "Quando ficar pronto, baixe o JSON e rode o gerar_slide local." : "When ready, download the JSON and run gerar_slide locally."}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {jobs.map((j) => (
                <div key={j.id} className="flex items-center justify-between rounded-md border p-3 gap-3">
                  <div className="min-w-0">
                    <div className="text-sm font-medium truncate">{j.title || j.url}</div>
                    <div className="text-xs text-muted-foreground truncate">{j.type} · {j.url}</div>
                  </div>
                  {j.status === "pending" && (
                    <span className="text-xs text-muted-foreground inline-flex items-center gap-1 shrink-0">
                      <Loader2 className="h-3 w-3 animate-spin" /> {pt ? "gerando…" : "generating…"}
                    </span>
                  )}
                  {j.status === "done" && (
                    <Button size="sm" variant="outline" onClick={() => download(j)} className="shrink-0">
                      <Download className="h-4 w-4 mr-2" /> JSON
                    </Button>
                  )}
                  {j.status === "error" && (
                    <span className="text-xs text-red-500 inline-flex items-center gap-1 shrink-0" title={j.error || ""}>
                      <AlertTriangle className="h-3 w-3" /> {pt ? "erro" : "error"}
                    </span>
                  )}
                </div>
              ))}
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
        <div className="space-y-3">
          {suggestions.map((s) => (
            <Card key={s.url}>
              <CardContent className="p-4 flex items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline" className={SEVERITY_STYLES[s.severity] || SEVERITY_STYLES.Low}>{s.severity}</Badge>
                    <span className="text-xs text-muted-foreground">{s.source}</span>
                    <span className="text-xs text-muted-foreground">· score {s.score}</span>
                    {s.kev && (
                      <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
                        <ShieldAlert className="h-3 w-3 mr-1" /> CISA KEV
                      </Badge>
                    )}
                    {s.cves?.slice(0, 3).map((c) => (<Badge key={c} variant="secondary" className="text-[10px]">{c}</Badge>))}
                  </div>
                  <a href={s.url} target="_blank" rel="noopener noreferrer" className="font-medium hover:underline inline-flex items-center gap-1 mt-1">
                    {s.title} <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                </div>
                <Button size="sm" onClick={() => generate(s.url, s.suggestedType, s.title)} className="shrink-0">
                  <Sparkles className="h-4 w-4 mr-2" /> {pt ? "Gerar" : "Generate"}
                </Button>
              </CardContent>
            </Card>
          ))}
          {!loading && !suggestions.length && (
            <p className="text-center text-muted-foreground py-8">{pt ? "Nenhuma sugestão no momento." : "No suggestions right now."}</p>
          )}
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default DailyBulletin;
