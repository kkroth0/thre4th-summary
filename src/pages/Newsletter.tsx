import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, BookOpen, AlertTriangle, Search, Mail, Eye, Sparkles, Filter, ChevronDown, RefreshCw, Calendar, Share2, Loader2, Bookmark } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { toast } from "sonner";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { NEWS_CATEGORY_ORDER, countByCategory, filterNewsletterAdvisories, filterStoryCards, formatNewsletterDate, groupAdvisoriesIntoStories } from "./newsletterView";
import type { StoryCard } from "./newsletterView";
import { generateBoletim, saveKnowledge } from "@/services/threatApi";
import { useOrgProfile } from "@/hooks/useOrgProfile";
import { annotateOrg, type OrgMatch } from "@/utils/orgRelevance";

interface IocSet {
  ips?: string[];
  domains?: string[];
  hashes?: string[];
  urls?: string[];
}

interface KevDetails {
  cve: string;
  dateAdded?: string;
  dueDate?: string;
  ransomware?: boolean;
}

interface Advisory {
  title: string;
  link: string;
  pubDate: string;
  description: string;
  source: string;
  // CTI relevance enrichment (from the specialized collector)
  score?: number;
  severity?: string; // Critical | High | Medium | Low
  categories?: string[]; // CTI scoring labels from scoreArticle — unrelated to navigation
  cves?: string[];
  cvss?: number | null;
  reasons?: string[]; // why it scored — surfaced as a tooltip
  // Active-exploitation correlation
  kev?: boolean;
  kevDetails?: KevDetails;
  epss?: number; // 0-1 exploit probability
  // Preenchidos na tela por annotateOrg; nunca vêm da API nem vão para o cache.
  orgScore?: number;
  orgMatches?: OrgMatch[];
  // Deterministic actionable enrichment
  threats?: string[];
  sectors?: string[];
  ttps?: string[];
  assets?: string[];
  iocs?: IocSet;
  // Agrupamento e atribuição, vindos do servidor
  storyId?: string | null;
  actors?: { id: string; name: string; matched?: string; via?: string }[];
  newsCategories?: string[]; // navigation buckets from categorize(), distinct from `categories` above
  primaryCategory?: string | null;
}


// A severidade é a única tag preenchida da linha: ela é o que decide se o card
// merece atenção, e como contorno se perdia entre as outras. O resto usa tinta
// suave sobre contorno, todas no mesmo formato.
// A severidade é o veredito do card e a única cor da parte de cima: contorno
// tingido na etiqueta. O score numérico não aparece — quem lê o feed decide por
// "Crítico", não por 92; o número continua no tooltip de `reasons` e na ordenação
// por relevância.
const SEVERITY_BADGE: Record<string, string> = {
  Critical: "bg-red-500/15 text-red-500 border-red-500/40",
  High: "bg-orange-500/15 text-orange-500 border-orange-500/40",
  Medium: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-500 border-yellow-500/40",
  Low: "bg-slate-400/15 text-slate-500 border-slate-400/40",
};


// Nível de severidade é rótulo de interface, não termo técnico — esse traduz.
const SEVERITY_PT: Record<string, string> = {
  Critical: "Crítico", High: "Alto", Medium: "Médio", Low: "Baixo",
};

const severityLabel = (severity: string, language: string): string =>
  (language === "pt" ? SEVERITY_PT[severity] : severity) || severity;

// Left-accent border + soft tint per severity — carries the visual hierarchy so
// the eye lands on Critical/High first when scanning the feed.
const SEVERITY_ACCENT: Record<string, string> = {
  Critical: "border-l-red-500",
  High: "border-l-orange-500",
  Medium: "border-l-yellow-500",
  Low: "border-l-slate-400",
};

// Compact relative time: "agora"/"now", "12m", "3h", "5d", else short date.
const relTime = (d: string | number | Date, lang = "pt"): string => {
  const t = new Date(d).getTime();
  if (isNaN(t)) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return lang === "pt" ? "agora" : "now";
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  if (s < 604800) return `${Math.floor(s / 86400)}d`;
  return new Date(t).toLocaleDateString(lang === "pt" ? "pt-BR" : "en-US", { day: "2-digit", month: "short" });
};

interface EnrichData {
  available: boolean;
  source?: string; // openrouter | translate | rss
  scraped?: boolean;
  title?: string;
  executiveSummary?: string;
  impactMitigation?: string;
  iocs?: IocSet | null;
  // Deterministic enrichment recomputed over the full article
  threats?: string[];
  sectors?: string[];
  ttps?: string[];
  assets?: string[];
  cves?: string[];
}

// Prefer the richer full-article enrichment, fall back to the collection-time item
const mergedField = (item: Advisory, e: EnrichData | undefined, key: "threats" | "sectors" | "ttps" | "assets" | "cves"): string[] =>
  (e?.[key]?.length ? e[key] : item[key]) ?? [];

// Build a well-organized, shareable text block (mirrors the SOC bot card layout)
const buildShareText = (item: Advisory, e: EnrichData | undefined, lang: string): string => {
  const isPt = lang === "pt";
  const out: string[] = [];
  out.push(`🚨 ${(e?.title || item.title || "").trim()}`);
  out.push("");
  const assets = mergedField(item, e, "assets");
  const threats = mergedField(item, e, "threats");
  const sectors = mergedField(item, e, "sectors");
  const ttps = mergedField(item, e, "ttps");
  const cves = mergedField(item, e, "cves");
  out.push(`Source: ${item.source}`);
  out.push(`Date: ${new Date(item.pubDate).toISOString().slice(0, 10)}`);
  if (assets.length) out.push(`Monitored Assets: ${assets.join(", ")}`);
  if (threats.length) out.push(`Threats: ${threats.join(", ")}`);
  if (sectors.length) out.push(`Targeted Sectors: ${sectors.join(", ")}`);
  if (ttps.length) {
    out.push("", "[ MITRE ATT&CK ]");
    ttps.forEach((tp) => out.push(`• ${tp}`));
  }
  if (e?.executiveSummary) {
    out.push("", `[ ${isPt ? "Resumo Executivo" : "Executive Summary"} ]`, e.executiveSummary);
  }
  if (e?.impactMitigation) {
    out.push("", `[ ${isPt ? "IMPACTO & MITIGAÇÃO" : "IMPACT & MITIGATION"} ]`, e.impactMitigation);
  }
  out.push("", `🔗 Source (${item.link})`);
  const refs = cves.map((c) => `https://nvd.nist.gov/vuln/detail/${c}`).join(", ");
  out.push(`📎 ${isPt ? "Referências" : "References"}: ${refs}`);
  return out.join("\n");
};

const Newsletter = () => {
  const { t, language } = useLanguage();
  
  // Newsletter States
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [searchNews, setSearchNews] = useState("");
  const [loadingNews, setLoadingNews] = useState(true);
  const [newsError, setNewsError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [sortByRelevance, setSortByRelevance] = useState<boolean>(false);
  const [kevOnly, setKevOnly] = useState<boolean>(false);
  const { profiles: orgProfiles, activeId: orgProfileId, setActiveId: setOrgProfileId, model: orgModel } = useOrgProfile();
  const [sortByOrg, setSortByOrg] = useState(false);
  const [orgOnly, setOrgOnly] = useState(false);
  // Links já guardados no Knowledge — só pra desabilitar o botão. A verdade
  // continua no servidor, que de-dup por URL de qualquer jeito.
  const [savedLinks, setSavedLinks] = useState<Set<string>>(new Set());

  // Background Polling / Last Updated States
  const [lastUpdatedNews, setLastUpdatedNews] = useState<Date | null>(null);
  const [isRefreshingNews, setIsRefreshingNews] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState(300);

  // Load from Cache on mount
  useEffect(() => {
    const cached = localStorage.getItem("cached_cti_advisories");
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed)) {
          // Schema/Integrity validation check (LOW-07)
          const validated: Advisory[] = parsed.filter((raw: unknown): raw is Record<string, unknown> => {
            const item = raw as Record<string, unknown>;
            return (
              !!item &&
              typeof item === "object" &&
              typeof item.title === "string" &&
              typeof item.link === "string" &&
              typeof item.pubDate === "string" &&
              typeof item.description === "string" &&
              typeof item.source === "string"
            );
          }).map((item) => ({
            title: item.title as string,
            link: item.link as string,
            pubDate: item.pubDate as string,
            description: item.description as string,
            source: item.source as string,
            score: typeof item.score === "number" ? item.score : undefined,
            severity: typeof item.severity === "string" ? (item.severity as string) : undefined,
            categories: Array.isArray(item.categories) ? (item.categories as string[]) : undefined,
            newsCategories: Array.isArray(item.newsCategories) ? (item.newsCategories as string[]) : undefined,
            cves: Array.isArray(item.cves) ? (item.cves as string[]) : undefined,
            cvss: typeof item.cvss === "number" ? item.cvss : undefined,
            reasons: Array.isArray(item.reasons) ? (item.reasons as string[]) : undefined,
            kev: typeof item.kev === "boolean" ? item.kev : undefined,
            kevDetails: item.kevDetails as KevDetails | undefined,
            epss: typeof item.epss === "number" ? item.epss : undefined,
            threats: Array.isArray(item.threats) ? (item.threats as string[]) : undefined,
            sectors: Array.isArray(item.sectors) ? (item.sectors as string[]) : undefined,
            ttps: Array.isArray(item.ttps) ? (item.ttps as string[]) : undefined,
            assets: Array.isArray(item.assets) ? (item.assets as string[]) : undefined,
            iocs: item.iocs as IocSet | undefined,
            storyId: typeof item.storyId === "string" || item.storyId === null ? (item.storyId as string | null) : undefined,
            actors: Array.isArray(item.actors) ? (item.actors as Advisory["actors"]) : undefined,
            primaryCategory: typeof item.primaryCategory === "string" || item.primaryCategory === null ? (item.primaryCategory as string | null) : undefined,
          }));
          setAdvisories(validated);
        }
      } catch (e) {
        console.error("Failed to parse cached advisories", e);
      }
    }
  }, []);

  // Fetch CTI News / Advisories
  const loadNews = async (isBackground = false) => {
    setSecondsRemaining(300);
    if (!isBackground) {
      setLoadingNews(true);
    } else {
      setIsRefreshingNews(true);
    }
    setNewsError(null);
    try {
      const res = await fetch("/api/newsletter");
      if (!res.ok) throw new Error("Failed to load threat advisories");
      const data = await res.json();
      
      setAdvisories(prev => {
        const merged = [...prev];
        const seenKeys = new Set(merged.map(item => `${item.link}_${item.title}_${item.source}`));
        
        data.forEach((item: Advisory) => {
          const key = `${item.link}_${item.title}_${item.source}`;
          if (!seenKeys.has(key)) {
            merged.push(item);
            seenKeys.add(key);
          } else {
            const index = merged.findIndex(m => `${m.link}_${m.title}_${m.source}` === key);
            if (index !== -1) {
              merged[index] = { ...merged[index], ...item };
            }
          }
        });
        
        // Sort newest first, then cap the persisted set so localStorage can't
        // grow past its quota as advisories accumulate across fetches/months.
        merged.sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime());
        const capped = merged.slice(0, 400);
        try {
          localStorage.setItem("cached_cti_advisories", JSON.stringify(capped));
        } catch {
          /* quota exceeded — keep the in-memory list, skip persistence */
        }
        return capped;
      });

      setLastUpdatedNews(new Date());
    } catch (err) {
      console.error(err);
      if (!isBackground) {
        setNewsError(err instanceof Error ? err.message : "Failed to load threat advisories");
      } else {
        toast.error(language === "pt" ? "Erro ao atualizar notícias em segundo plano" : "Failed to background refresh news");
      }
    } finally {
      setLoadingNews(false);
      setIsRefreshingNews(false);
    }
  };

  useEffect(() => {
    loadNews();

    // 1-second interval to update countdown
    const countdownInterval = setInterval(() => {
      setSecondsRemaining(prev => {
        if (prev <= 1) {
          loadNews(true);
          return 300;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      clearInterval(countdownInterval);
    };
    // loadNews is stable for the component lifetime; run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Time formatting helper
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  // Regex highlighting helper for CVEs inside description text
  const renderHighlightedDescription = (text: string) => {
    if (!text) return "";
    
    const cveRegex = /(cve-\d{4}-\d{4,7})/gi;
    const parts = text.split(cveRegex);
    
    if (parts.length === 1) return text;
    
    return (
      <>
        {parts.map((part, index) => {
          if (cveRegex.test(part)) {
            const cveUpper = part.toUpperCase();
            return (
              <Badge
                key={index}
                variant="outline"
                className="mx-1 font-mono text-[11px] font-bold bg-primary/10 text-primary border-border/50 hover:bg-primary/20 cursor-pointer transition-colors scale-95"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  handlePivotSearch(cveUpper);
                }}
                title={language === "pt" ? `Pesquisar ${cveUpper} no painel` : `Pivot search ${cveUpper} on dashboard`}
              >
                {cveUpper}
              </Badge>
            );
          }
          return part;
        })}
      </>
    );
  };

  // Trigger Pivot Search on main dashboard
  const handlePivotSearch = (cveId: string) => {
    localStorage.setItem("pivotSearchQuery", cveId);
    toast.success(language === "pt" ? `Pesquisando ${cveId} no painel...` : `Searching ${cveId} on main dashboard...`);
    window.location.href = "/";
  };

  // ── Actionable analysis: expand + lazy LLM enrichment + share ──
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [enrichment, setEnrichment] = useState<Record<string, { loading: boolean; data?: EnrichData }>>({});

  // A cobertura inteira é o contexto: análise e boletim leem todas as fontes.
  // Escolher quais entram é decisão da tela de geração, não do feed — aqui o
  // analista está lendo, não montando entregável.
  const sourcesOf = (card: StoryCard<Advisory>) => card.sources.map((s) => s.link);
  const enrichKeyOf = (card: StoryCard<Advisory>) => [...sourcesOf(card)].sort().join("|");

  // Chaveada pelo conjunto marcado, não pelo link do artigo: desmarcar uma fonte
  // é outra análise e tem que refazer, não reaproveitar a anterior.
  const getEnrichment = async (item: Advisory, urls: string[] = [item.link]): Promise<EnrichData> => {
    const key = [...urls].sort().join("|");
    const cached = enrichment[key]?.data;
    if (cached) return cached;
    setEnrichment(p => ({ ...p, [key]: { loading: true } }));
    try {
      const res = await fetch("/api/newsletter/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls, lang: language }),
      });
      if (!res.ok) throw new Error("enrich failed");
      const data: EnrichData = await res.json();
      setEnrichment(p => ({ ...p, [key]: { loading: false, data } }));
      return data;
    } catch {
      const fallback: EnrichData = { available: false, executiveSummary: item.description, impactMitigation: "" };
      setEnrichment(p => ({ ...p, [key]: { loading: false, data: fallback } }));
      return fallback;
    }
  };

  // O destaque abre sozinho — é o card que o leitor vai ler de qualquer jeito, e
  // uma chamada de enrich por carga do feed é barata. Abrir todos não seria:
  // cada painel custa um scrape e uma chamada de LLM.
  const isExpanded = (card: StoryCard<Advisory>, featured: boolean) =>
    expanded[card.sources[0].link] ?? featured;

  const toggleExpand = (card: StoryCard<Advisory>, featured: boolean) => {
    const item = card.sources[0];
    const open = !isExpanded(card, featured);
    if (open && !enrichment[enrichKeyOf(card)]) void getEnrichment(item, sourcesOf(card));
    setExpanded(p => ({ ...p, [item.link]: open }));
  };

  const shareAdvisory = async (card: StoryCard<Advisory>) => {
    const item = card.sources[0];
    const data = enrichment[enrichKeyOf(card)]?.data ?? (await getEnrichment(item, sourcesOf(card)));
    const text = buildShareText(item, data, language);
    try {
      if (navigator.share) {
        await navigator.share({ title: item.title, text });
      } else {
        await navigator.clipboard.writeText(text);
        toast.success(language === "pt" ? "Análise copiada para a área de transferência" : "Analysis copied to clipboard");
      }
    } catch {
      /* user dismissed the share sheet — no-op */
    }
  };

  // Enfileira um boletim sobre as fontes marcadas. O job é assíncrono (um worker
  // na VPS consome a fila), então aqui só confirmamos o enfileiramento — o
  // acompanhamento é a página de relatórios, que já lista os jobs do usuário.
  const [boletimBusy, setBoletimBusy] = useState<string | null>(null);

  const makeBoletim = async (card: StoryCard<Advisory>) => {
    const urls = sourcesOf(card);
    setBoletimBusy(card.storyId);
    try {
      await generateBoletim(urls, card.cves.length ? "vuln" : "campaign", card.title);
      toast.success(language === "pt"
        ? `Boletim na fila com ${urls.length} ${urls.length > 1 ? "fontes" : "fonte"} de contexto — acompanhe em Relatórios.`
        : `Report queued with ${urls.length} source${urls.length > 1 ? "s" : ""} of context — track it in Reports.`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : (language === "pt" ? "Falha ao enfileirar o boletim" : "Failed to queue the report"));
    } finally {
      setBoletimBusy(null);
    }
  };

  // Segue a cobertura no Knowledge. Vai o storyId e quantos veículos existiam
  // agora: a cobertura continua crescendo, e é essa diferença que a aba mostra
  // como novidade. O servidor extrai as técnicas do título e une com os CVEs que
  // o coletor já tinha achado, então o item já nasce indexado.
  const keepAdvisory = async (card: StoryCard<Advisory>) => {
    const item = card.sources[0];
    try {
      await saveKnowledge({
        title: card.title,
        url: item.link,
        source: item.source,
        publishedAt: item.pubDate,
        cves: card.cves,
        storyId: card.storyId,
        sourceCount: new Set(card.sources.map((source) => source.source)).size,
      });
      setSavedLinks((prev) => new Set(prev).add(item.link));
      toast.success(language === "pt" ? "Seguindo — novas fontes aparecem no Knowledge" : "Following — new sources show up in Knowledge");
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  // Filter Advisories / News
  const filteredAdvisories = useMemo(() => annotateOrg(filterNewsletterAdvisories(advisories, {
    search: searchNews,
    severity: selectedSeverity,
    kevOnly,
    sortByRelevance,
  }), orgModel), [advisories, searchNews, selectedSeverity, sortByRelevance, kevOnly, orgModel]);

  const [categoryFilter, setCategoryFilter] = useState("");

  const storyCards = useMemo(
    () => filterStoryCards(
      groupAdvisoriesIntoStories(filteredAdvisories, { sortByRelevance, sortByOrg: sortByOrg && Boolean(orgModel) }),
      { category: categoryFilter, orgOnly: orgOnly && Boolean(orgModel) },
    ),
    [filteredAdvisories, sortByRelevance, sortByOrg, orgModel, categoryFilter, orgOnly],
  );
  const categoryCounts = useMemo(() => countByCategory(groupAdvisoriesIntoStories(filteredAdvisories)), [filteredAdvisories]);

  // How many filters are narrowing the feed — drives the badge on the Filters button.
  const activeFilterCount = [
    selectedSeverity !== "all",
    sortByRelevance,
    kevOnly,
    sortByOrg,
    orgOnly,
  ].filter(Boolean).length;
  const clearFilters = () => {
    setSelectedSeverity("all");
    setSortByRelevance(false);
    setKevOnly(false);
    setSortByOrg(false);
    setOrgOnly(false);
  };

  return (
    <PageLayout width="max-w-7xl">
        <div className="space-y-6">

          {/* Page Title Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Mail className="h-6 w-6 text-primary" />
                {language === "pt" ? "Notícias de Segurança" : "Security News"}
              </h1>
              <p className="text-xs text-muted-foreground mt-1">
                {language === "pt"
                  ? "Agregador de notícias e avisos de segurança de múltiplas fontes de inteligência contra ameaças"
                  : "Threat intelligence news and security advisories aggregated from multiple sources"}
              </p>
            </div>
            {/* Auto-polling / última atualização — status enxuto + gestão de fontes */}
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex items-center gap-2 text-xs text-muted-foreground tabular-nums">
                <span className={`h-1.5 w-1.5 rounded-full ${isRefreshingNews ? "bg-primary animate-pulse" : "bg-green-500"}`} />
                {isRefreshingNews
                  ? (language === "pt" ? "atualizando…" : "refreshing…")
                  : (
                    <span>
                      {language === "pt" ? "atualizado " : "updated "}
                      {lastUpdatedNews ? lastUpdatedNews.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}
                      <span className="text-muted-foreground/40"> · {language === "pt" ? "próx." : "next"} </span>
                      {formatTime(secondsRemaining)}
                    </span>
                  )}
              </div>
            </div>
          </div>

          {/* Date + search + filters — one bar */}
          <div className="flex flex-col xl:flex-row xl:items-center gap-3 bg-card border p-3 rounded-lg">
            <div className="flex items-center gap-2.5 shrink-0">
              <Calendar className="h-4 w-4 text-primary shrink-0" />
              <span className="text-sm font-semibold text-foreground capitalize whitespace-nowrap">
                {formatNewsletterDate(new Date(), language)}
              </span>
            </div>
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t("searchAdvisories") || "Search advisories..."}
                value={searchNews}
                onChange={(e) => setSearchNews(e.target.value)}
                className="pl-9 bg-card border-border/50"
              />
            </div>
            
            {/* Filters & Actions */}
            <div className="flex items-center gap-1.5 shrink-0">
              {/* All filters collapsed into one popover — keeps the bar clean */}
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant={activeFilterCount > 0 ? "default" : "outline"}
                    size="sm"
                    className="h-9 text-xs font-semibold px-3 gap-1.5"
                  >
                    <Filter className="h-3.5 w-3.5" />
                    {language === "pt" ? "Filtros" : "Filters"}
                    {activeFilterCount > 0 && (
                      <Badge variant="secondary" className="ml-0.5 h-4 min-w-[16px] px-1 text-[10px] tabular-nums">
                        {activeFilterCount}
                      </Badge>
                    )}
                  </Button>
                </PopoverTrigger>
                <PopoverContent align="end" className="w-72 space-y-3">
                  {/* Severity */}
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                      {language === "pt" ? "Severidade" : "Severity"}
                    </div>
                    <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                      <SelectTrigger className="h-8 text-xs font-semibold">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">{language === "pt" ? "Toda Severidade" : "All Severity"}</SelectItem>
                        <SelectItem value="Critical">Critical</SelectItem>
                        <SelectItem value="High">High</SelectItem>
                        <SelectItem value="Medium">Medium</SelectItem>
                        <SelectItem value="Low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator />

                  {/* Sort + KEV toggles */}
                  <div className="grid grid-cols-2 gap-1.5">
                    <Button
                      variant={sortByRelevance ? "default" : "outline"}
                      size="sm"
                      className="h-8 text-xs font-semibold gap-1.5"
                      onClick={() => setSortByRelevance((v) => !v)}
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      {language === "pt" ? "Relevância" : "Relevance"}
                    </Button>
                    <Button
                      variant={kevOnly ? "default" : "outline"}
                      size="sm"
                      className={`h-8 text-xs font-semibold gap-1.5 ${kevOnly ? "bg-red-600 hover:bg-red-600/90 text-white" : "text-red-500 border-red-500/30 hover:bg-red-500/5"}`}
                      onClick={() => setKevOnly((v) => !v)}
                    >
                      <AlertTriangle className="h-3.5 w-3.5" />
                      {language === "pt" ? "Explorado" : "Exploited"}
                    </Button>
                  </div>

                  {orgProfiles.length > 0 && (
                    <div className="space-y-2 border-t pt-3">
                      <label className="text-xs font-medium text-muted-foreground">
                        {language === "pt" ? "Contexto da organização" : "Organization context"}
                      </label>
                      <select
                        value={orgProfileId}
                        onChange={(event) => setOrgProfileId(event.target.value)}
                        className="w-full rounded-md border bg-background px-2 py-1.5 text-xs"
                      >
                        <option value="">{language === "pt" ? "Sem contexto" : "No context"}</option>
                        {orgProfiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>{profile.name}</option>
                        ))}
                      </select>
                      <label className="flex items-center gap-2 text-xs">
                        <input type="checkbox" checked={sortByOrg} disabled={!orgModel} onChange={(event) => setSortByOrg(event.target.checked)} />
                        {language === "pt" ? "Relevante para mim primeiro" : "Most relevant to me first"}
                      </label>
                      <label className="flex items-center gap-2 text-xs">
                        <input type="checkbox" checked={orgOnly} disabled={!orgModel} onChange={(event) => setOrgOnly(event.target.checked)} />
                        {language === "pt" ? "Só o meu contexto" : "My context only"}
                      </label>
                    </div>
                  )}

                  {activeFilterCount > 0 && (
                    <Button variant="ghost" size="sm" className="h-8 w-full text-xs text-muted-foreground" onClick={clearFilters}>
                      {language === "pt" ? "Limpar filtros" : "Clear filters"}
                    </Button>
                  )}
                </PopoverContent>
              </Popover>

              <Button
                variant="outline"
                size="icon"
                disabled={loadingNews || isRefreshingNews}
                onClick={() => loadNews()}
                className="h-9 w-9 border-border/50 hover:bg-primary/5 shrink-0"
                title={language === "pt" ? "Atualizar feeds" : "Refresh feeds"}
              >
                <RefreshCw className={`h-4 w-4 ${(loadingNews || isRefreshingNews) ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </div>

          {/* News history */}
          <div className="space-y-6">
            {/* News Feed */}
            <div className="space-y-4">
              {/* Loading/Error/News List */}
              <div className="flex flex-wrap gap-2 pb-3">
                <button
                  type="button"
                  onClick={() => setCategoryFilter("")}
                  aria-pressed={categoryFilter === ""}
                  className={`rounded-full border px-3 py-1 text-xs transition ${categoryFilter === "" ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                >
                  {language === "pt" ? "Todas" : "All"}
                </button>
                {NEWS_CATEGORY_ORDER.filter((name) => categoryCounts[name]).map((name) => (
                  <button
                    key={name}
                    type="button"
                    onClick={() => setCategoryFilter(categoryFilter === name ? "" : name)}
                    aria-pressed={categoryFilter === name}
                    className={`rounded-full border px-3 py-1 text-xs transition ${categoryFilter === name ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                  >
                    {name} <span className="tabular-nums opacity-60">{categoryCounts[name]}</span>
                  </button>
                ))}
              </div>
              {loadingNews ? (
                <div className="space-y-4">
                  {[1, 2, 3].map((n) => (
                    <div key={n} className="p-4 rounded-lg border bg-card animate-pulse space-y-3">
                      <div className="h-4 w-1/4 bg-muted rounded"></div>
                      <div className="h-6 w-3/4 bg-muted rounded"></div>
                      <div className="h-4 w-5/6 bg-muted rounded"></div>
                    </div>
                  ))}
                </div>
              ) : newsError ? (
                <div className="p-8 border border-destructive/20 rounded-lg bg-destructive/5 text-center">
                  <AlertTriangle className="h-10 w-10 text-destructive mx-auto mb-3" />
                  <p className="text-destructive font-medium">{newsError}</p>
                  <p className="text-sm text-muted-foreground mt-1">Please try again later.</p>
                </div>
              ) : storyCards.length === 0 ? (
                <div className="p-12 border border-dashed rounded-lg text-center bg-card space-y-4">
                  <BookOpen className="h-12 w-12 text-muted-foreground/50 mx-auto mb-3" />
                  <div>
                    <p className="text-muted-foreground font-medium">{language === "pt" ? "Nenhuma notícia encontrada no histórico" : "No threat advisories found in the stored history"}</p>
                    <p className="text-xs text-muted-foreground mt-1">{language === "pt" ? "Ajuste a busca ou os filtros, ou atualize os feeds" : "Adjust the search or filters, or refresh the feeds"}</p>
                  </div>
                  <Button
                    onClick={() => loadNews()}
                    className="gap-2 h-9 px-4 rounded-md text-xs font-semibold bg-primary hover:bg-primary/90 text-white mx-auto"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {language === "pt" ? "Buscar Notícias Recentes" : "Fetch Recent Advisories"}
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col gap-2.5">
                  {storyCards.map((card, idx) => {
                    const item = card.sources[0];
                    const enrichKey = enrichKeyOf(card);
                    const enr = enrichment[enrichKey]?.data;
                    // Magazine layout: the first item (top of the current sort —
                    // highest relevance or newest) renders as the featured story.
                    const featured = idx === 0;
                    const accent = item.severity ? (SEVERITY_ACCENT[item.severity] || SEVERITY_ACCENT.Low) : "border-l-transparent";

                    return (
                      <div
                        key={idx}
                        className={cn(
                          "rounded-lg border border-l-[3px] bg-card p-4 transition-colors hover:border-border/50",
                          accent,
                          featured && "shadow-sm ring-1 ring-primary/10",
                        )}
                      >
                        {/* Severidade e hora, com o chevron do card à direita. A seta
                            controla o corpo inteiro (sumário + fontes + ações), não um
                            pedaço: um disclosure por card em vez de um por seção. */}
                        <div className="flex items-center gap-2.5">
                          {item.severity && (
                            <Badge
                              title={item.reasons?.length ? `${language === "pt" ? "Por quê" : "Why"}: ${item.reasons.join(" · ")}` : undefined}
                              className={cn(
                                "rounded px-1.5 py-0 font-mono text-[10px] font-bold uppercase tracking-wider",
                                SEVERITY_BADGE[item.severity] || SEVERITY_BADGE.Low,
                                item.reasons?.length && "cursor-help",
                              )}
                            >
                              {severityLabel(item.severity, language)}
                            </Badge>
                          )}
                          {card.orgScore > 0 && (
                            <Badge
                              variant="outline"
                              title={language === "pt" ? "Casa com o contexto da organização" : "Matches your organization context"}
                              className="rounded border-primary/30 bg-primary/10 px-1.5 py-0 font-mono text-[10px] font-bold uppercase tracking-wider text-primary"
                            >
                              {language === "pt" ? "Relevante" : "Relevant"}
                              <span className="ml-1 font-normal normal-case tracking-normal opacity-80">
                                {card.orgMatches.slice(0, 3).map((match) => match.label).join(" · ")}
                              </span>
                            </Badge>
                          )}
                          <span className="ml-auto font-mono text-xs text-muted-foreground" title={new Date(item.pubDate).toLocaleString()}>
                            {relTime(item.pubDate, language)}
                          </span>
                          <button
                            type="button"
                            onClick={() => toggleExpand(card, featured)}
                            aria-expanded={isExpanded(card, featured)}
                            aria-label={language === "pt" ? "Expandir" : "Expand"}
                            className="text-muted-foreground transition-colors hover:text-foreground"
                          >
                            <ChevronDown className={cn("h-4 w-4 transition-transform", !isExpanded(card, featured) && "-rotate-90")} />
                          </button>
                        </div>

                        {/* Só a manchete grande recebe o título normalizado e traduzido
                            pela análise. Os títulos das fontes ficam como o veículo
                            publicou — é por eles que o analista reencontra a matéria
                            depois, e traduzir quebraria a busca. */}
                        <h3 className={cn("mt-2 font-bold text-foreground", featured ? "text-lg leading-snug" : "text-base leading-snug")}>
                          <a href={item.link} target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">
                            {enr?.title || item.title}
                          </a>
                        </h3>

                        {/* Faixa de identificadores: rótulo apagado, valor legível, um
                            filete entre os pares. Pílula para cada um enchia a linha de
                            molduras sem acrescentar informação. */}
                        {(item.cves?.length || typeof item.epss === "number" || item.kev) && (
                          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs">
                            {(item.cves ?? []).slice(0, 2).map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="group/cve"
                              >
                                <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70">CVE </span>
                                <span className="text-foreground/90 group-hover/cve:text-primary">{cve.replace(/^CVE-/i, "")}</span>
                              </a>
                            ))}
                            {typeof item.epss === "number" && (
                              <span className="border-l border-border pl-3" title={language === "pt" ? "Probabilidade de exploração em 30 dias (FIRST EPSS)" : "30-day exploit probability (FIRST EPSS)"}>
                                <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70">EPSS </span>
                                <span className="text-foreground/90">{Math.round(item.epss * 100)}%</span>
                              </span>
                            )}
                            {item.kev && (
                              <span className="border-l border-border pl-3" title={item.kevDetails?.dateAdded ? `${language === "pt" ? "Adicionado em" : "Added"} ${item.kevDetails.dateAdded}` : "CISA KEV"}>
                                <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70">KEV </span>
                                <span className="text-foreground/90">CISA</span>
                              </span>
                            )}
                          </div>
                        )}

                        {isExpanded(card, featured) && (
                          <>
                            {enrichment[enrichKey]?.loading ? (
                              <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                {language === "pt" ? "Coletando artigos e gerando análise..." : "Fetching articles and generating analysis..."}
                              </div>
                            ) : (
                              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
                                {enr?.executiveSummary || renderHighlightedDescription(item.description)}
                              </p>
                            )}

                            {card.sources.length > 1 && (
                              <div className="mt-4 border-t pt-3">
                                <div className="flex items-center gap-2 text-xs">
                                  <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                                    {language === "pt" ? "Fontes" : "Sources"}
                                  </span>
                                  <span className="font-semibold text-foreground">{card.sources.length}</span>
                                </div>

                                {/* Linha do tempo da cobertura: a data é a espinha à
                                    esquerda, e o filete liga um veículo ao seguinte. As
                                    fontes já vinham em ordem cronológica — isto só faz a
                                    ordem ser visível, que é o que mostra a notícia se
                                    espalhando de um veículo para os outros. */}
                                <div className="mt-2">
                                  {[...card.sources]
                                    .sort((a, b) => a.pubDate.localeCompare(b.pubDate))
                                    .map((source, sourceIdx, ordered) => (
                                      <div
                                        key={source.link}
                                        className="flex items-center gap-3 rounded py-1.5 text-xs transition-colors hover:bg-muted/40"
                                      >
                                        <span className="w-10 shrink-0 font-mono tabular-nums text-muted-foreground/70">
                                          {new Date(source.pubDate).toLocaleDateString(language === "pt" ? "pt-BR" : "en-US", { day: "2-digit", month: "2-digit" })}
                                        </span>
                                        {/* Sem checkbox, a bolinha é o marcador da linha: fica
                                            maior e na cor da marca, com o fio em cinza de texto
                                            em vez da cor de borda — que no tema escuro quase
                                            não separava do fundo do card. */}
                                        <span className="relative flex w-2.5 shrink-0 items-center justify-center self-stretch">
                                          {sourceIdx > 0 && <span className="absolute bottom-1/2 top-0 w-px bg-muted-foreground/30" />}
                                          {sourceIdx < ordered.length - 1 && <span className="absolute bottom-0 top-1/2 w-px bg-muted-foreground/30" />}
                                          <span className="relative h-2 w-2 rounded-full bg-primary ring-2 ring-card" />
                                        </span>
                                        <span className="w-28 shrink-0 truncate font-semibold text-foreground">{source.source}</span>
                                        <a
                                          href={source.link}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="truncate text-muted-foreground hover:text-primary hover:underline"
                                          title={source.title}
                                        >
                                          {source.title}
                                        </a>
                                      </div>
                                    ))}
                                </div>
                              </div>
                            )}

                            <div className="mt-4 flex items-center gap-2 border-t pt-3">
                              <Button
                                size="sm"
                                onClick={() => makeBoletim(card)}
                                disabled={boletimBusy === card.storyId}
                                className="h-8 px-3 text-xs font-semibold"
                              >
                                {boletimBusy === card.storyId && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
                                {language === "pt" ? "Gerar Boletim" : "Generate Bulletin"}
                              </Button>
                              <Button asChild variant="outline" size="sm" className="h-8 px-3 text-xs font-semibold">
                                <a href={item.link} target="_blank" rel="noopener noreferrer">
                                  {language === "pt" ? "Ver artigo" : "Read article"}
                                </a>
                              </Button>
                              <Button
                                variant="ghost" size="icon"
                                onClick={() => shareAdvisory(card)}
                                title={language === "pt" ? "Compartilhar" : "Share"}
                                className="ml-auto h-8 w-8 text-muted-foreground hover:text-foreground"
                              >
                                <Share2 className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost" size="icon"
                                onClick={() => keepAdvisory(card)}
                                disabled={savedLinks.has(item.link)}
                                title={savedLinks.has(item.link)
                                  ? (language === "pt" ? "Seguindo" : "Following")
                                  : (language === "pt" ? "Seguir" : "Follow")}
                                className="h-8 w-8 text-muted-foreground hover:text-foreground"
                              >
                                <Bookmark className={cn("h-4 w-4", savedLinks.has(item.link) && "fill-current text-primary")} />
                              </Button>
                            </div>
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

          </div>

        </div>
    </PageLayout>
  );
};

export default Newsletter;
