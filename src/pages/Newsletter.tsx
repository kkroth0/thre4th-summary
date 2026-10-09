import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, BookOpen, AlertTriangle, Search, Mail, Eye, Filter, ChevronDown, RefreshCw, Share2, Loader2, Bookmark, X, PencilLine, ExternalLink, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { EmptyState } from "@/components/EmptyState";
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
import { cn } from "@/lib/utils";
import { NEWS_CATEGORY_ORDER, countByCategory, filterNewsletterAdvisories, filterStoryCards, groupAdvisoriesIntoStories, severityEvidence, activeFilterChips, TIME_RANGES } from "./newsletterView";
import type { TimeRange } from "./newsletterView";
import type { StoryCard } from "./newsletterView";
import { generateBoletim, saveKnowledge, fetchStoryDetail, type StoryDetail, type CorrelationEvidenceType } from "@/services/threatApi";
import { useOrgProfile } from "@/hooks/useOrgProfile";
import { useNewsMonitoring } from "@/hooks/useNewsMonitoring";
import { useAuth } from "@/contexts/AuthContext";
import { newsMonitoringCacheKey } from "@/utils/newsVendorSelection";
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
  weight_boost?: number; // confiança/prioridade da fonte (0-20), do catálogo CTI_FEEDS
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
  vendors?: { id: string; name: string; sector: string; matched: string }[];
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

// Rótulo do chip de evidência — por que o servidor agrupou estas fontes numa
// história só (ver server/correlationEvidence.js).
const EVIDENCE_LABEL: Record<CorrelationEvidenceType, { pt: string; en: string }> = {
  cve: { pt: "Mesmo CVE", en: "Same CVE" },
  campaign: { pt: "Mesma campanha", en: "Same campaign" },
  actor: { pt: "Mesmo ator", en: "Same actor" },
  malware: { pt: "Mesmo malware", en: "Same malware" },
  "ioc-hash": { pt: "Mesmo hash", en: "Same hash" },
  "ioc-domain": { pt: "Mesmo domínio", en: "Same domain" },
  "ioc-url": { pt: "Mesma URL", en: "Same URL" },
  "ioc-ip": { pt: "Mesmo IP", en: "Same IP" },
  ttp: { pt: "Mesma técnica MITRE", en: "Same MITRE technique" },
  "rare-term": { pt: "Termo em comum", en: "Shared term" },
};

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
  const { language } = useLanguage();
  const { auth } = useAuth();
  const monitoring = useNewsMonitoring();
  const newsCacheKey = monitoring.data ? newsMonitoringCacheKey(auth.login ?? "", monitoring.data.preferences) : null;
  const newsRequest = useRef<AbortController | null>(null);
  
  // Newsletter States
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [searchNews, setSearchNews] = useState("");
  const [loadingNews, setLoadingNews] = useState(true);
  const [newsError, setNewsError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedSource, setSelectedSource] = useState<string>("all");
  const [sortByRelevance, setSortByRelevance] = useState<boolean>(false);
  const [kevOnly, setKevOnly] = useState<boolean>(false);
  const [timeRange, setTimeRange] = useState<TimeRange>("all");
  const searchInputRef = useRef<HTMLInputElement>(null);
  const { profiles: orgProfiles, activeId: orgProfileId, setActiveId: setOrgProfileId, model: orgModel } = useOrgProfile();
  const [orgOnly, setOrgOnly] = useState(false);
  // Links já guardados no Knowledge — só pra desabilitar o botão. A verdade
  // continua no servidor, que de-dup por URL de qualquer jeito.
  const [savedLinks, setSavedLinks] = useState<Set<string>>(new Set());

  // Background Polling / Last Updated States
  const [lastUpdatedNews, setLastUpdatedNews] = useState<Date | null>(null);
  const [isRefreshingNews, setIsRefreshingNews] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState(300);

  // Cached news is scoped to account and selection. Changing either clears the
  // view before loading another snapshot, including an offline visit.
  useEffect(() => {
    setAdvisories([]);
    if (!newsCacheKey) return;
    let cached: string | null = null;
    try { cached = localStorage.getItem(newsCacheKey); } catch { /* storage may be disabled */ }
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
            weight_boost: typeof item.weight_boost === "number" ? item.weight_boost : undefined,
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
            vendors: Array.isArray(item.vendors) ? (item.vendors as Advisory["vendors"]) : undefined,
            primaryCategory: typeof item.primaryCategory === "string" || item.primaryCategory === null ? (item.primaryCategory as string | null) : undefined,
          }));
          setAdvisories(validated);
        }
      } catch (e) {
        console.error("Failed to parse cached advisories", e);
      }
    }
  }, [newsCacheKey]);

  // Fetch CTI News / Advisories
  const loadNews = useCallback(async (isBackground = false) => {
    if (!newsCacheKey) return;
    newsRequest.current?.abort();
    const controller = new AbortController();
    newsRequest.current = controller;
    setSecondsRemaining(300);
    if (!isBackground) {
      setLoadingNews(true);
    } else {
      setIsRefreshingNews(true);
    }
    setNewsError(null);
    try {
      const res = await fetch("/api/newsletter", { signal: controller.signal, cache: "no-store" });
      if (!res.ok) throw new Error("Failed to load threat advisories");
      const data = await res.json();
      if (controller.signal.aborted) return;
      
      if (!Array.isArray(data)) throw new Error("Invalid feed response");
      // The backend snapshot owns story identity. Combining it with older
      // snapshots resurrects retired IDs after an event merge.
      const snapshot = data as Advisory[];
      setAdvisories(snapshot);
      try {
        localStorage.removeItem("cached_cti_advisories_v2");
        localStorage.removeItem("cached_cti_advisories_v3");
        localStorage.setItem(newsCacheKey, JSON.stringify(snapshot.slice(0, 400)));
      } catch { /* keep the complete in-memory snapshot if storage is full */ }
      setLastUpdatedNews(new Date());
    } catch (err) {
      if (controller.signal.aborted) return;
      console.error(err);
      if (!isBackground) {
        setNewsError(err instanceof Error ? err.message : "Failed to load threat advisories");
      } else {
        toast.error(language === "pt" ? "Erro ao atualizar notícias em segundo plano" : "Failed to background refresh news");
      }
    } finally {
      if (newsRequest.current === controller) {
        setLoadingNews(false);
        setIsRefreshingNews(false);
      }
    }
  }, [newsCacheKey, language]);

  useEffect(() => {
    if (!newsCacheKey) return;
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
      newsRequest.current?.abort();
    };
  }, [loadNews, newsCacheKey]);

  // Atalho "/" foca a busca — só quando o foco não está já num campo de
  // digitação, senão "/" vira caractere normal em vez de atalho.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if (typing) return;
      e.preventDefault();
      searchInputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
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
  const [correlation, setCorrelation] = useState<Record<string, { loading: boolean; data?: StoryDetail }>>({});

  // storyId do servidor é um sha1(link) de 12 hex (ver newsStories.js). O
  // agrupamento do cliente (newsletterView.ts) também produz chaves sintéticas
  // ("vendor-advisory:...", "link:...") pra cards que ele mesmo agrupou — esses
  // não têm uma Story persistida no servidor pra explicar.
  const isServerStoryId = (id: string) => /^[0-9a-f]{12}$/.test(id);

  const getCorrelation = async (storyId: string): Promise<StoryDetail> => {
    const cached = correlation[storyId]?.data;
    if (cached) return cached;
    setCorrelation(p => ({ ...p, [storyId]: { loading: true } }));
    const empty: StoryDetail = { correlationEvidence: [], relatedBySeller: [] };
    try {
      const data = await fetchStoryDetail(storyId);
      setCorrelation(p => ({ ...p, [storyId]: { loading: false, data } }));
      return data;
    } catch {
      setCorrelation(p => ({ ...p, [storyId]: { loading: false, data: empty } }));
      return empty;
    }
  };

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
    if (open && card.sources.length > 1 && isServerStoryId(card.storyId) && !correlation[card.storyId]) {
      void getCorrelation(card.storyId);
    }
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
        // As técnicas que o coletor inferiu do artigo. Sem elas a coluna
        // Técnicas do Knowledge dependia do título citar "T1486", e ficava toda
        // de traço.
        techniques: [...new Set(card.sources.flatMap((source) => source.ttps ?? []))],
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
    source: selectedSource,
    kevOnly,
    sortByRelevance,
    timeRange,
  }), orgModel), [advisories, searchNews, selectedSeverity, selectedSource, sortByRelevance, kevOnly, timeRange, orgModel]);

  // Fontes disponíveis no feed atual (não no filtrado — senão escolher uma
  // fonte faria as outras desaparecerem da própria lista de opções).
  const availableSources = useMemo(
    () => [...new Set(advisories.map((item) => item.source).filter(Boolean))].sort((a, b) => a.localeCompare(b)),
    [advisories],
  );

  const [categoryFilter, setCategoryFilter] = useState("");
  // A lista de categorias cresce (9 hoje); só as com maior volume ficam à vista,
  // o resto entra por "Ver todas" — senão a barra vira duas linhas de pílula
  // toda vez que uma categoria rara aparece.
  const [showAllCategories, setShowAllCategories] = useState(false);
  const VISIBLE_CATEGORY_CAP = 5;

  const storyCards = useMemo(
    () => filterStoryCards(
      groupAdvisoriesIntoStories(filteredAdvisories, { sortByRelevance, pt: language === "pt" }),
      { category: categoryFilter, orgOnly: orgOnly && Boolean(orgModel) },
    ),
    [filteredAdvisories, sortByRelevance, orgModel, categoryFilter, orgOnly, language],
  );
  const categoryCounts = useMemo(() => countByCategory(groupAdvisoriesIntoStories(filteredAdvisories)), [filteredAdvisories]);
  // Ordenadas por volume no momento — é o que ajuda a escolher o que ler
  // primeiro; a ordem de precedência (NEWS_CATEGORY_ORDER) só decide qual
  // categoria "ganha" quando uma matéria cabe em mais de uma, não em que
  // ordem os filtros aparecem aqui.
  const categoriesByVolume = useMemo(
    () => NEWS_CATEGORY_ORDER.filter((name) => categoryCounts[name])
      .slice().sort((a, b) => categoryCounts[b] - categoryCounts[a]),
    [categoryCounts],
  );
  const visibleCategories = showAllCategories ? categoriesByVolume : categoriesByVolume.slice(0, VISIBLE_CATEGORY_CAP);
  const hiddenCategoryCount = categoriesByVolume.length - visibleCategories.length;

  // How many filters are narrowing the feed — drives the badge on the Filters button.
  const activeFilterCount = [
    selectedSeverity !== "all",
    selectedSource !== "all",
    sortByRelevance,
    kevOnly,
    orgOnly,
    timeRange !== "all",
  ].filter(Boolean).length;
  // DEN-02: o que está filtrando saía só como número no botão. Cada filtro
  // ativo vira chip removível, para o leitor ver e desfazer sem reabrir o
  // popover — e para não achar que o feed está curto quando ele está filtrado.
  const filterChips = activeFilterChips(
    { severity: selectedSeverity, source: selectedSource, kevOnly, orgOnly, sortByRelevance, search: searchNews, timeRange },
    language === "pt",
  );
  const removeFilter = (key: string) => {
    if (key === "severity") setSelectedSeverity("all");
    if (key === "source") setSelectedSource("all");
    if (key === "kevOnly") setKevOnly(false);
    if (key === "orgOnly") setOrgOnly(false);
    if (key === "sortByRelevance") setSortByRelevance(false);
    if (key === "timeRange") setTimeRange("all");
    if (key === "search") setSearchNews("");
  };
  const clearFilters = () => {
    setSelectedSeverity("all");
    setSelectedSource("all");
    setSortByRelevance(false);
    setKevOnly(false);
    setOrgOnly(false);
    setTimeRange("all");
  };

  return (
    <PageLayout width="max-w-7xl">
        <div className="space-y-6">

          {/* Page Title Row */}
          <div className="page-head">
            <div>
              <h1 className="page-title flex items-center gap-2">
                <Mail className="h-6 w-6 text-primary" />
                {language === "pt" ? "Feed de inteligência" : "Intelligence feed"}
              </h1>
              <p className="page-lede">
                {language === "pt"
                  ? "Notícias, advisories e pesquisas para acompanhar ameaças e reunir suas fontes."
                  : "News, advisories and research to follow threats and bring your sources together."}
              </p>
            </div>

            {/* Duas leituras rápidas: quando os dados ficaram velhos, e quanto
                está na tela agora — os dois números que respondem "ainda vale
                confiar nisso?" sem abrir nada. */}
            <div className="flex shrink-0 items-stretch gap-4">
              <div className="text-right">
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  {language === "pt" ? "Última atualização" : "Last update"}
                </div>
                <div
                  className="flex items-center justify-end gap-1.5 font-mono text-sm font-bold tabular-nums text-foreground"
                  title={!isRefreshingNews ? `${language === "pt" ? "Próxima em" : "Next in"} ${formatTime(secondsRemaining)}` : undefined}
                >
                  <span className={cn("h-1.5 w-1.5 rounded-full", isRefreshingNews ? "bg-primary animate-pulse" : "bg-green-500")} />
                  {isRefreshingNews
                    ? (language === "pt" ? "atualizando…" : "refreshing…")
                    : (lastUpdatedNews ? lastUpdatedNews.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—")}
                </div>
              </div>
              <div className="w-px bg-border" aria-hidden />
              <div className="text-right">
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  {language === "pt" ? "Sinais ativos" : "Active signals"}
                </div>
                <div className="font-mono text-sm font-bold tabular-nums text-primary" title={language === "pt" ? "Histórias na visão atual, já com os filtros aplicados" : "Stories in the current view, filters applied"}>
                  {storyCards.length}
                </div>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-card px-4 py-3 text-sm">
            <span className="text-muted-foreground">{monitoring.error
              ? (language === "pt" ? "Monitoramento indisponível" : "Monitoring unavailable")
              : !monitoring.data ? (language === "pt" ? "Carregando monitoramento…" : "Loading monitoring…")
              : monitoring.data.preferences.mode === "selected"
              ? (language === "pt" ? `Fornecedores monitorados: ${monitoring.data.preferences.vendorIds.length}` : `Monitored vendors: ${monitoring.data.preferences.vendorIds.length}`)
              : (language === "pt" ? "Monitoramento: todas as notícias" : "Monitoring: all news")}</span>
            <Link to="/settings?section=monitoring&from=/newsletter#news-vendors" className="font-medium text-primary hover:underline">{language === "pt" ? "Escolher fornecedores" : "Choose vendors"}</Link>
          </div>

          {/* Busca + filtros — uma barra só, um botão de filtro só: eram 4
              controles sempre à vista (severidade, período, ordenação, "mais
              filtros") competindo por espaço — agora é um Popover com tudo
              dentro, e os chips abaixo (DEN-02) continuam mostrando o que
              está ativo sem precisar abrir nada. */}
          <div className="flex flex-col gap-3 rounded-lg border bg-card p-3">
            <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  ref={searchInputRef}
                  placeholder={language === "pt" ? "Buscar por CVE, vetor, alvo..." : "Search by CVE, vector, target..."}
                  value={searchNews}
                  onChange={(e) => setSearchNews(e.target.value)}
                  className="pl-9 pr-9 bg-card border-border/50"
                />
                {!searchNews && (
                  <kbd className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                    /
                  </kbd>
                )}
              </div>

              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant={activeFilterCount > 0 ? "default" : "outline"}
                    size="sm"
                    className="h-9 shrink-0 gap-1.5 px-3 text-xs font-semibold"
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
                <PopoverContent align="start" className="w-80 space-y-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-muted-foreground">
                      {language === "pt" ? "Severidade" : "Severity"}
                    </label>
                    <div className="flex items-center gap-1 rounded-md border border-border/60 bg-background p-0.5">
                      {([
                        ["all", language === "pt" ? "Todas" : "All"],
                        ["Critical", language === "pt" ? "Críticas" : "Critical"],
                        ["High", language === "pt" ? "Alta" : "High"],
                        ["Medium", language === "pt" ? "Média" : "Medium"],
                        ["Low", language === "pt" ? "Baixa" : "Low"],
                      ] as const).map(([value, label]) => (
                        <button
                          key={value}
                          type="button"
                          onClick={() => setSelectedSeverity(value)}
                          aria-pressed={selectedSeverity === value}
                          className={cn(
                            "flex-1 rounded px-2 py-1.5 text-xs font-semibold transition-colors",
                            selectedSeverity === value ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground",
                          )}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 border-t pt-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">
                        {language === "pt" ? "Período" : "Period"}
                      </label>
                      <Select value={timeRange} onValueChange={(v) => setTimeRange(v as TimeRange)}>
                        <SelectTrigger className="h-9 w-full text-xs font-semibold">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {TIME_RANGES.map((range) => (
                            <SelectItem key={range} value={range}>
                              {range === "all" && (language === "pt" ? "Todo o período" : "All time")}
                              {range === "24h" && (language === "pt" ? "Últimas 24h" : "Last 24h")}
                              {range === "7d" && (language === "pt" ? "Últimos 7 dias" : "Last 7 days")}
                              {range === "30d" && (language === "pt" ? "Últimos 30 dias" : "Last 30 days")}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">
                        {language === "pt" ? "Ordenar por" : "Sort by"}
                      </label>
                      <Select value={sortByRelevance ? "relevance" : "recent"} onValueChange={(v) => setSortByRelevance(v === "relevance")}>
                        <SelectTrigger className="h-9 w-full text-xs font-semibold">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="recent">{language === "pt" ? "Mais recentes" : "Most recent"}</SelectItem>
                          <SelectItem value="relevance">{language === "pt" ? "Mais relevantes" : "Most relevant"}</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <Button
                    variant={kevOnly ? "default" : "outline"}
                    size="sm"
                    className={cn(
                      "h-8 w-full justify-start gap-1.5 border-t text-xs font-semibold",
                      !kevOnly && "text-red-500 border-red-500/30 hover:bg-red-500/5",
                      kevOnly && "bg-red-600 hover:bg-red-600/90 text-white",
                    )}
                    onClick={() => setKevOnly((v) => !v)}
                  >
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {language === "pt" ? "Só explorada ativamente (KEV)" : "Actively exploited only (KEV)"}
                  </Button>

                  {availableSources.length > 0 && (
                    <div className="space-y-1.5 border-t pt-3">
                      <label className="text-xs font-medium text-muted-foreground">
                        {language === "pt" ? "Fonte" : "Source"}
                      </label>
                      <select
                        value={selectedSource}
                        onChange={(event) => setSelectedSource(event.target.value)}
                        className="w-full rounded-md border bg-background px-2 py-1.5 text-xs"
                      >
                        <option value="all">{language === "pt" ? "Todas as fontes" : "All sources"}</option>
                        {availableSources.map((source) => (
                          <option key={source} value={source}>{source}</option>
                        ))}
                      </select>
                    </div>
                  )}

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
                        <input type="checkbox" checked={orgOnly} disabled={!orgModel} onChange={(event) => setOrgOnly(event.target.checked)} />
                        {language === "pt" ? "Só o meu contexto" : "My context only"}
                      </label>
                    </div>
                  )}

                  {activeFilterCount > 0 && (
                    <Button variant="ghost" size="sm" className="h-8 w-full border-t text-xs text-muted-foreground" onClick={clearFilters}>
                      {language === "pt" ? "Limpar filtros" : "Clear filters"}
                    </Button>
                  )}
                </PopoverContent>
              </Popover>

              <Button
                disabled={loadingNews || isRefreshingNews}
                onClick={() => loadNews()}
                className="h-9 shrink-0 gap-1.5 px-3 text-xs font-semibold lg:ml-auto"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", (loadingNews || isRefreshingNews) && "animate-spin")} />
                {language === "pt" ? "Atualizar agora" : "Refresh now"}
              </Button>
            </div>
          </div>

          {/* News history */}
          <div className="space-y-6">
            {/* News Feed */}
            <div className="space-y-4">
              {/* Loading/Error/News List */}
              <div className="flex flex-wrap items-center gap-2 pb-3">
                <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  {language === "pt" ? "Categorias" : "Categories"}
                </span>
                <button
                  type="button"
                  onClick={() => setCategoryFilter("")}
                  aria-pressed={categoryFilter === ""}
                  className={`rounded-full border px-3 py-1 text-xs transition ${categoryFilter === "" ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                >
                  {language === "pt" ? "Todas" : "All"}
                </button>
                {visibleCategories.map((name) => (
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
                {categoriesByVolume.length > VISIBLE_CATEGORY_CAP && (
                  <button
                    type="button"
                    onClick={() => setShowAllCategories((v) => !v)}
                    className="text-xs font-medium text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
                  >
                    {showAllCategories
                      ? (language === "pt" ? "Ver menos" : "Show less")
                      : (language === "pt" ? `Ver todas (+${hiddenCategoryCount})` : `Show all (+${hiddenCategoryCount})`)}
                  </button>
                )}
              </div>

              {/* DEN-02: os chips de categoria são o filtro primário, porque
                  carregam contagem. Abaixo deles, o que veio do popover e da
                  busca aparece como chip removível — antes só existia como
                  número dentro do botão Filtros. */}
              {!!filterChips.length && (
                <div className="mb-4 flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    {language === "pt" ? "Filtrando por" : "Filtering by"}
                  </span>
                  {filterChips.map((chip) => (
                    <button
                      key={chip.key}
                      type="button"
                      onClick={() => removeFilter(chip.key)}
                      className="inline-flex items-center gap-1 rounded-full border border-primary/40 bg-primary/10 px-2.5 py-1 text-xs text-primary transition hover:bg-primary/20"
                      aria-label={`${language === "pt" ? "Remover filtro" : "Remove filter"}: ${chip.label}`}
                    >
                      {chip.label}
                      <X className="h-3 w-3" />
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="ml-1 text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
                  >
                    {language === "pt" ? "limpar tudo" : "clear all"}
                  </button>
                </div>
              )}

              {monitoring.error ? (
                <div role="alert" className="rounded-lg border border-destructive/20 bg-destructive/5 p-6 text-center">
                  <p>{language === "pt" ? "Não foi possível carregar seu monitoramento de notícias." : "Unable to load your news monitoring."}</p>
                  <Button size="sm" variant="outline" className="mt-3" onClick={() => monitoring.refetch()}>{language === "pt" ? "Tentar novamente" : "Retry"}</Button>
                </div>
              ) : loadingNews ? (
                <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
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
                <EmptyState
                  icon={BookOpen}
                  title={monitoring.data?.preferences.mode === "selected"
                    ? (language === "pt" ? "Nenhuma notícia para sua seleção" : "No news for your selection")
                    : (language === "pt" ? "Nenhuma notícia no histórico" : "No advisories in the stored history")}
                  description={language === "pt"
                    ? "Ajuste a busca, os filtros ou os fornecedores monitorados nas configurações."
                    : "Adjust your search, filters or monitored vendors in settings."}
                  action={monitoring.data?.preferences.mode === "selected" && !advisories.length ? (
                    <Button asChild size="sm"><Link to="/settings?section=monitoring&from=/newsletter#news-vendors">{language === "pt" ? "Selecionar fornecedores" : "Select vendors"}</Link></Button>
                  ) : (
                    <Button onClick={() => loadNews()} size="sm" className="gap-2">
                      <RefreshCw className="h-3.5 w-3.5" />
                      {language === "pt" ? "Buscar notícias recentes" : "Fetch recent advisories"}
                    </Button>
                  )}
                />
              ) : (
                // Sem items-start: a grade estica os dois cards da mesma linha pra
                // bater a mesma altura — é o que reduz a variação de tamanho entre
                // um card que expandiu e o vizinho que ficou fechado.
                <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
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
                          "flex h-full flex-col rounded-lg border border-l-[3px] bg-card p-4 transition-colors hover:border-border/50",
                          accent,
                          featured && "shadow-sm ring-1 ring-primary/10",
                        )}
                      >
                        {/* Severidade e hora, com o chevron do card à direita. A seta
                            controla o corpo inteiro (sumário + fontes + ações), não um
                            pedaço: um disclosure por card em vez de um por seção. */}
                        <div className="flex flex-wrap items-center gap-2.5">
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
                          {/* EST-05: o veredito passa a vir com a prova ao lado.
                              KEV, EPSS e CVSS já viajavam no item, mas só num
                              tooltip — e ninguém abre tooltip passando os olhos
                              na lista. Card sem sinal medido não ganha etiqueta
                              nenhuma, que é a informação honesta: a severidade
                              ali veio do texto. */}
                          {severityEvidence(item, language === "pt").map((chip) => (
                            <span
                              key={chip.label}
                              className={cn(
                                "rounded border px-1.5 py-0 font-mono text-[10px] font-bold uppercase tracking-wider",
                                chip.tone === "kev"
                                  ? "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400"
                                  : "border-border text-muted-foreground",
                              )}
                            >
                              {chip.label}
                            </span>
                          ))}
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
                          {/* Fonte + prioridade + ações, sempre visíveis na linha — antes
                              a fonte só aparecia expandido, e as 4 ações (boletim, artigo,
                              compartilhar, seguir) ficavam escondidas no rodapé expandido. */}
                          <div className="ml-auto flex flex-wrap items-center justify-end gap-1.5">
                            {item.source && (
                              <span
                                className="flex shrink-0 items-center gap-1 rounded border border-border px-1.5 py-0 font-mono text-[10px] font-semibold text-muted-foreground"
                                title={
                                  typeof item.weight_boost === "number"
                                    ? `${language === "pt" ? "Prioridade da fonte" : "Source priority"}: ${item.weight_boost}/20`
                                    : undefined
                                }
                              >
                                <span className="max-w-[140px] truncate text-foreground/80">{item.source}</span>
                                {typeof item.weight_boost === "number" && (
                                  <span className="text-primary">P{item.weight_boost}</span>
                                )}
                              </span>
                            )}
                            <span className="font-mono text-xs text-muted-foreground" title={new Date(item.pubDate).toLocaleString()}>
                              {relTime(item.pubDate, language)}
                              <span className="ml-1 opacity-70">
                                ({new Date(item.pubDate).toLocaleDateString(language === "pt" ? "pt-BR" : "en-US", { day: "2-digit", month: "2-digit", year: "numeric" })})
                              </span>
                            </span>

                            <div className="flex items-center gap-0.5 border-l border-border pl-1.5">
                              <Button
                                variant="ghost" size="icon"
                                onClick={() => makeBoletim(card)}
                                disabled={boletimBusy === card.storyId}
                                title={language === "pt" ? "Gerar Boletim" : "Generate Bulletin"}
                                aria-label={language === "pt" ? "Gerar Boletim" : "Generate Bulletin"}
                                className="h-7 w-7 text-muted-foreground hover:text-foreground"
                              >
                                {boletimBusy === card.storyId
                                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  : <PencilLine className="h-3.5 w-3.5" />}
                              </Button>
                              <Button
                                asChild variant="ghost" size="icon"
                                title={language === "pt" ? "Ver artigo" : "Read article"}
                                className="h-7 w-7 text-muted-foreground hover:text-foreground"
                              >
                                <a href={item.link} target="_blank" rel="noopener noreferrer" aria-label={language === "pt" ? "Ver artigo" : "Read article"}>
                                  <ExternalLink className="h-3.5 w-3.5" />
                                </a>
                              </Button>
                              <Button
                                variant="ghost" size="icon"
                                onClick={() => shareAdvisory(card)}
                                title={language === "pt" ? "Compartilhar" : "Share"}
                                aria-label={language === "pt" ? "Compartilhar" : "Share"}
                                className="h-7 w-7 text-muted-foreground hover:text-foreground"
                              >
                                <Share2 className="h-3.5 w-3.5" />
                              </Button>
                              <Button
                                variant="ghost" size="icon"
                                onClick={() => keepAdvisory(card)}
                                disabled={savedLinks.has(item.link)}
                                title={savedLinks.has(item.link)
                                  ? (language === "pt" ? "Seguindo" : "Following")
                                  : (language === "pt" ? "Seguir" : "Follow")}
                                aria-label={savedLinks.has(item.link)
                                  ? (language === "pt" ? "Seguindo" : "Following")
                                  : (language === "pt" ? "Seguir" : "Follow")}
                                className="h-7 w-7 text-muted-foreground hover:text-foreground"
                              >
                                <Bookmark className={cn("h-3.5 w-3.5", savedLinks.has(item.link) && "fill-current text-primary")} />
                              </Button>
                            </div>

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
                        </div>

                        {/* Só a manchete grande recebe o título normalizado e traduzido
                            pela análise. Os títulos das fontes ficam como o veículo
                            publicou — é por eles que o analista reencontra a matéria
                            depois, e traduzir quebraria a busca. */}
                        <h3 className={cn("mt-2 line-clamp-2 font-bold text-foreground", featured ? "text-lg leading-snug" : "text-base leading-snug")}>
                          <a href={item.link} target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">
                            {enr?.title || card.title}
                          </a>
                        </h3>

                        {/* Prévia do resumo que o próprio feed RSS já manda — só
                            quando existe (bastante fonte não traz nenhum) e só
                            fechado: expandido, o painel abaixo já mostra o texto
                            inteiro (ou o resumo da análise, quando houver). */}
                        {!isExpanded(card, featured) && item.description?.trim() && (
                          <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
                            {item.description}
                          </p>
                        )}

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

                                {/* Por que o servidor juntou estas fontes numa história só —
                                    só existe pra storyId real (o sintético do agrupamento do
                                    cliente não tem Story persistida pra explicar). Buscado sob
                                    demanda no toggleExpand, não no feed plano. */}
                                {isServerStoryId(card.storyId) && (
                                  correlation[card.storyId]?.loading ? (
                                    <div className="mt-2 text-[11px] text-muted-foreground">
                                      {language === "pt" ? "Calculando correlação…" : "Computing correlation…"}
                                    </div>
                                  ) : (
                                    <>
                                      {(correlation[card.storyId]?.data?.correlationEvidence ?? []).length > 0 && (
                                        <div className="mt-2 flex flex-wrap gap-1.5">
                                          {correlation[card.storyId]!.data!.correlationEvidence.map((ev, i) => (
                                            <span
                                              key={`${ev.type}-${ev.value}-${i}`}
                                              title={ev.sourceLinks.join(", ")}
                                              className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400"
                                            >
                                              <CheckCircle2 className="h-3 w-3" />
                                              {EVIDENCE_LABEL[ev.type]?.[language === "pt" ? "pt" : "en"] ?? ev.type}: {ev.value}
                                            </span>
                                          ))}
                                        </div>
                                      )}
                                      {/* Mesmo vendedor de dark web em outra história — relacionado,
                                          nunca fundido: vítimas diferentes continuam sendo notícias
                                          diferentes (ver server/darkWebHandle.js). */}
                                      {(correlation[card.storyId]?.data?.relatedBySeller ?? []).length > 0 && (
                                        <div className="mt-2 flex flex-wrap gap-1.5">
                                          {correlation[card.storyId]!.data!.relatedBySeller.map((rel) => (
                                            <a
                                              key={rel.storyId}
                                              href={rel.link ?? undefined}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              title={rel.title}
                                              className="inline-flex max-w-[280px] items-center gap-1 rounded-full border border-border px-2 py-0.5 text-[11px] text-muted-foreground hover:border-primary/40 hover:text-foreground"
                                            >
                                              <span className="shrink-0">{language === "pt" ? "Mesmo vendedor:" : "Same seller:"}</span>
                                              <span className="truncate">{rel.title}</span>
                                            </a>
                                          ))}
                                        </div>
                                      )}
                                    </>
                                  )
                                )}

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
