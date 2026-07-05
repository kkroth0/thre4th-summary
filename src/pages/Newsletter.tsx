import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, BookOpen, AlertTriangle, Search, Mail, Eye, Sparkles, Filter, CheckCircle2, ChevronLeft, ChevronRight, ChevronDown, Download, Layers, RefreshCw, Calendar, Share2, Loader2, Crosshair, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import FeedSourcesManager from "@/components/FeedSourcesManager";
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
  layer?: number;
  titlePt?: string;
  descriptionPt?: string;
  // CTI relevance enrichment (from the specialized collector)
  score?: number;
  severity?: string; // Critical | High | Medium | Low
  categories?: string[];
  cves?: string[];
  cvss?: number | null;
  reasons?: string[]; // why it scored — surfaced as a tooltip
  // Active-exploitation correlation
  kev?: boolean;
  kevDetails?: KevDetails;
  epss?: number; // 0-1 exploit probability
  // Deterministic actionable enrichment
  threats?: string[];
  sectors?: string[];
  ttps?: string[];
  assets?: string[];
  iocs?: IocSet;
}

const SEVERITY_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-slate-400",
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
  source?: string; // groq | translate | rss
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

// Guided Threat Hunting pack, produced by the Python hunt-service (Groq +
// Pydantic) and proxied through /api/newsletter/hunt-pack. Every IOC arrives
// already defanged from the service.
interface HuntIoc {
  type: "ip" | "domain" | "url" | "hash";
  value: string;
}
interface HuntDetectionQuery {
  kql: string;
  sigma?: string;
}
interface HuntPackData {
  available: boolean;
  scraped_chars?: number;
  lang?: string;
  threat_actor: string;
  ttp_mitre: string[];
  ioc_list: HuntIoc[];
  hunting_hypothesis: string;
  detection_query: HuntDetectionQuery;
  executive_brief: string;
  soc_summary: string;
}

// True when an IOC set carries at least one indicator.
const hasIocs = (i?: IocSet | null): boolean =>
  !!i && [(i.ips), (i.domains), (i.hashes), (i.urls)].some((a) => (a?.length ?? 0) > 0);

// Defang an indicator for safe copy/paste/export (1.2.3.4 -> 1.2.3[.]4).
const defang = (s: string): string =>
  s.replace(/^http/i, "hxxp").replace(/\./g, "[.]");

// Flatten an IOC set into [type, value] rows (values defanged for safety).
const iocRows = (i: IocSet): Array<[string, string]> => [
  ...(i.hashes ?? []).map((v) => ["hash", v] as [string, string]),
  ...(i.ips ?? []).map((v) => ["ip", defang(v)] as [string, string]),
  ...(i.domains ?? []).map((v) => ["domain", defang(v)] as [string, string]),
  ...(i.urls ?? []).map((v) => ["url", defang(v)] as [string, string]),
];

// Prefer the richer full-article enrichment, fall back to the collection-time item
const mergedField = (item: Advisory, e: EnrichData | undefined, key: "threats" | "sectors" | "ttps" | "assets" | "cves"): string[] =>
  (e?.[key]?.length ? e[key] : item[key]) ?? [];

// Build a well-organized, shareable text block (mirrors the SOC bot card layout)
const buildShareText = (item: Advisory, e: EnrichData | undefined, lang: string): string => {
  const isPt = lang === "pt";
  const out: string[] = [];
  out.push(`🚨 ${(e?.title || item.titlePt || item.title || "").trim()}`);
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

const translateText = async (text: string): Promise<string> => {
  if (!text) return "";
  const textToTranslate = text.length > 500 ? text.substring(0, 500) : text;
  try {
    const res = await fetch(`https://api.mymemory.translated.net/get?q=${encodeURIComponent(textToTranslate)}&langpair=en|pt`);
    if (!res.ok) return text;
    const data = await res.json();
    let translated = data.responseData?.translatedText || text;
    if (text.length > 500) {
      translated += "...";
    }
    return translated;
  } catch (err) {
    console.error("Translation error:", err);
    return text;
  }
};

const Newsletter = () => {
  const { t, language } = useLanguage();
  
  // Newsletter States
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [searchNews, setSearchNews] = useState("");
  const [selectedNews, setSelectedNews] = useState<Record<string, boolean>>({});
  const [loadingNews, setLoadingNews] = useState(true);
  const [newsError, setNewsError] = useState<string | null>(null);
  const [translatingIds, setTranslatingIds] = useState<Record<string, boolean>>({});
  const [isDigestOpen, setIsDigestOpen] = useState(false);
  const [selectedLayer, setSelectedLayer] = useState<string>("all");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [sortByRelevance, setSortByRelevance] = useState<boolean>(false);
  const [kevOnly, setKevOnly] = useState<boolean>(false);

  // Calendar Month Selector States
  const [selectedMonth, setSelectedMonth] = useState<number>(new Date().getMonth());
  const [selectedYear, setSelectedYear] = useState<number>(new Date().getFullYear());

  const monthNames = [
    "January", "February", "March", "April", "May", "June", 
    "July", "August", "September", "October", "November", "December"
  ];
  const monthNamesPt = [
    "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"
  ];

  const handlePrevMonth = () => {
    setSelectedMonth(prev => {
      if (prev === 0) {
        setSelectedYear(y => y - 1);
        return 11;
      }
      return prev - 1;
    });
  };

  const handleNextMonth = () => {
    setSelectedMonth(prev => {
      if (prev === 11) {
        setSelectedYear(y => y + 1);
        return 0;
      }
      return prev + 1;
    });
  };

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
            layer: typeof item.layer === "number" ? item.layer : undefined,
            titlePt: typeof item.titlePt === "string" ? (item.titlePt as string) : undefined,
            descriptionPt: typeof item.descriptionPt === "string" ? (item.descriptionPt as string) : undefined,
            score: typeof item.score === "number" ? item.score : undefined,
            severity: typeof item.severity === "string" ? (item.severity as string) : undefined,
            categories: Array.isArray(item.categories) ? (item.categories as string[]) : undefined,
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
              if (merged[index].titlePt && !item.titlePt) item.titlePt = merged[index].titlePt;
              if (merged[index].descriptionPt && !item.descriptionPt) item.descriptionPt = merged[index].descriptionPt;
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
                className="mx-1 font-mono text-[11px] font-bold bg-primary/10 text-primary border-primary/20 hover:bg-primary/20 cursor-pointer transition-colors scale-95"
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

  // Toggle selection for a news item
  const toggleSelectNews = (title: string) => {
    setSelectedNews(prev => ({
      ...prev,
      [title]: !prev[title]
    }));
  };

  // Select all / Deselect all
  const selectAllVisibleNews = (visibleItems: Advisory[]) => {
    const allSelected = visibleItems.every(item => selectedNews[item.title]);
    const nextState: Record<string, boolean> = { ...selectedNews };
    visibleItems.forEach(item => {
      nextState[item.title] = !allSelected;
    });
    setSelectedNews(nextState);
  };

  // Trigger Pivot Search on main dashboard
  const handlePivotSearch = (cveId: string) => {
    localStorage.setItem("pivotSearchQuery", cveId);
    toast.success(language === "pt" ? `Pesquisando ${cveId} no painel...` : `Searching ${cveId} on main dashboard...`);
    window.location.href = "/";
  };

  // Print Compiled PDF / Print Document
  const handlePrintDigest = () => {
    const printWindow = window.open("", "_blank");
    if (!printWindow) return;
    const content = document.getElementById("compiled-digest-preview")?.innerHTML || "";
    printWindow.document.write(`
      <html>
        <head>
          <title>ThreatSumm4ry - CTI Digest</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #0f172a; background-color: #ffffff; }
            h1 { color: #6366f1; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; margin-bottom: 20px; font-size: 24px; font-weight: 800; text-transform: uppercase; tracking: 0.05em; }
            h2 { color: #1e293b; margin-top: 30px; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px; font-size: 18px; }
            .meta { color: #64748b; font-size: 12px; margin-bottom: 20px; }
            .advisory { margin-bottom: 24px; padding: 18px; border: 1px solid #e2e8f0; border-radius: 8px; }
            .source { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; background-color: #f1f5f9; color: #475569; margin-bottom: 8px; }
            .source-cisa { background-color: #fee2e2; color: #b91c1c; }
            .source-bleeping { background-color: #dbeafe; color: #1d4ed8; }
            .source-hacker { background-color: #fef3c7; color: #b45309; }
            .title { font-weight: bold; font-size: 16px; margin-bottom: 6px; color: #0f172a; }
            .date { color: #94a3b8; font-size: 11px; margin-bottom: 10px; }
            .description { font-size: 13px; line-height: 1.6; color: #334155; white-space: pre-line; }
            .sev { display: inline-block; margin-left: 6px; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; background-color: #fee2e2; color: #b91c1c; }
            .kv { font-size: 12px; color: #334155; margin: 2px 0; }
            .kv strong { color: #0f172a; }
            .section { font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; color: #6366f1; margin-top: 12px; margin-bottom: 4px; }
            .ttp-block ul { margin: 0; padding-left: 18px; }
            .ttp-block li { font-size: 12px; color: #334155; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
            .footer { margin-top: 50px; font-size: 10px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 15px; text-align: center; }
          </style>
        </head>
        <body>
          ${content}
          <div class="footer">Generated by ThreatSumm4ry - Advanced Threat Intelligence Platform</div>
          <script>
            window.onload = function() { window.print(); window.close(); }
          </script>
        </body>
      </html>
    `);
    printWindow.document.close();
  };

  // ── Actionable analysis: expand + lazy LLM enrichment + share ──
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [enrichment, setEnrichment] = useState<Record<string, { loading: boolean; data?: EnrichData }>>({});

  const getEnrichment = async (item: Advisory): Promise<EnrichData> => {
    const cached = enrichment[item.link]?.data;
    if (cached) return cached;
    setEnrichment(p => ({ ...p, [item.link]: { loading: true } }));
    try {
      const res = await fetch("/api/newsletter/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: item.link, lang: language }),
      });
      if (!res.ok) throw new Error("enrich failed");
      const data: EnrichData = await res.json();
      setEnrichment(p => ({ ...p, [item.link]: { loading: false, data } }));
      return data;
    } catch {
      const fallback: EnrichData = { available: false, executiveSummary: item.description, impactMitigation: "" };
      setEnrichment(p => ({ ...p, [item.link]: { loading: false, data: fallback } }));
      return fallback;
    }
  };

  // ── Guided Threat Hunting: on-demand, never auto-fetched (it's expensive:
  // browser scrape + LLM + validation retries, and the free host may cold-start).
  const [huntPacks, setHuntPacks] = useState<Record<string, { loading: boolean; error?: string; data?: HuntPackData }>>({});

  const getHuntPack = async (item: Advisory) => {
    if (huntPacks[item.link]?.loading) return;
    setHuntPacks(p => ({ ...p, [item.link]: { loading: true } }));
    try {
      const res = await fetch("/api/newsletter/hunt-pack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: item.link, lang: language }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = res.status === 503
          ? (language === "pt" ? "Serviço de threat hunting não configurado" : "Threat hunting service not configured")
          : (body?.error || (language === "pt" ? "Falha ao gerar o Hunt Pack" : "Failed to generate Hunt Pack"));
        throw new Error(msg);
      }
      setHuntPacks(p => ({ ...p, [item.link]: { loading: false, data: body as HuntPackData } }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : (language === "pt" ? "Falha ao gerar o Hunt Pack" : "Failed to generate Hunt Pack");
      setHuntPacks(p => ({ ...p, [item.link]: { loading: false, error: msg } }));
    }
  };

  const toggleExpand = (item: Advisory) => {
    setExpanded(p => {
      const open = !p[item.link];
      if (open && !enrichment[item.link]) void getEnrichment(item);
      return { ...p, [item.link]: open };
    });
  };

  const shareAdvisory = async (item: Advisory) => {
    const data = enrichment[item.link]?.data ?? (await getEnrichment(item));
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

  // Filter Advisories / News
  const filteredAdvisories = useMemo(() => {
    const filtered = advisories.filter(item => {
      // 1. Month/Year filter
      const d = new Date(item.pubDate);
      if (d.getMonth() !== selectedMonth || d.getFullYear() !== selectedYear) {
        return false;
      }

      // 2. Search Text filter
      const matchesSearch =
        (item.title ?? '').toLowerCase().includes(searchNews.toLowerCase()) ||
        (item.description ?? '').toLowerCase().includes(searchNews.toLowerCase()) ||
        (item.source ?? '').toLowerCase().includes(searchNews.toLowerCase());

      if (!matchesSearch) return false;

      // 3. Severity filter (CTI relevance)
      if (selectedSeverity !== "all" && item.severity !== selectedSeverity) return false;

      // 3b. KEV-only filter (actively exploited)
      if (kevOnly && !item.kev) return false;

      // 4. Layer filter
      if (selectedLayer === "l1" && item.layer !== 1) return false;
      if (selectedLayer === "l2" && item.layer !== 2) return false;
      // L3 captures research labs (3) and LATAM/BR regional (4)
      if (selectedLayer === "l3" && (item.layer ?? 0) < 3) return false;

      return true;
    });

    // 5. Ordering: relevance (score) or recency
    return sortByRelevance
      ? [...filtered].sort((a, b) => (b.score ?? 0) - (a.score ?? 0) || new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
      : filtered;
  }, [advisories, selectedMonth, selectedYear, searchNews, selectedLayer, selectedSeverity, sortByRelevance, kevOnly]);

  useEffect(() => {
    if (language !== "pt") return;

    const toTranslate = filteredAdvisories.filter(
      item => !item.titlePt || !item.descriptionPt
    );

    if (toTranslate.length === 0) return;

    let active = true;

    const performTranslations = async () => {
      const itemsToProcess = toTranslate.slice(0, 5);

      for (const item of itemsToProcess) {
        if (!active) break;
        
        const key = item.title;
        setTranslatingIds(prev => ({ ...prev, [key]: true }));

        try {
          const [transTitle, transDesc] = await Promise.all([
            item.titlePt ? Promise.resolve(item.titlePt) : translateText(item.title),
            item.descriptionPt ? Promise.resolve(item.descriptionPt) : translateText(item.description)
          ]);

          if (!active) break;

          setAdvisories(prev => {
            const updated = prev.map(adv => {
              if (adv.title === item.title && adv.source === item.source) {
                return {
                  ...adv,
                  titlePt: transTitle || item.title,
                  descriptionPt: transDesc || item.description
                };
              }
              return adv;
            });
            localStorage.setItem("cached_cti_advisories", JSON.stringify(updated));
            return updated;
          });
        } catch (e) {
          console.error("Failed to translate advisory", item.title, e);
        } finally {
          setTranslatingIds(prev => {
            const next = { ...prev };
            delete next[key];
            return next;
          });
        }
      }
    };

    performTranslations();

    return () => {
      active = false;
    };
  }, [language, filteredAdvisories]);

  const selectedCount = Object.values(selectedNews).filter(Boolean).length;
  const selectedAdvisoriesList = advisories.filter(item => selectedNews[item.title]);

  // How many filters are narrowing the feed — drives the badge on the Filters button.
  const activeFilterCount = [
    selectedLayer !== "all",
    selectedSeverity !== "all",
    sortByRelevance,
    kevOnly,
  ].filter(Boolean).length;
  const clearFilters = () => {
    setSelectedLayer("all");
    setSelectedSeverity("all");
    setSortByRelevance(false);
    setKevOnly(false);
  };

  // Pre-load the LLM analysis for selected items when the digest opens, so the
  // exported PDF includes the Executive Summary + Impact & Mitigation.
  useEffect(() => {
    if (!isDigestOpen) return;
    selectedAdvisoriesList.forEach(item => {
      if (!enrichment[item.link]) void getEnrichment(item);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isDigestOpen]);

  return (
    <PageLayout width="max-w-7xl">
        <div className="space-y-6">

          {/* Page Title Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Mail className="h-6 w-6 text-primary" />
                {language === "pt" ? "Coletor de Intel" : "Intel Collector"}
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
              <FeedSourcesManager />
            </div>
          </div>

          {/* Calendar Month Selector Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-card border rounded-lg p-2.5">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="icon"
                className="h-9 w-9 rounded-md shrink-0"
                onClick={handlePrevMonth}
                title={language === "pt" ? "Mês Anterior" : "Previous Month"}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <div className="flex items-center gap-2 px-2 shrink-0">
                <Calendar className="h-4 w-4 text-primary" />
                <span className="text-sm font-bold text-foreground font-mono whitespace-nowrap min-w-[130px] text-center">
                  {language === "pt" ? monthNamesPt[selectedMonth] : monthNames[selectedMonth]} {selectedYear}
                </span>
              </div>
              <Button
                variant="outline"
                size="icon"
                className="h-9 w-9 rounded-md shrink-0"
                onClick={handleNextMonth}
                title={language === "pt" ? "Próximo Mês" : "Next Month"}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>

            {/* Quick Month Select Dropdown */}
            <div className="flex items-center gap-2.5 w-full sm:w-auto">
              <Select value={selectedMonth.toString()} onValueChange={(val) => setSelectedMonth(parseInt(val))}>
                <SelectTrigger className="h-9 w-full sm:w-[130px] rounded-md text-xs font-semibold">
                  <SelectValue placeholder={language === "pt" ? "Mês" : "Month"} />
                </SelectTrigger>
                <SelectContent className="max-h-60 border-primary/10 bg-popover/95 backdrop-blur-md rounded-xl">
                  {(language === "pt" ? monthNamesPt : monthNames).map((name, idx) => (
                    <SelectItem key={idx} value={idx.toString()} className="text-xs rounded-lg">
                      {name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={selectedYear.toString()} onValueChange={(val) => setSelectedYear(parseInt(val))}>
                <SelectTrigger className="h-9 w-full sm:w-[95px] rounded-md text-xs font-semibold">
                  <SelectValue placeholder={language === "pt" ? "Ano" : "Year"} />
                </SelectTrigger>
                <SelectContent className="border-primary/10 bg-popover/95 backdrop-blur-md rounded-xl">
                  {["2024", "2025", "2026", "2027"].map(year => (
                    <SelectItem key={year} value={year} className="text-xs rounded-lg">
                      {year}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Search, Layer Filter, and Action Bar at the Top */}
          <div className="flex flex-col xl:flex-row gap-3 bg-card border p-3 rounded-lg">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t("searchAdvisories") || "Search advisories..."}
                value={searchNews}
                onChange={(e) => setSearchNews(e.target.value)}
                className="pl-9 bg-card border-primary/10"
              />
            </div>
            
            {/* Feed Layers pill filter group & Actions */}
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
                  {/* Layer */}
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                      {language === "pt" ? "Camada" : "Layer"}
                    </div>
                    <div className="grid grid-cols-2 gap-1.5">
                      {[
                        { k: "all", label: language === "pt" ? "Todos" : "All", dot: "" },
                        { k: "l1", label: "L1 · PSIRT", dot: "bg-red-500" },
                        { k: "l2", label: "L2 · CTI", dot: "bg-amber-500" },
                        { k: "l3", label: "L3 · Research/BR", dot: "bg-blue-500" },
                      ].map((o) => (
                        <Button
                          key={o.k}
                          variant={selectedLayer === o.k ? "default" : "outline"}
                          size="sm"
                          className="h-8 justify-start text-xs font-semibold gap-1.5"
                          onClick={() => setSelectedLayer(o.k)}
                        >
                          {o.dot && <span className={`h-2 w-2 rounded-full ${o.dot}`} />}
                          {o.label}
                        </Button>
                      ))}
                    </div>
                  </div>

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

                  {activeFilterCount > 0 && (
                    <Button variant="ghost" size="sm" className="h-8 w-full text-xs text-muted-foreground" onClick={clearFilters}>
                      {language === "pt" ? "Limpar filtros" : "Clear filters"}
                    </Button>
                  )}
                </PopoverContent>
              </Popover>

              <div className="h-4 w-px bg-border/60 mx-1 shrink-0" />

              <Button
                variant="outline"
                size="sm"
                onClick={() => selectAllVisibleNews(filteredAdvisories)}
                className="h-9 text-xs gap-1.5 border-primary/20 hover:bg-primary/5 shrink-0"
              >
                <Filter className="h-3.5 w-3.5" />
                {filteredAdvisories.every(item => selectedNews[item.title])
                  ? (language === "pt" ? "Desmarcar Todos" : "Deselect All")
                  : (language === "pt" ? "Selecionar Visíveis" : "Select Visible")}
              </Button>
              <Button
                variant="outline"
                size="icon"
                disabled={loadingNews || isRefreshingNews}
                onClick={() => loadNews()}
                className="h-9 w-9 border-primary/20 hover:bg-primary/5 shrink-0"
                title={language === "pt" ? "Atualizar feeds" : "Refresh feeds"}
              >
                <RefreshCw className={`h-4 w-4 ${(loadingNews || isRefreshingNews) ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </div>

          {/* Main Layout - Digest Builder at the top, then News Feed full width */}
          <div className="space-y-6">
            
            {/* Top Banner: Digest Builder Tool */}
            <Card className="border bg-card">
              <CardContent className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="p-2 rounded-md bg-primary/10 text-primary shrink-0">
                    <Layers className="h-5 w-5" />
                  </div>
                  <div className="space-y-0.5 min-w-0">
                    <CardTitle className="text-sm flex items-center gap-2">
                      {t("generateWeeklyDigest") || "Generate Weekly Digest"}
                      <Badge variant={selectedCount > 0 ? "default" : "secondary"} className="text-[10px]">
                        {selectedCount} {language === "pt" ? "selecionados" : "selected"}
                      </Badge>
                    </CardTitle>
                    <CardDescription className="text-xs max-w-2xl truncate">
                      {t("selectForDigest") || "Select security articles from the feed to compile a report"}
                    </CardDescription>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-3 w-full md:w-auto">
                  <Dialog open={isDigestOpen} onOpenChange={setIsDigestOpen}>
                    <DialogTrigger asChild>
                      <Button
                        className="w-full md:w-auto gap-2 text-xs h-9 px-4"
                        disabled={selectedCount === 0}
                      >
                        <Sparkles className="h-4 w-4" />
                        {t("generateWeeklyDigest") || "Generate weekly digest"}
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col p-6">
                      <DialogHeader className="border-b pb-4">
                        <DialogTitle className="text-lg font-bold flex items-center gap-2">
                          <Sparkles className="h-5 w-5 text-primary" />
                          {t("weeklyDigestTitle") || "Threat Weekly Digest"}
                        </DialogTitle>
                      </DialogHeader>

                      <div className="flex-1 overflow-y-auto pr-1 py-4">
                        {/* Compiled newsletter template print container */}
                        <div id="compiled-digest-preview" className="space-y-6 text-slate-800 dark:text-slate-100 p-4 border rounded-lg bg-card">
                          <h1>{t("weeklyDigestTitle") || "Weekly Threat Digest"}</h1>
                          <p className="meta">
                            <strong>Date:</strong> {new Date().toLocaleDateString()}<br />
                            <strong>Source:</strong> ThreatSumm4ry Platform Aggregator
                          </p>
                          
                          <p className="description text-sm leading-relaxed text-muted-foreground">
                            {language === "pt"
                              ? "Este documento é um sumário compilado de inteligência contra ameaças digitais coletado e estruturado a partir de múltiplas fontes de segurança cibernética públicas e privadas."
                              : "This document contains compiled cyber threat intelligence alerts curated and structured from various security feeds and vendor advisories."}
                          </p>

                          <div className="space-y-4">
                            {selectedAdvisoriesList.map((item, idx) => {
                              const e = enrichment[item.link]?.data;
                              return (
                              <div key={idx} className="advisory p-4 border rounded-lg space-y-2 bg-card">
                                <span className={`source text-xs font-bold px-2 py-0.5 rounded ${
                                  item.source.toLowerCase().includes("cisa")
                                    ? "bg-red-500/15 text-red-500"
                                    : item.source.toLowerCase().includes("bleeping")
                                    ? "bg-blue-500/15 text-blue-500"
                                    : "bg-amber-500/15 text-amber-500"
                                }`}>
                                  {item.source}
                                </span>
                                {item.severity && <span className="sev">{item.severity}{typeof item.score === "number" ? ` · ${item.score}` : ""}</span>}
                                <div className="title font-bold text-base text-foreground">{e?.title || (language === "pt" ? (item.titlePt || item.title) : item.title)}</div>
                                <div className="date text-xs text-muted-foreground">{new Date(item.pubDate).toLocaleString()}</div>
                                {mergedField(item, e, "assets").length ? <div className="kv"><strong>Monitored Assets:</strong> {mergedField(item, e, "assets").join(", ")}</div> : null}
                                {mergedField(item, e, "threats").length ? <div className="kv"><strong>Threats:</strong> {mergedField(item, e, "threats").join(", ")}</div> : null}
                                {mergedField(item, e, "sectors").length ? <div className="kv"><strong>Targeted Sectors:</strong> {mergedField(item, e, "sectors").join(", ")}</div> : null}
                                {mergedField(item, e, "ttps").length ? (
                                  <div className="ttp-block">
                                    <div className="section">[ MITRE ATT&CK ]</div>
                                    <ul>{mergedField(item, e, "ttps").map((tp) => <li key={tp}>{tp}</li>)}</ul>
                                  </div>
                                ) : null}
                                <div className="section">[ {language === "pt" ? "Resumo Executivo" : "Executive Summary"} ]</div>
                                <div className="description text-sm text-muted-foreground leading-relaxed whitespace-pre-line">{e?.executiveSummary || renderHighlightedDescription(language === "pt" ? (item.descriptionPt || item.description) : item.description)}</div>
                                {e?.impactMitigation ? (
                                  <>
                                    <div className="section">[ {language === "pt" ? "Impacto & Mitigação" : "Impact & Mitigation"} ]</div>
                                    <div className="description text-sm text-muted-foreground leading-relaxed whitespace-pre-line">{e.impactMitigation}</div>
                                  </>
                                ) : null}
                                {mergedField(item, e, "cves").length ? <div className="kv"><strong>Related CVEs:</strong> {mergedField(item, e, "cves").join(", ")}</div> : null}
                              </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between border-t pt-4 mt-2">
                        <Button variant="ghost" onClick={() => setIsDigestOpen(false)}>
                          {language === "pt" ? "Fechar" : "Close"}
                        </Button>
                        <Button className="gap-2" onClick={handlePrintDigest}>
                          <Download className="h-4 w-4" />
                          {t("downloadDigest") || "Download Digest"}
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </CardContent>
            </Card>

            {/* News Feed */}
            <div className="space-y-4">
              {/* Loading/Error/News List */}
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
              ) : filteredAdvisories.length === 0 ? (
                <div className="p-12 border border-dashed rounded-lg text-center bg-card space-y-4">
                  <BookOpen className="h-12 w-12 text-muted-foreground/50 mx-auto mb-3" />
                  <div>
                    <p className="text-muted-foreground font-medium">{language === "pt" ? "Nenhuma notícia encontrada para este mês no cache local" : "No threat advisories found for this month in local cache"}</p>
                    <p className="text-xs text-muted-foreground mt-1">{language === "pt" ? "Você pode buscar as notícias mais recentes do servidor para popular o cache" : "Try fetching the latest feed from the server or choose another month"}</p>
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
                  {filteredAdvisories.map((item, idx) => {
                    const enr = enrichment[item.link]?.data;
                    const mCves = mergedField(item, enr, "cves");
                    // Prefer the richer full-article IOCs (enrich) over the
                    // lightweight collection-time set.
                    const mIocs: IocSet | undefined = hasIocs(enr?.iocs) ? (enr?.iocs ?? undefined) : item.iocs;
                    const isCisa = item.source.toLowerCase().includes("cisa");
                    const isBleeping = item.source.toLowerCase().includes("bleeping");
                    // Magazine layout: the first item (top of the current sort —
                    // highest relevance or newest) renders as the featured story.
                    const featured = idx === 0;
                    const accent = item.severity ? (SEVERITY_ACCENT[item.severity] || SEVERITY_ACCENT.Low) : "border-l-transparent";

                    return (
                      <div
                        key={idx}
                        className={`rounded-lg border border-l-[3px] bg-card transition-colors flex items-start gap-3 ${accent} ${
                          featured ? "p-5 shadow-sm ring-1 ring-primary/10" : "p-3"
                        } ${
                          selectedNews[item.title] ? "border-primary/50 bg-primary/5" : "hover:border-primary/30"
                        }`}
                      >
                        <Checkbox
                          checked={!!selectedNews[item.title]}
                          onCheckedChange={() => toggleSelectNews(item.title)}
                          className="mt-1"
                        />

                        <div className="flex-1 min-w-0 space-y-1.5">
                          <div className="flex items-center gap-2 flex-wrap text-xs">
                            {featured && (
                              <Badge className="text-[10px] font-bold gap-1 bg-primary text-primary-foreground">
                                <Sparkles className="h-3 w-3" />
                                {language === "pt" ? "Destaque" : "Top story"}
                              </Badge>
                            )}
                            {item.severity && (
                              <span
                                title={item.reasons?.length ? `${language === "pt" ? "Por quê" : "Why"}: ${item.reasons.join(" · ")}` : undefined}
                                className={`inline-flex items-center gap-1.5 font-semibold ${item.reasons?.length ? "cursor-help" : ""}`}
                              >
                                <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT[item.severity] || SEVERITY_DOT.Low}`} />
                                {item.severity}
                                {typeof item.score === "number" && <span className="font-normal text-muted-foreground">{item.score}</span>}
                              </span>
                            )}
                            <span className={`font-medium ${isCisa ? "text-red-500" : isBleeping ? "text-blue-500" : "text-amber-500"}`}>
                              {item.source}
                            </span>
                            {item.kev && (
                              <Badge
                                variant="outline"
                                title={item.kevDetails ? `CISA KEV · ${item.kevDetails.cve}${item.kevDetails.dateAdded ? ` · ${language === "pt" ? "adicionado" : "added"} ${item.kevDetails.dateAdded}` : ""}${item.kevDetails.ransomware ? " · ransomware" : ""}` : "CISA KEV"}
                                className="text-[10px] font-bold bg-red-600/15 text-red-500 border-red-600/30 cursor-help"
                              >
                                {language === "pt" ? "Explorado" : "Exploited"}
                                {typeof item.epss === "number" && <span className="ml-1 opacity-80">EPSS {Math.round(item.epss * 100)}%</span>}
                              </Badge>
                            )}
                            {!item.kev && typeof item.epss === "number" && item.epss >= 0.5 && (
                              <Badge
                                variant="outline"
                                title={language === "pt" ? "Probabilidade de exploração (FIRST EPSS) nos próximos 30 dias" : "Exploit probability (FIRST EPSS) over the next 30 days"}
                                className="text-[10px] font-bold bg-orange-500/10 text-orange-500 border-orange-500/20 cursor-help"
                              >
                                EPSS {Math.round(item.epss * 100)}%
                              </Badge>
                            )}
                            {(item.cves ?? []).slice(0, 3).map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="font-mono font-semibold text-primary hover:underline"
                              >
                                {cve}
                              </a>
                            ))}
                            <span className="text-muted-foreground ml-auto tabular-nums shrink-0" title={new Date(item.pubDate).toLocaleString()}>
                              {relTime(item.pubDate, language)}
                            </span>
                          </div>
                          
                          <h3 className={`font-semibold text-foreground hover:text-primary transition-colors flex items-center gap-2 flex-wrap ${featured ? "text-lg md:text-xl leading-snug" : "text-[15px]"}`}>
                            <a href={item.link} target="_blank" rel="noopener noreferrer">
                              {language === "pt" ? (item.titlePt || item.title) : item.title}
                            </a>
                            {translatingIds[item.title] && (
                              <Badge variant="outline" className="text-[9px] px-1.5 py-px bg-purple-500/10 text-purple-400 border-purple-500/20 font-medium tracking-wide animate-pulse">
                                <RefreshCw className="h-2 w-2 animate-spin mr-1 inline" />
                                Traduzindo...
                              </Badge>
                            )}
                            {language === "pt" && item.titlePt && !translatingIds[item.title] && (
                              <Badge variant="outline" className="text-[9px] px-1.5 py-px bg-purple-500/5 text-purple-400 border-purple-500/15 font-normal tracking-wide">
                                Traduzido
                              </Badge>
                            )}
                          </h3>

                          {/* Featured story gets a short teaser under the headline */}
                          {featured && (
                            <p className="text-sm text-muted-foreground leading-relaxed line-clamp-2">
                              {language === "pt" ? (item.descriptionPt || item.description) : item.description}
                            </p>
                          )}

                          {/* Action row (collapsed view = title + source + these) */}
                          <div className="pt-1 flex items-center gap-1.5 flex-wrap">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => toggleExpand(item)}
                              className="h-7 text-xs gap-1.5 px-2.5 rounded-lg text-foreground hover:bg-muted/50"
                            >
                              <ChevronDown className={`h-3.5 w-3.5 transition-transform ${expanded[item.link] ? "rotate-180" : ""}`} />
                              {language === "pt" ? "Análise acionável" : "Actionable analysis"}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => shareAdvisory(item)}
                              className="h-7 text-xs gap-1.5 px-2.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/50"
                            >
                              <Share2 className="h-3.5 w-3.5" />
                              {language === "pt" ? "Compartilhar" : "Share"}
                            </Button>
                            <a
                              href={item.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-primary hover:underline font-semibold flex items-center gap-1 ml-auto"
                            >
                              {t("viewFullArticle") || "View full article"}
                              <ChevronRight className="h-3 w-3" />
                            </a>
                          </div>

                          {/* Collapsible actionable analysis */}
                          {expanded[item.link] && (
                            <div className="mt-2 rounded-xl border border-border/50 bg-muted/20 p-4 space-y-3 text-sm font-sans">
                              {/* Analysis (LLM, or scraped + translated) */}
                              {enrichment[item.link]?.loading ? (
                                <div className="flex items-center gap-2 text-xs text-muted-foreground py-1">
                                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  {language === "pt" ? "Coletando artigo e gerando análise..." : "Fetching article and generating analysis..."}
                                </div>
                              ) : (
                                <>
                                  <div>
                                    <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ {language === "pt" ? "Resumo Executivo" : "Executive Summary"} ]</div>
                                    <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">
                                      {enrichment[item.link]?.data?.executiveSummary
                                        || renderHighlightedDescription(language === "pt" ? (item.descriptionPt || item.description) : item.description)}
                                    </p>
                                  </div>
                                  {/* Copyable source line: "Source - Link" */}
                                  <div className="pt-1 text-xs text-foreground/80 select-all break-all">
                                    {item.source} - {item.link}
                                  </div>
                                  {enrichment[item.link]?.data?.source === "translate" ? (
                                    <p className="text-[10px] text-muted-foreground/60 italic">
                                      {language === "pt" ? "Conteúdo do artigo traduzido (Google Translate) — análise por IA desativada" : "Article content translated (Google Translate) — AI analysis off"}
                                    </p>
                                  ) : enrichment[item.link]?.data?.source === "rss" ? (
                                    <p className="text-[10px] text-muted-foreground/60 italic">
                                      {language === "pt" ? "Resumo do artigo (análise por IA indisponível)" : "Article summary (AI analysis unavailable)"}
                                    </p>
                                  ) : null}
                                </>
                              )}

                              {/* Indicators of Compromise (deterministic) */}
                              {mIocs && hasIocs(mIocs) ? (
                                <div>
                                  <div className="flex items-center justify-between mb-1">
                                    <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide">[ {language === "pt" ? "INDICADORES (IOCs)" : "INDICATORS (IOCs)"} ]</div>
                                    <div className="flex items-center gap-1.5">
                                      <button
                                        onClick={() => {
                                          const txt = iocRows(mIocs).map(([t, v]) => `${t}\t${v}`).join("\n");
                                          navigator.clipboard.writeText(txt);
                                          toast.success(language === "pt" ? "IOCs copiados (defanged)" : "IOCs copied (defanged)");
                                        }}
                                        className="text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                                      >
                                        {language === "pt" ? "Copiar" : "Copy"}
                                      </button>
                                      <button
                                        onClick={() => {
                                          const rows = [["type", "indicator"], ...iocRows(mIocs)];
                                          const csv = rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n");
                                          const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
                                          const a = document.createElement("a");
                                          a.href = URL.createObjectURL(blob);
                                          a.download = `iocs_${new Date(item.pubDate).toISOString().slice(0, 10)}.csv`;
                                          a.click();
                                          URL.revokeObjectURL(a.href);
                                        }}
                                        className="text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                                      >
                                        {language === "pt" ? "Exportar CSV" : "Export CSV"}
                                      </button>
                                    </div>
                                  </div>
                                  <div className="flex flex-wrap gap-1.5">
                                    {iocRows(mIocs).map(([type, value]) => (
                                      <span
                                        key={`${type}:${value}`}
                                        title={type}
                                        className="font-mono text-[11px] px-1.5 py-0.5 rounded border border-amber-500/25 bg-amber-500/5 text-amber-600 dark:text-amber-400 break-all"
                                      >
                                        {value}
                                      </span>
                                    ))}
                                  </div>
                                  <p className="text-[10px] text-muted-foreground/60 italic mt-1">
                                    {language === "pt" ? "Indicadores defanged — valide antes de bloquear." : "Defanged indicators — validate before blocking."}
                                  </p>
                                </div>
                              ) : null}

                              {/* Guided Threat Hunting Pack (on-demand) */}
                              {(() => {
                                const hp = huntPacks[item.link];
                                return (
                                  <div className="pt-2 border-t border-border/40">
                                    {!hp || (!hp.loading && !hp.data && !hp.error) ? (
                                      <button
                                        onClick={() => void getHuntPack(item)}
                                        className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1.5 rounded-lg border border-primary/30 text-primary hover:bg-primary/10 transition-colors"
                                      >
                                        <Crosshair className="h-3.5 w-3.5" />
                                        {language === "pt" ? "Gerar Hunt Pack" : "Generate Hunt Pack"}
                                      </button>
                                    ) : null}

                                    {hp?.loading ? (
                                      <div className="flex items-center gap-2 text-xs text-muted-foreground py-1">
                                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                        {language === "pt"
                                          ? "Coletando o artigo e montando o Hunt Pack (pode aquecer o serviço, ~1 min)..."
                                          : "Scraping the article and building the Hunt Pack (service may be warming up, ~1 min)..."}
                                      </div>
                                    ) : null}

                                    {hp?.error ? (
                                      <div className="flex items-center justify-between gap-2 text-xs py-1">
                                        <span className="text-red-500">{hp.error}</span>
                                        <button
                                          onClick={() => void getHuntPack(item)}
                                          className="text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                                        >
                                          {language === "pt" ? "Tentar de novo" : "Retry"}
                                        </button>
                                      </div>
                                    ) : null}

                                    {hp?.data ? (() => {
                                      const pack = hp.data;
                                      const copy = (text: string, label: string) => {
                                        navigator.clipboard.writeText(text);
                                        toast.success(label);
                                      };
                                      return (
                                        <div className="mt-1 space-y-3 rounded-lg border border-primary/20 bg-primary/[0.03] p-3">
                                          <div className="flex items-center gap-1.5 text-[11px] font-bold text-primary tracking-wide">
                                            <Crosshair className="h-3.5 w-3.5" />
                                            {language === "pt" ? "PACOTE DE THREAT HUNTING" : "THREAT HUNTING PACK"}
                                          </div>

                                          <div className="text-[13px]">
                                            <span className="font-bold">{language === "pt" ? "Ator de ameaça:" : "Threat actor:"}</span> {pack.threat_actor}
                                          </div>

                                          {pack.ttp_mitre?.length ? (
                                            <div>
                                              <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ MITRE ATT&CK ]</div>
                                              <div className="flex flex-wrap gap-1.5">
                                                {pack.ttp_mitre.map((t) => (
                                                  <a
                                                    key={t}
                                                    href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="font-mono text-[11px] px-1.5 py-0.5 rounded border border-primary/20 text-primary hover:bg-primary/10"
                                                  >
                                                    {t}
                                                  </a>
                                                ))}
                                              </div>
                                            </div>
                                          ) : null}

                                          {pack.ioc_list?.length ? (
                                            <div>
                                              <div className="flex items-center justify-between mb-1">
                                                <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide">[ {language === "pt" ? "INDICADORES (IOCs)" : "INDICATORS (IOCs)"} ]</div>
                                                <button
                                                  onClick={() => copy(
                                                    pack.ioc_list.map((i) => `${i.type}\t${i.value}`).join("\n"),
                                                    language === "pt" ? "IOCs copiados (defanged)" : "IOCs copied (defanged)"
                                                  )}
                                                  className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                                                >
                                                  <Copy className="h-3 w-3" />{language === "pt" ? "Copiar" : "Copy"}
                                                </button>
                                              </div>
                                              <div className="flex flex-wrap gap-1.5">
                                                {pack.ioc_list.map((i) => (
                                                  <span
                                                    key={`${i.type}:${i.value}`}
                                                    title={i.type}
                                                    className="font-mono text-[11px] px-1.5 py-0.5 rounded border border-amber-500/25 bg-amber-500/5 text-amber-600 dark:text-amber-400 break-all"
                                                  >
                                                    {i.value}
                                                  </span>
                                                ))}
                                              </div>
                                            </div>
                                          ) : null}

                                          {pack.hunting_hypothesis ? (
                                            <div>
                                              <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ {language === "pt" ? "HIPÓTESE DE CAÇA" : "HUNTING HYPOTHESIS"} ]</div>
                                              <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{pack.hunting_hypothesis}</p>
                                            </div>
                                          ) : null}

                                          {pack.detection_query?.kql ? (
                                            <div>
                                              <div className="flex items-center justify-between mb-1">
                                                <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide">[ {language === "pt" ? "CONSULTA KQL (Sentinel)" : "KQL QUERY (Sentinel)"} ]</div>
                                                <button
                                                  onClick={() => copy(pack.detection_query.kql, language === "pt" ? "KQL copiada" : "KQL copied")}
                                                  className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                                                >
                                                  <Copy className="h-3 w-3" />{language === "pt" ? "Copiar" : "Copy"}
                                                </button>
                                              </div>
                                              <pre className="text-[11px] font-mono bg-muted/40 border border-border/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{pack.detection_query.kql}</pre>
                                            </div>
                                          ) : null}

                                          {pack.detection_query?.sigma ? (
                                            <div>
                                              <div className="flex items-center justify-between mb-1">
                                                <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide">[ {language === "pt" ? "REGRA SIGMA" : "SIGMA RULE"} ]</div>
                                                <button
                                                  onClick={() => copy(pack.detection_query.sigma || "", language === "pt" ? "Sigma copiada" : "Sigma copied")}
                                                  className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                                                >
                                                  <Copy className="h-3 w-3" />{language === "pt" ? "Copiar" : "Copy"}
                                                </button>
                                              </div>
                                              <pre className="text-[11px] font-mono bg-muted/40 border border-border/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{pack.detection_query.sigma}</pre>
                                            </div>
                                          ) : null}

                                          {pack.executive_brief ? (
                                            <div>
                                              <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ {language === "pt" ? "BRIEF EXECUTIVO" : "EXECUTIVE BRIEF"} ]</div>
                                              <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{pack.executive_brief}</p>
                                            </div>
                                          ) : null}

                                          {pack.soc_summary ? (
                                            <div>
                                              <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ {language === "pt" ? "RESUMO SOC" : "SOC SUMMARY"} ]</div>
                                              <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{pack.soc_summary}</p>
                                            </div>
                                          ) : null}

                                          <p className="text-[10px] text-muted-foreground/60 italic">
                                            {language === "pt"
                                              ? "Gerado por IA a partir do artigo — indicadores defanged; valide antes de agir."
                                              : "AI-generated from the article — defanged indicators; validate before acting."}
                                          </p>
                                        </div>
                                      );
                                    })() : null}
                                  </div>
                                );
                              })()}

                              {/* Source + References footer */}
                              <div className="pt-2 border-t border-border/40 space-y-1 text-[12px]">
                                <div>
                                  🔗 <a href={item.link} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline font-semibold">Source</a>
                                </div>
                                {mCves.length ? (
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    <span>📎 {language === "pt" ? "Referências:" : "References:"}</span>
                                    {mCves.map((cve) => (
                                      <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" className="font-mono font-semibold px-1.5 py-0.5 rounded border border-primary/20 text-primary hover:bg-primary/10">{cve}</a>
                                    ))}
                                  </div>
                                ) : null}
                              </div>
                            </div>
                          )}
                        </div>
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
