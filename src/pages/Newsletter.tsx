import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, BookOpen, AlertTriangle, Search, Mail, Eye, Sparkles, Filter, CheckCircle2, ChevronLeft, ChevronRight, ChevronDown, Download, Layers, RefreshCw, Calendar, Share2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";
import { toast } from "sonner";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

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
  // Deterministic actionable enrichment
  threats?: string[];
  sectors?: string[];
  ttps?: string[];
  assets?: string[];
}

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-500 border-red-500/20",
  High: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  Medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  Low: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

interface EnrichData {
  available: boolean;
  source?: string; // groq | translate | rss
  scraped?: boolean;
  title?: string;
  executiveSummary?: string;
  impactMitigation?: string;
  iocs?: Record<string, unknown> | null;
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
  const { isCollapsed } = useSidebar();
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
            threats: Array.isArray(item.threats) ? (item.threats as string[]) : undefined,
            sectors: Array.isArray(item.sectors) ? (item.sectors as string[]) : undefined,
            ttps: Array.isArray(item.ttps) ? (item.ttps as string[]) : undefined,
            assets: Array.isArray(item.assets) ? (item.assets as string[]) : undefined,
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
  }, [advisories, selectedMonth, selectedYear, searchNews, selectedLayer, selectedSeverity, sortByRelevance]);

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
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />

      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">

          {/* Page Title Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Mail className="h-6 w-6 text-primary" />
                {language === "pt" ? "Feed de Advisories" : "Advisory Feed"}
              </h1>
              <p className="text-xs text-muted-foreground mt-1">
                {language === "pt"
                  ? "Agregador de notícias e avisos de segurança de múltiplas fontes de inteligência contra ameaças"
                  : "Threat intelligence news and security advisories aggregated from multiple sources"}
              </p>
            </div>
            {/* Auto-polling / Last Updated Status */}
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <div className="flex items-center gap-2 bg-muted/25 border border-border/40 p-1.5 rounded-md px-3 shadow-inner">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                </span>
                <span className="font-semibold text-foreground/90">{language === "pt" ? "Auto-polling ativo" : "Auto-polling active"}</span>
                <span className="text-muted-foreground/30">|</span>
                <div className="flex items-center gap-1">
                  <svg className="h-3 w-3 transform -rotate-90 text-green-500 shrink-0" viewBox="0 0 24 24">
                    <circle
                      className="text-muted/20 dark:text-muted/10"
                      strokeWidth="3.5"
                      stroke="currentColor"
                      fill="transparent"
                      r="8"
                      cx="12"
                      cy="12"
                    />
                    <circle
                      className="text-green-500 transition-all duration-1000 ease-linear"
                      strokeWidth="3.5"
                      strokeDasharray="50.27"
                      strokeDashoffset={50.27 * (1 - secondsRemaining / 300)}
                      strokeLinecap="round"
                      stroke="currentColor"
                      fill="transparent"
                      r="8"
                      cx="12"
                      cy="12"
                    />
                  </svg>
                  <span className="font-mono text-[10px] text-muted-foreground/90 tabular-nums">{formatTime(secondsRemaining)}</span>
                </div>
              </div>
              {isRefreshingNews && <span className="animate-pulse text-primary font-medium">{language === "pt" ? "Atualizando..." : "Refreshing..."}</span>}
              <span>
                {language === "pt" ? "Última atualização: " : "Last updated: "}
                {lastUpdatedNews ? lastUpdatedNews.toLocaleTimeString() : "Pending"}
              </span>
            </div>
          </div>

          {/* Calendar Month Selector Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-card/25 backdrop-blur-xl border border-primary/10 rounded-2xl p-4 shadow-lg">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="icon"
                className="h-9.5 w-9.5 rounded-xl border-primary/15 hover:bg-primary/5 shrink-0"
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
                className="h-9.5 w-9.5 rounded-xl border-primary/15 hover:bg-primary/5 shrink-0"
                onClick={handleNextMonth}
                title={language === "pt" ? "Próximo Mês" : "Next Month"}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>

            {/* Quick Month Select Dropdown */}
            <div className="flex items-center gap-2.5 w-full sm:w-auto">
              <Select value={selectedMonth.toString()} onValueChange={(val) => setSelectedMonth(parseInt(val))}>
                <SelectTrigger className="h-9.5 w-full sm:w-[130px] bg-background/50 border-primary/15 rounded-xl text-xs font-semibold focus:ring-primary/20 hover:bg-background/60 transition-all">
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
                <SelectTrigger className="h-9.5 w-full sm:w-[95px] bg-background/50 border-primary/15 rounded-xl text-xs font-semibold focus:ring-primary/20 hover:bg-background/60 transition-all">
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
          <div className="flex flex-col xl:flex-row gap-3 bg-card/40 border p-3 rounded-xl backdrop-blur-sm">
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
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 xl:pb-0 shrink-0">
              <Button
                variant={selectedLayer === "all" ? "default" : "outline"}
                size="sm"
                className="h-9 text-xs font-semibold px-3"
                onClick={() => setSelectedLayer("all")}
              >
                {language === "pt" ? "Todos os Feeds" : "All Feeds"}
              </Button>
              <Button
                variant={selectedLayer === "l1" ? "default" : "outline"}
                size="sm"
                className="h-9 text-xs font-semibold px-3 gap-1.5"
                onClick={() => setSelectedLayer("l1")}
              >
                <span className="h-2 w-2 rounded-full bg-red-500" />
                L1: PSIRT
              </Button>
              <Button
                variant={selectedLayer === "l2" ? "default" : "outline"}
                size="sm"
                className="h-9 text-xs font-semibold px-3 gap-1.5"
                onClick={() => setSelectedLayer("l2")}
              >
                <span className="h-2 w-2 rounded-full bg-amber-500" />
                L2: CTI Research
              </Button>
              <Button
                variant={selectedLayer === "l3" ? "default" : "outline"}
                size="sm"
                className="h-9 text-xs font-semibold px-3 gap-1.5"
                onClick={() => setSelectedLayer("l3")}
              >
                <span className="h-2 w-2 rounded-full bg-blue-500" />
                L3: Research/BR
              </Button>

              <div className="h-4 w-px bg-border/60 mx-1 shrink-0" />

              {/* Severity filter (CTI relevance) */}
              <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                <SelectTrigger className="h-9 w-[140px] text-xs font-semibold shrink-0">
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

              {/* Relevance sort toggle */}
              <Button
                variant={sortByRelevance ? "default" : "outline"}
                size="sm"
                className="h-9 text-xs font-semibold px-3 gap-1.5 shrink-0"
                onClick={() => setSortByRelevance(v => !v)}
                title={language === "pt" ? "Ordenar por relevância" : "Sort by relevance"}
              >
                <Sparkles className="h-3.5 w-3.5" />
                {language === "pt" ? "Relevância" : "Relevance"}
              </Button>

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
            <Card className="border border-primary/10 shadow-lg bg-card/45 backdrop-blur-lg relative overflow-hidden group">
              {/* Premium gradient accent top bar */}
              <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary via-blue-500 to-cyan-500" />
              
              <CardContent className="p-4 md:p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="flex items-start gap-3.5 flex-1 min-w-0">
                  <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 text-primary shrink-0">
                    <Layers className="h-6 w-6" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <CardTitle className="text-base flex items-center gap-2">
                      {t("generateWeeklyDigest") || "Generate Weekly Digest"}
                      <Badge variant={selectedCount > 0 ? "default" : "secondary"} className={selectedCount > 0 ? "bg-primary text-primary-foreground shadow-sm shadow-primary/25 animate-pulse ml-1.5" : "ml-1.5"}>
                        {selectedCount} {language === "pt" ? "Selecionados" : "Selected"}
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
                        className={`w-full md:w-auto gap-2 text-xs h-9 px-5 transition-all duration-300 ${
                          selectedCount > 0 
                            ? "bg-gradient-to-r from-primary to-blue-600 hover:from-primary/90 hover:to-blue-600/90 text-primary-foreground shadow-md shadow-primary/15 hover:shadow-lg hover:shadow-primary/25 hover:scale-[1.02] active:scale-[0.98]" 
                            : "bg-muted/50 text-muted-foreground cursor-not-allowed"
                        }`}
                        disabled={selectedCount === 0}
                        variant={selectedCount > 0 ? "default" : "secondary"}
                      >
                        <Sparkles className="h-4 w-4" />
                        {t("generateWeeklyDigest") || "Generate weekly digest"}
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col p-6">
                      <DialogHeader className="border-b pb-4">
                        <DialogTitle className="text-2xl font-bold flex items-center gap-2">
                          <Sparkles className="h-6 w-6 text-primary" />
                          {t("weeklyDigestTitle") || "Threat Weekly Digest"}
                        </DialogTitle>
                      </DialogHeader>

                      <div className="flex-1 overflow-y-auto pr-1 py-4">
                        {/* Compiled newsletter template print container */}
                        <div id="compiled-digest-preview" className="space-y-6 text-slate-800 dark:text-slate-100 p-4 border rounded-xl bg-card/50 backdrop-blur-sm">
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
                    <div key={n} className="p-6 rounded-xl border bg-card/60 animate-pulse space-y-3">
                      <div className="h-4 w-1/4 bg-muted rounded"></div>
                      <div className="h-6 w-3/4 bg-muted rounded"></div>
                      <div className="h-4 w-5/6 bg-muted rounded"></div>
                    </div>
                  ))}
                </div>
              ) : newsError ? (
                <div className="p-8 border border-destructive/20 rounded-xl bg-destructive/5 text-center">
                  <AlertTriangle className="h-10 w-10 text-destructive mx-auto mb-3" />
                  <p className="text-destructive font-medium">{newsError}</p>
                  <p className="text-sm text-muted-foreground mt-1">Please try again later.</p>
                </div>
              ) : filteredAdvisories.length === 0 ? (
                <div className="p-12 border border-dashed rounded-xl text-center bg-card space-y-4">
                  <BookOpen className="h-12 w-12 text-muted-foreground/50 mx-auto mb-3" />
                  <div>
                    <p className="text-muted-foreground font-medium">{language === "pt" ? "Nenhuma notícia encontrada para este mês no cache local" : "No threat advisories found for this month in local cache"}</p>
                    <p className="text-xs text-muted-foreground mt-1">{language === "pt" ? "Você pode buscar as notícias mais recentes do servidor para popular o cache" : "Try fetching the latest feed from the server or choose another month"}</p>
                  </div>
                  <Button
                    onClick={() => loadNews()}
                    className="gap-2 h-9 px-4 rounded-xl text-xs font-semibold bg-primary hover:bg-primary/90 text-white mx-auto"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {language === "pt" ? "Buscar Notícias Recentes" : "Fetch Recent Advisories"}
                  </Button>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {filteredAdvisories.map((item, idx) => {
                    const enr = enrichment[item.link]?.data;
                    const mThreats = mergedField(item, enr, "threats");
                    const mSectors = mergedField(item, enr, "sectors");
                    const mTtps = mergedField(item, enr, "ttps");
                    const mAssets = mergedField(item, enr, "assets");
                    const mCves = mergedField(item, enr, "cves");
                    const isCisa = item.source.toLowerCase().includes("cisa");
                    const isBleeping = item.source.toLowerCase().includes("bleeping");
                    const badgeColor = isCisa
                      ? "bg-red-500/10 text-red-500 border-red-500/20 hover:bg-red-500/20"
                      : isBleeping
                      ? "bg-blue-500/10 text-blue-500 border-blue-500/20 hover:bg-blue-500/20"
                      : "bg-amber-500/10 text-amber-500 border-amber-500/20 hover:bg-amber-500/20";

                    return (
                      <div
                        key={idx}
                        className={`p-5 rounded-xl border bg-card shadow-sm hover:shadow-md transition-all flex items-start gap-4 ${
                          selectedNews[item.title] ? "border-primary/50 bg-primary/5" : ""
                        }`}
                      >
                        <Checkbox
                          checked={!!selectedNews[item.title]}
                          onCheckedChange={() => toggleSelectNews(item.title)}
                          className="mt-1"
                        />
                        
                        <div className="flex-1 space-y-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge variant="outline" className={badgeColor}>
                              {item.source}
                            </Badge>
                            {item.severity && (
                              <Badge variant="outline" className={`text-[10px] font-bold ${SEVERITY_STYLES[item.severity] || SEVERITY_STYLES.Low}`}>
                                {item.severity}
                                {typeof item.score === "number" && <span className="ml-1 opacity-70">{item.score}</span>}
                              </Badge>
                            )}
                            {(item.cves ?? []).slice(0, 3).map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border border-primary/20 text-primary hover:bg-primary/10 transition-colors"
                              >
                                {cve}
                              </a>
                            ))}
                            <span className="text-xs text-muted-foreground">
                              {new Date(item.pubDate).toLocaleString()}
                            </span>
                          </div>
                          
                          <h3 className="font-bold text-lg text-foreground hover:text-primary transition-colors flex items-center gap-2 flex-wrap">
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
                              {/* Metadata block (mirrors the SOC bot card) */}
                              <div className="space-y-0.5 text-[13px] text-foreground/90">
                                <div><span className="font-bold">Source:</span> {item.source}</div>
                                <div><span className="font-bold">Date:</span> {new Date(item.pubDate).toISOString().slice(0, 10)}</div>
                                {mAssets.length ? <div><span className="font-bold">Monitored Assets:</span> {mAssets.join(", ")}</div> : null}
                                {mThreats.length ? <div><span className="font-bold">Threats:</span> {mThreats.join(", ")}</div> : null}
                                {mSectors.length ? <div><span className="font-bold">Targeted Sectors:</span> {mSectors.join(", ")}</div> : null}
                              </div>

                              {/* MITRE ATT&CK */}
                              {mTtps.length ? (
                                <div>
                                  <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ MITRE ATT&CK ]</div>
                                  <ul className="space-y-0.5">
                                    {mTtps.map((tp) => (
                                      <li key={tp} className="text-xs font-mono">• {tp}</li>
                                    ))}
                                  </ul>
                                </div>
                              ) : null}

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
                                  {enrichment[item.link]?.data?.impactMitigation ? (
                                    <div>
                                      <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1">[ {language === "pt" ? "IMPACTO & MITIGAÇÃO" : "IMPACT & MITIGATION"} ]</div>
                                      <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{enrichment[item.link]?.data?.impactMitigation}</p>
                                    </div>
                                  ) : null}
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
      </div>
      <Footer />
    </div>
  );
};

export default Newsletter;
