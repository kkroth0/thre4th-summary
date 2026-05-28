import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, BookOpen, AlertTriangle, Search, Mail, Eye, Sparkles, Filter, CheckCircle2, ChevronLeft, ChevronRight, Download, Layers, RefreshCw, Calendar } from "lucide-react";
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
}

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
          const validated: Advisory[] = parsed.filter((item: any): item is Advisory => {
            return (
              item &&
              typeof item === "object" &&
              typeof item.title === "string" &&
              typeof item.link === "string" &&
              typeof item.pubDate === "string" &&
              typeof item.description === "string" &&
              typeof item.source === "string"
            );
          }).map(item => ({
            title: item.title,
            link: item.link,
            pubDate: item.pubDate,
            description: item.description,
            source: item.source,
            layer: typeof item.layer === "number" ? item.layer : undefined,
            titlePt: typeof item.titlePt === "string" ? item.titlePt : undefined,
            descriptionPt: typeof item.descriptionPt === "string" ? item.descriptionPt : undefined
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
        
        // Sort newest first
        merged.sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime());
        localStorage.setItem("cached_cti_advisories", JSON.stringify(merged));
        return merged;
      });

      setLastUpdatedNews(new Date());
    } catch (err: any) {
      console.error(err);
      if (!isBackground) {
        setNewsError(err.message);
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
            .description { font-size: 13px; line-height: 1.6; color: #334155; }
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

  // Filter Advisories / News
  const filteredAdvisories = useMemo(() => {
    return advisories.filter(item => {
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

      // 3. Layer filter
      if (selectedLayer === "all") return true;
      if (selectedLayer === "l1") return item.layer === 1;
      if (selectedLayer === "l2") return item.layer === 2;
      if (selectedLayer === "l3") return item.layer === 3;
      return true;
    });
  }, [advisories, selectedMonth, selectedYear, searchNews, selectedLayer]);

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
                L3: Blogs
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
              <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary via-purple-500 to-blue-500" />
              
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
                            ? "bg-gradient-to-r from-primary to-purple-600 hover:from-primary/90 hover:to-purple-600/90 text-primary-foreground shadow-md shadow-primary/15 hover:shadow-lg hover:shadow-primary/25 hover:scale-[1.02] active:scale-[0.98]" 
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
                            {selectedAdvisoriesList.map((item, idx) => (
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
                                <div className="title font-bold text-base text-foreground">{language === "pt" ? (item.titlePt || item.title) : item.title}</div>
                                <div className="date text-xs text-muted-foreground">{new Date(item.pubDate).toLocaleString()}</div>
                                <div className="description text-sm text-muted-foreground leading-relaxed">{renderHighlightedDescription(language === "pt" ? (item.descriptionPt || item.description) : item.description)}</div>
                              </div>
                            ))}
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
                          
                          <div className="text-sm text-muted-foreground leading-relaxed">
                            {renderHighlightedDescription(language === "pt" ? (item.descriptionPt || item.description) : item.description)}
                          </div>

                          <div className="pt-2 flex items-center justify-between">
                            <a
                              href={item.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-primary hover:underline font-semibold flex items-center gap-1"
                            >
                              {t("viewFullArticle") || "View full article"}
                              <ChevronRight className="h-3 w-3" />
                            </a>
                          </div>
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
