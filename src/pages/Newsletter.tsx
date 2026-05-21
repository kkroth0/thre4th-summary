import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, Shield, BookOpen, AlertTriangle, Search, Mail, Eye, Sparkles, Filter, CheckCircle2, ChevronRight, Download, BarChart2, Layers, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { Header } from "@/components/Header";
import { toast } from "sonner";

interface Advisory {
  title: string;
  link: string;
  pubDate: string;
  description: string;
  source: string;
  layer?: number;
}

interface CveItem {
  id: string;
  cvss: number | null;
  summary: string;
  Published: string;
  Modified?: string;
}

interface ExploitedCve {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
}

const Newsletter = () => {
  const { t, language } = useLanguage();
  
  // Newsletter States
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [searchNews, setSearchNews] = useState("");
  const [selectedNews, setSelectedNews] = useState<Record<string, boolean>>({});
  const [email, setEmail] = useState("");
  const [loadingNews, setLoadingNews] = useState(true);
  const [newsError, setNewsError] = useState<string | null>(null);
  const [isDigestOpen, setIsDigestOpen] = useState(false);
  const [selectedLayer, setSelectedLayer] = useState<string>("all");

  // CVE Dashboard States
  const [recentCves, setRecentCves] = useState<CveItem[]>([]);
  const [exploitedCves, setExploitedCves] = useState<ExploitedCve[]>([]);
  const [searchCveQuery, setSearchCveQuery] = useState("");
  const [loadingCves, setLoadingCves] = useState(true);
  const [loadingExploited, setLoadingExploited] = useState(true);
  const [cveError, setCveError] = useState<string | null>(null);

  // Background Polling / Last Updated States
  const [lastUpdatedNews, setLastUpdatedNews] = useState<Date | null>(null);
  const [lastUpdatedCves, setLastUpdatedCves] = useState<Date | null>(null);
  const [isRefreshingNews, setIsRefreshingNews] = useState(false);
  const [isRefreshingCves, setIsRefreshingCves] = useState(false);

  // Fetch CTI News / Advisories
  const loadNews = async (isBackground = false) => {
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
      setAdvisories(data);
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

  // Fetch CVE Dashboard Data
  const loadCves = async (isBackground = false) => {
    if (!isBackground) {
      setLoadingCves(true);
      setLoadingExploited(true);
    } else {
      setIsRefreshingCves(true);
    }
    setCveError(null);
    try {
      const [recentRes, exploitedRes] = await Promise.all([
        fetch("/api/cves/recent"),
        fetch("/api/cves/exploited")
      ]);
      
      if (!recentRes.ok) throw new Error("Failed to fetch recent CVEs");
      if (!exploitedRes.ok) throw new Error("Failed to fetch CISA KEV catalog");
      
      const recentData = await recentRes.json();
      const exploitedData = await exploitedRes.json();
      
      setRecentCves(recentData);
      setExploitedCves(exploitedData);
      setLastUpdatedCves(new Date());
    } catch (err: any) {
      console.error(err);
      if (!isBackground) {
        setCveError(err.message);
      } else {
        toast.error(language === "pt" ? "Erro ao atualizar CVEs em segundo plano" : "Failed to background refresh CVEs");
      }
    } finally {
      setLoadingCves(false);
      setLoadingExploited(false);
      setIsRefreshingCves(false);
    }
  };

  useEffect(() => {
    loadNews();
    loadCves();

    // Polling intervals: 5 min for news (300000ms), 10 min for CVEs (600000ms)
    const newsInterval = setInterval(() => {
      loadNews(true);
    }, 300000);

    const cvesInterval = setInterval(() => {
      loadCves(true);
    }, 600000);

    return () => {
      clearInterval(newsInterval);
      clearInterval(cvesInterval);
    };
  }, []);

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

  // Simulated Email Subscription
  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !email.includes("@")) {
      toast.error(language === "pt" ? "Por favor, insira um e-mail válido" : "Please enter a valid email");
      return;
    }
    toast.success(t("subscribeSuccess"), {
      description: t("subscribeSuccessDesc"),
      icon: <CheckCircle2 className="h-5 w-5 text-green-500" />
    });
    setEmail("");
  };

  // Trigger Pivot Search on main dashboard
  const handlePivotSearch = (cveId: string) => {
    localStorage.setItem("pivotSearchQuery", cveId);
    toast.success(language === "pt" ? `Pesquisando ${cveId} no painel...` : `Searching ${cveId} on main dashboard...`);
    window.location.href = "/";
  };

  // Parse CVSS severity class
  const getCvssSeverity = (score: number | null): { label: string; color: string } => {
    if (score === null) return { label: "N/A", color: "bg-slate-500/20 text-slate-400 border-slate-500/30" };
    if (score >= 9.0) return { label: "Critical", color: "bg-red-500/20 text-red-500 border-red-500/30" };
    if (score >= 7.0) return { label: "High", color: "bg-orange-500/20 text-orange-500 border-orange-500/30" };
    if (score >= 4.0) return { label: "Medium", color: "bg-yellow-500/20 text-yellow-500 border-yellow-500/30" };
    return { label: "Low", color: "bg-green-500/20 text-green-500 border-green-500/30" };
  };

  // Print Compiled PDF / Print Document
  const handlePrintDigest = () => {
    const printWindow = window.open("", "_blank");
    if (!printWindow) return;
    const content = document.getElementById("compiled-digest-preview")?.innerHTML || "";
    printWindow.document.write(`
      <html>
        <head>
          <title>ThreatSumm4ry - CTI & CVE Digest</title>
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
  const filteredAdvisories = advisories.filter(item => {
    const matchesSearch =
      (item.title ?? '').toLowerCase().includes(searchNews.toLowerCase()) ||
      (item.description ?? '').toLowerCase().includes(searchNews.toLowerCase()) ||
      (item.source ?? '').toLowerCase().includes(searchNews.toLowerCase());

    if (selectedLayer === "all") return matchesSearch;
    if (selectedLayer === "l1") return matchesSearch && item.layer === 1;
    if (selectedLayer === "l2") return matchesSearch && item.layer === 2;
    if (selectedLayer === "l3") return matchesSearch && item.layer === 3;
    return matchesSearch;
  });

  // Filter CVEs
  const filteredRecentCves = recentCves.filter(cve =>
    (cve.id ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
    (cve.summary ?? '').toLowerCase().includes(searchCveQuery.toLowerCase())
  );

  const filteredExploitedCves = exploitedCves.filter(cve =>
    (cve.cveID ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
    (cve.vendorProject ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
    (cve.product ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
    (cve.vulnerabilityName ?? '').toLowerCase().includes(searchCveQuery.toLowerCase())
  );

  const selectedCount = Object.values(selectedNews).filter(Boolean).length;
  const selectedAdvisoriesList = advisories.filter(item => selectedNews[item.title]);

  // Statistics calculation for CVEs
  const totalCvesTracked = recentCves.length + exploitedCves.length;
  const validCvssList = recentCves
    .map(c => c.cvss)
    .filter((c): c is number => c !== null && c !== undefined && !isNaN(Number(c)))
    .map(Number);
  const averageCvss = validCvssList.length > 0 ? (validCvssList.reduce((a, b) => a + b, 0) / validCvssList.length).toFixed(1) : "8.2";
  const criticalCount = recentCves.filter(c => {
    const val = c.cvss !== null && c.cvss !== undefined ? Number(c.cvss) : null;
    return val !== null && !isNaN(val) && val >= 9.0;
  }).length + exploitedCves.length;

  // Detailed CVSS Severity counts
  const cvssDistribution = useMemo(() => {
    let critical = 0; // >= 9.0
    let high = 0;     // 7.0 - 8.9
    let medium = 0;   // 4.0 - 6.9
    let low = 0;      // 0.1 - 3.9
    let na = 0;       // null/NaN/0

    recentCves.forEach(cve => {
      const score = cve.cvss;
      if (score === null || score === undefined || isNaN(Number(score))) {
        na++;
      } else {
        const val = Number(score);
        if (val >= 9.0) critical++;
        else if (val >= 7.0) high++;
        else if (val >= 4.0) medium++;
        else if (val > 0) low++;
        else na++;
      }
    });

    // CISA KEV Exploited CVEs represent critical real-world severity
    critical += exploitedCves.length;

    return { critical, high, medium, low, na };
  }, [recentCves, exploitedCves]);

  // Top Targeted Vendors based on CISA KEV catalog (exploitedCves)
  const topTargetedVendors = useMemo(() => {
    const counts: Record<string, number> = {};
    exploitedCves.forEach(cve => {
      const vendor = cve.vendorProject || "Unknown";
      counts[vendor] = (counts[vendor] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [exploitedCves]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Header showBackButton />

      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">

          {/* Unified Page Tabs */}
          <Tabs defaultValue="newsletter" className="w-full">
            <TabsList className="grid w-full grid-cols-2 max-w-md bg-muted/40 p-1 rounded-xl mb-6">
              <TabsTrigger value="newsletter" className="rounded-lg gap-2">
                <BookOpen className="h-4 w-4" />
                {t("newsletter")}
              </TabsTrigger>
              <TabsTrigger value="cves" className="rounded-lg gap-2">
                <Shield className="h-4 w-4" />
                {t("cveDashboard")}
              </TabsTrigger>
            </TabsList>

            {/* Newsletter Tab */}
            <TabsContent value="newsletter" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                
                {/* Left Side: Controls */}
                <div className="lg:col-span-1 space-y-6">
                  {/* Digest Builder Tool */}
                  <Card className="border shadow bg-gradient-to-br from-card to-muted/10">
                    <CardHeader className="pb-4">
                      <CardTitle className="text-lg flex items-center gap-2">
                        <Layers className="h-5 w-5 text-primary" />
                        {t("generateWeeklyDigest")}
                      </CardTitle>
                      <CardDescription>
                        {t("selectForDigest")}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="text-sm flex items-center justify-between border-b pb-2">
                        <span className="text-muted-foreground">{t("selectedArticles")}:</span>
                        <Badge variant={selectedCount > 0 ? "default" : "secondary"}>
                          {selectedCount}
                        </Badge>
                      </div>

                      <Dialog open={isDigestOpen} onOpenChange={setIsDigestOpen}>
                        <DialogTrigger asChild>
                          <Button
                            className="w-full gap-2"
                            variant="default"
                            disabled={selectedCount === 0}
                          >
                            <Sparkles className="h-4 w-4" />
                            {t("generateWeeklyDigest")}
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col p-6">
                          <DialogHeader className="border-b pb-4">
                            <DialogTitle className="text-2xl font-bold flex items-center gap-2">
                              <Sparkles className="h-6 w-6 text-primary" />
                              {t("weeklyDigestTitle")}
                            </DialogTitle>
                          </DialogHeader>

                          <div className="flex-1 overflow-y-auto pr-1 py-4">
                            {/* Compiled newsletter template print container */}
                            <div id="compiled-digest-preview" className="space-y-6 text-slate-800 dark:text-slate-100 p-4 border rounded-xl bg-card/50 backdrop-blur-sm">
                              <h1>{t("weeklyDigestTitle")}</h1>
                              <p className="meta">
                                <strong>Date:</strong> {new Date().toLocaleDateString()}<br />
                                <strong>Source:</strong> ThreatSumm4ry Platform Aggregator
                              </p>
                              
                              <p className="description">
                                {language === "pt"
                                  ? "Este documento é um sumário compilado de inteligência contra ameaças digitais coletado e estruturado a partir de múltiplas fontes de segurança cibernética públicas e privadas."
                                  : "This document contains compiled cyber threat intelligence alerts curated and structured from various security feeds and vendor advisories."}
                              </p>

                              <div className="space-y-4">
                                {selectedAdvisoriesList.map((item, idx) => (
                                  <div key={idx} className="advisory">
                                    <span className={`source ${
                                      item.source.toLowerCase().includes("cisa")
                                        ? "source-cisa"
                                        : item.source.toLowerCase().includes("bleeping")
                                        ? "source-bleeping"
                                        : "source-hacker"
                                    }`}>
                                      {item.source}
                                    </span>
                                    <div className="title">{item.title}</div>
                                    <div className="date">{new Date(item.pubDate).toLocaleString()}</div>
                                    <div className="description">{renderHighlightedDescription(item.description)}</div>
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
                              {t("downloadDigest")}
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                    </CardContent>
                  </Card>

                  {/* Layer Filter Card */}
                  <Card className="border shadow bg-gradient-to-br from-card to-muted/10">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                        <Layers className="h-4 w-4 text-primary" />
                        {language === "pt" ? "Camadas de Feeds" : "Feed Layers"}
                      </CardTitle>
                      <CardDescription>
                        {language === "pt" ? "Filtre fontes por camadas de severidade" : "Filter sources by severity layers"}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <Button
                        variant={selectedLayer === "all" ? "default" : "outline"}
                        size="sm"
                        className="w-full justify-start text-xs font-semibold"
                        onClick={() => setSelectedLayer("all")}
                      >
                        {language === "pt" ? "Todos os Feeds" : "All Feeds"}
                      </Button>
                      <Button
                        variant={selectedLayer === "l1" ? "default" : "outline"}
                        size="sm"
                        className="w-full justify-start text-xs font-semibold gap-2"
                        onClick={() => setSelectedLayer("l1")}
                      >
                        <span className="h-2.5 w-2.5 rounded-full bg-red-500 animate-pulse" />
                        L1: PSIRT / Vendor Advisories
                      </Button>
                      <Button
                        variant={selectedLayer === "l2" ? "default" : "outline"}
                        size="sm"
                        className="w-full justify-start text-xs font-semibold gap-2"
                        onClick={() => setSelectedLayer("l2")}
                      >
                        <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
                        L2: Security Research (TI)
                      </Button>
                      <Button
                        variant={selectedLayer === "l3" ? "default" : "outline"}
                        size="sm"
                        className="w-full justify-start text-xs font-semibold gap-2"
                        onClick={() => setSelectedLayer("l3")}
                      >
                        <span className="h-2.5 w-2.5 rounded-full bg-blue-500" />
                        L3: LATAM & Regional Blogs
                      </Button>
                    </CardContent>
                  </Card>
                </div>

                {/* Right Side: News Feed */}
                <div className="lg:col-span-3 space-y-4">
                  {/* Polling / Last Updated status */}
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between text-xs text-muted-foreground bg-muted/20 border border-border/40 p-2.5 rounded-lg px-4 gap-2">
                    <div className="flex items-center gap-2">
                      <span className="relative flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                      </span>
                      <span>Auto-polling active (5m news, 10m CVEs)</span>
                    </div>
                    <div className="flex items-center gap-2 w-full sm:w-auto justify-between sm:justify-end">
                      {isRefreshingNews && <span className="animate-pulse text-primary font-medium">{language === "pt" ? "Atualizando..." : "Refreshing..."}</span>}
                      <span>
                        {language === "pt" ? "Última atualização: " : "Last updated: "}
                        {lastUpdatedNews ? lastUpdatedNews.toLocaleTimeString() : "Pending"}
                      </span>
                    </div>
                  </div>

                  {/* Search and control bar */}
                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="relative flex-1">
                      <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder={t("searchAdvisories")}
                        value={searchNews}
                        onChange={(e) => setSearchNews(e.target.value)}
                        className="pl-9 bg-card"
                      />
                    </div>
                    <Button
                      variant="outline"
                      onClick={() => selectAllVisibleNews(filteredAdvisories)}
                      className="gap-2 shrink-0 border-primary/20 hover:bg-primary/5"
                    >
                      <Filter className="h-4 w-4" />
                      {filteredAdvisories.every(item => selectedNews[item.title])
                        ? (language === "pt" ? "Desmarcar Todos" : "Deselect All")
                        : (language === "pt" ? "Selecionar Visíveis" : "Select Visible")}
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      disabled={loadingNews || isRefreshingNews}
                      onClick={() => loadNews()}
                      className="shrink-0 border-primary/20 hover:bg-primary/5"
                      title={language === "pt" ? "Atualizar feeds" : "Refresh feeds"}
                    >
                      <RefreshCw className={`h-4 w-4 ${(loadingNews || isRefreshingNews) ? "animate-spin" : ""}`} />
                    </Button>
                  </div>

                  {/* Loading/Error/News List */}
                  {loadingNews ? (
                    <div className="space-y-4 py-8">
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
                    <div className="p-12 border border-dashed rounded-xl text-center bg-card">
                      <BookOpen className="h-12 w-12 text-muted-foreground/50 mx-auto mb-3" />
                      <p className="text-muted-foreground font-medium">{t("noAdvisoriesFound")}</p>
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
                              
                              <h3 className="font-bold text-lg text-foreground hover:text-primary transition-colors">
                                <a href={item.link} target="_blank" rel="noopener noreferrer">
                                  {item.title}
                                </a>
                              </h3>
                              
                              <p className="text-sm text-muted-foreground line-clamp-3">
                                {renderHighlightedDescription(item.description)}
                              </p>

                              <div className="pt-2 flex items-center justify-between">
                                <a
                                  href={item.link}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-xs text-primary hover:underline font-semibold flex items-center gap-1"
                                >
                                  {t("viewFullArticle")}
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
            </TabsContent>

            {/* CVE Dashboard Tab */}
            <TabsContent value="cves" className="space-y-6">
              {/* Metrics row */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
                  <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{language === "pt" ? "Total de Ameaças" : t("totalTracked")}</span>
                    <BarChart2 className="h-4 w-4 text-primary" />
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="text-2xl font-bold">{totalCvesTracked}</div>
                  </CardContent>
                </Card>

                <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
                  <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("avgCvss")}</span>
                    <Shield className="h-4 w-4 text-amber-500" />
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="text-2xl font-bold text-amber-500">{averageCvss}</div>
                  </CardContent>
                </Card>

                <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
                  <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("criticalCves")}</span>
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="text-2xl font-bold text-red-500">{criticalCount}</div>
                  </CardContent>
                </Card>

                <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
                  <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("activeExploits")}</span>
                    <Globe className="h-4 w-4 text-red-500 animate-pulse" />
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="text-2xl font-bold text-red-500">{exploitedCves.length}</div>
                  </CardContent>
                </Card>
              </div>

              {/* Visual Analytics Section */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Card 1: CVSS Severity Distribution */}
                <Card className="border shadow-sm bg-card/65 backdrop-blur-md">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                      <BarChart2 className="h-4 w-4 text-primary" />
                      {language === "pt" ? "Distribuição de Severidade CVSS" : "CVSS Severity Distribution"}
                    </CardTitle>
                    <CardDescription className="text-xs">
                      {language === "pt" ? "Contagem baseada nos relatórios de vulnerabilidades recentes + KEV" : "Breakdown of recent CVEs + active exploits by CVSS score bands"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-4 flex flex-col justify-end min-h-[220px]">
                    {/* Dynamic Vertical Bar Chart */}
                    <div className="flex items-end justify-around h-36 border-b border-border/60 pb-1">
                      {(() => {
                        const distribution = [
                          { label: "Critical (>=9.0)", count: cvssDistribution.critical, color: "bg-red-500/80 hover:bg-red-500", labelShort: "Crit" },
                          { label: "High (7.0-8.9)", count: cvssDistribution.high, color: "bg-orange-500/80 hover:bg-orange-500", labelShort: "High" },
                          { label: "Medium (4.0-6.9)", count: cvssDistribution.medium, color: "bg-yellow-500/80 hover:bg-yellow-500", labelShort: "Med" },
                          { label: "Low (<4.0)", count: cvssDistribution.low, color: "bg-green-500/80 hover:bg-green-500", labelShort: "Low" },
                          { label: "N/A", count: cvssDistribution.na, color: "bg-slate-500/80 hover:bg-slate-500", labelShort: "N/A" }
                        ];
                        const maxCount = Math.max(...distribution.map(d => d.count)) || 1;
                        
                        return distribution.map((item, idx) => {
                          const heightPct = Math.max(8, (item.count / maxCount) * 100);
                          return (
                            <div key={idx} className="flex flex-col items-center group relative w-12 sm:w-16">
                              {/* Tooltip on hover */}
                              <div className="absolute -top-10 scale-0 group-hover:scale-100 transition-all bg-popover text-popover-foreground border shadow text-[10px] px-2 py-1 rounded font-bold z-10 whitespace-nowrap pointer-events-none">
                                {item.label}: {item.count}
                              </div>
                              
                              {/* Bar Wrapper Container with fixed height to allow percentage child height calculation */}
                              <div className="h-24 w-full flex items-end justify-center">
                                <div 
                                  style={{ height: `${heightPct}%` }}
                                  className={`w-8 sm:w-10 ${item.color} rounded-t-md transition-all duration-300 flex items-center justify-center`}
                                >
                                  <span className="text-[10px] font-bold text-white mb-auto pt-1 font-mono group-hover:block hidden">
                                    {item.count}
                                  </span>
                                </div>
                              </div>
                              
                              {/* Label */}
                              <span className="text-[10px] font-bold text-muted-foreground mt-2 truncate w-full text-center">
                                {item.labelShort}
                              </span>
                              
                              <span className="text-[10px] font-mono text-muted-foreground font-semibold mt-0.5">
                                {item.count}
                              </span>
                            </div>
                          );
                        });
                      })()}
                    </div>
                  </CardContent>
                </Card>

                {/* Card 2: Top Targeted Vendors (CISA KEV) */}
                <Card className="border shadow-sm bg-card/65 backdrop-blur-md flex flex-col justify-between">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                      <Globe className="h-4 w-4 text-primary animate-pulse" />
                      {language === "pt" ? "Fabricantes Mais Visados (CISA KEV)" : "Top Targeted Vendors (CISA KEV)"}
                    </CardTitle>
                    <CardDescription className="text-xs">
                      {language === "pt" ? "Fabricantes com maior frequência no catálogo de exploração ativa" : "Most targeted vendors in CISA's Known Exploited Vulnerabilities catalog"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-4 flex-1 flex flex-col justify-center space-y-3.5">
                    {topTargetedVendors.length === 0 ? (
                      <div className="text-center text-xs text-muted-foreground py-8">
                        {language === "pt" ? "Nenhum dado disponível." : "No data available."}
                      </div>
                    ) : (
                      (() => {
                        const maxCount = Math.max(...topTargetedVendors.map(v => v.count)) || 1;
                        return topTargetedVendors.map((vendor, idx) => {
                          const pct = Math.round((vendor.count / exploitedCves.length) * 100);
                          const widthPct = Math.max(5, (vendor.count / maxCount) * 100);
                          return (
                            <div key={idx} className="space-y-1.5">
                              <div className="flex justify-between items-center text-xs">
                                <span className="font-bold text-foreground truncate max-w-[200px]" title={vendor.name}>
                                  {idx + 1}. {vendor.name}
                                </span>
                                <span className="font-mono text-muted-foreground text-[11px]">
                                  <strong className="text-primary">{vendor.count}</strong> exploits ({pct}%)
                                </span>
                              </div>
                              <div className="h-2 w-full bg-muted/40 rounded-full overflow-hidden border border-primary/5 flex">
                                <div 
                                  style={{ width: `${widthPct}%` }}
                                  className="bg-primary/80 hover:bg-primary transition-all duration-300 rounded-full"
                                />
                              </div>
                            </div>
                          );
                        });
                      })()
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Search Bar */}
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={t("searchCves")}
                  value={searchCveQuery}
                  onChange={(e) => setSearchCveQuery(e.target.value)}
                  className="pl-9 bg-card"
                />
              </div>

              {/* Sub tabs: Recent vs Exploited */}
              <Tabs defaultValue="exploited" className="w-full">
                <TabsList className="justify-start overflow-x-auto h-auto p-1 bg-muted/30 border-b border-border/60 rounded-none w-full flex gap-4">
                  <TabsTrigger value="exploited" className="bg-transparent border-b-2 rounded-none px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent">
                    {t("exploitedCves")}
                  </TabsTrigger>
                  <TabsTrigger value="recent" className="bg-transparent border-b-2 rounded-none px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent">
                    {t("latestCves")}
                  </TabsTrigger>
                </TabsList>

                {/* Exploited CVEs list */}
                <TabsContent value="exploited" className="pt-4">
                  {loadingExploited ? (
                    <div className="space-y-3 py-6">
                      {[1, 2, 3].map(n => (
                        <div key={n} className="h-16 w-full bg-muted/40 animate-pulse rounded-lg"></div>
                      ))}
                    </div>
                  ) : filteredExploitedCves.length === 0 ? (
                    <div className="p-12 border border-dashed rounded-xl text-center bg-card">
                      <AlertTriangle className="h-12 w-12 text-muted-foreground/50 mx-auto mb-3" />
                      <p className="text-muted-foreground font-medium">{t("noCvesFound")}</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 gap-4">
                      {filteredExploitedCves.map((cve) => (
                        <Card key={cve.cveID} className="border shadow-sm bg-card hover:shadow-md transition-all">
                          <CardHeader className="pb-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div className="flex items-center gap-3">
                              <Badge variant="outline" className="font-mono text-sm border-red-500/30 text-red-500 bg-red-500/5">
                                {cve.cveID}
                              </Badge>
                              <Badge variant="secondary">
                                {cve.vendorProject} - {cve.product}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-muted-foreground">
                                {t("dueDate")}: <strong className="text-red-500">{cve.dueDate}</strong>
                              </span>
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 px-2.5 rounded text-xs gap-1 border-primary/20 hover:bg-primary/5"
                                onClick={() => handlePivotSearch(cve.cveID)}
                                title={t("pivotSearchTooltip")}
                              >
                                <Eye className="h-3 w-3" />
                                {t("pivotSearch")}
                              </Button>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div className="text-sm font-semibold">{cve.vulnerabilityName}</div>
                            <p className="text-sm text-muted-foreground">{cve.shortDescription}</p>
                            
                            {cve.requiredAction && (
                              <div className="p-3 rounded-lg bg-muted/40 border text-xs space-y-1">
                                <div className="font-semibold text-foreground uppercase tracking-wider">{t("requiredAction")}</div>
                                <div className="text-muted-foreground leading-relaxed">{cve.requiredAction}</div>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </TabsContent>

                {/* Recent CVEs list */}
                <TabsContent value="recent" className="pt-4">
                  {loadingCves ? (
                    <div className="space-y-3 py-6">
                      {[1, 2, 3].map(n => (
                        <div key={n} className="h-16 w-full bg-muted/40 animate-pulse rounded-lg"></div>
                      ))}
                    </div>
                  ) : cveError ? (
                    <div className="p-8 border border-destructive/20 rounded-xl bg-destructive/5 text-center">
                      <AlertTriangle className="h-10 w-10 text-destructive mx-auto mb-3" />
                      <p className="text-destructive font-medium">{cveError}</p>
                    </div>
                  ) : filteredRecentCves.length === 0 ? (
                    <div className="p-12 border border-dashed rounded-xl text-center bg-card">
                      <AlertTriangle className="h-12 w-12 text-muted-foreground/50 mx-auto mb-3" />
                      <p className="text-muted-foreground font-medium">{t("noCvesFound")}</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 gap-4">
                      {filteredRecentCves.map((cve) => {
                        const sev = getCvssSeverity(cve.cvss);
                        return (
                          <Card key={cve.id} className="border shadow-sm bg-card hover:shadow-md transition-all">
                            <CardHeader className="pb-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <div className="flex items-center gap-3">
                                <Badge variant="outline" className="font-mono text-sm border-primary/30 text-primary bg-primary/5">
                                  {cve.id}
                                </Badge>
                                <Badge variant="outline" className={sev.color}>
                                  {t("severity")}: {sev.label} {cve.cvss ? `(${cve.cvss})` : ""}
                                </Badge>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-muted-foreground">
                                  {t("publishDate")}: {cve.Published ? new Date(cve.Published).toLocaleDateString() : "N/A"}
                                </span>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="h-7 px-2.5 rounded text-xs gap-1 border-primary/20 hover:bg-primary/5"
                                  onClick={() => handlePivotSearch(cve.id)}
                                  title={t("pivotSearchTooltip")}
                                >
                                  <Eye className="h-3 w-3" />
                                  {t("pivotSearch")}
                                </Button>
                              </div>
                            </CardHeader>
                            <CardContent>
                              <p className="text-sm text-muted-foreground">{cve.summary}</p>
                            </CardContent>
                          </Card>
                        );
                      })}
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </TabsContent>

          </Tabs>

        </div>
      </div>
      <Footer />
    </div>
  );
};

export default Newsletter;
