import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, Shield, AlertTriangle, Search, Eye, BarChart2, RefreshCw, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";
import { toast } from "sonner";

interface CveItem {
  id: string;
  cvss: number | null;
  summary: string;
  Published: string;
  Modified?: string;
  source?: string;
  vectorString?: string;
  mitigation?: string;
  references?: string[];
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

const CveDashboard = () => {
  const { isCollapsed } = useSidebar();
  const { t, language } = useLanguage();
  
  // CVE Dashboard States
  const [recentCves, setRecentCves] = useState<CveItem[]>([]);
  const [exploitedCves, setExploitedCves] = useState<ExploitedCve[]>([]);
  const [searchCveQuery, setSearchCveQuery] = useState("");
  const [loadingCves, setLoadingCves] = useState(true);
  const [loadingExploited, setLoadingExploited] = useState(true);
  const [cveError, setCveError] = useState<string | null>(null);

  // Background Polling / Last Updated States
  const [lastUpdatedCves, setLastUpdatedCves] = useState<Date | null>(null);
  const [isRefreshingCves, setIsRefreshingCves] = useState(false);

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
    loadCves();

    // Polling interval: 10 min for CVEs (600000ms)
    const cvesInterval = setInterval(() => {
      loadCves(true);
    }, 600000);

    return () => {
      clearInterval(cvesInterval);
    };
  }, []);

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
    <div className="min-h-screen bg-background flex flex-col lg:pl-56">
      <Header showBackButton />

      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Shield className="h-6 w-6 text-primary" />
                {t("cveDashboard") || "CVE Dashboard"}
              </h1>
              <p className="text-xs text-muted-foreground mt-1">
                {language === "pt"
                  ? "Acompanhe e analise vulnerabilidades críticas recentemente publicadas e explorações ativas relatadas pela CISA"
                  : "Track and analyze critical vulnerabilities and active exploits in the wild reported by CISA"}
              </p>
            </div>
            {/* Last updated and refresh controls */}
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              {isRefreshingCves && <span className="animate-pulse text-primary font-medium">{language === "pt" ? "Atualizando..." : "Refreshing..."}</span>}
              <span>
                {language === "pt" ? "Última atualização: " : "Last updated: "}
                {lastUpdatedCves ? lastUpdatedCves.toLocaleTimeString() : "Pending"}
              </span>
              <Button
                variant="outline"
                size="icon"
                className="h-8 w-8 border-primary/20 hover:bg-primary/5 shrink-0"
                disabled={loadingCves || isRefreshingCves}
                onClick={() => loadCves()}
                title={language === "pt" ? "Atualizar dados" : "Refresh data"}
              >
                <RefreshCw className={`h-4 w-4 ${(loadingCves || isRefreshingCves) ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </div>

          {/* Metrics row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{language === "pt" ? "Total de Ameaças" : t("totalTracked") || "Total Tracked"}</span>
                <BarChart2 className="h-4 w-4 text-primary" />
              </CardHeader>
              <CardContent className="pt-0">
                <div className="text-2xl font-bold">{totalCvesTracked}</div>
              </CardContent>
            </Card>

            <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("avgCvss") || "Avg CVSS"}</span>
                <Shield className="h-4 w-4 text-amber-500" />
              </CardHeader>
              <CardContent className="pt-0">
                <div className="text-2xl font-bold text-amber-500">{averageCvss}</div>
              </CardContent>
            </Card>

            <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("criticalCves") || "Critical CVEs"}</span>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent className="pt-0">
                <div className="text-2xl font-bold text-red-500">{criticalCount}</div>
              </CardContent>
            </Card>

            <Card className="border shadow-sm bg-card/60 backdrop-blur-sm">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("activeExploits") || "Active Exploits"}</span>
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
                  {language === "pt" ? "Fabricantes com maior frequência no catálogo de exploração activa" : "Most targeted vendors in CISA's Known Exploited Vulnerabilities catalog"}
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
              placeholder={t("searchCves") || "Search CVEs..."}
              value={searchCveQuery}
              onChange={(e) => setSearchCveQuery(e.target.value)}
              className="pl-9 bg-card"
            />
          </div>

          {/* Sub tabs: Recent vs Exploited */}
          <Tabs defaultValue="exploited" className="w-full">
            <TabsList className="justify-start overflow-x-auto h-auto p-1 bg-muted/30 border-b border-border/60 rounded-none w-full flex gap-4">
              <TabsTrigger value="exploited" className="bg-transparent border-b-2 rounded-none px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent">
                {t("exploitedCves") || "Exploited CVEs"}
              </TabsTrigger>
              <TabsTrigger value="recent" className="bg-transparent border-b-2 rounded-none px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent">
                {t("latestCves") || "Recent CVEs"}
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
                  <p className="text-muted-foreground font-medium">{t("noCvesFound") || "No CVEs found"}</p>
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
                            {t("dueDate") || "Due Date"}: <strong className="text-red-500">{cve.dueDate}</strong>
                          </span>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-2.5 rounded text-xs gap-1 border-primary/20 hover:bg-primary/5"
                            onClick={() => handlePivotSearch(cve.cveID)}
                            title={t("pivotSearchTooltip") || "Pivot search on dashboard"}
                          >
                            <Eye className="h-3 w-3" />
                            {t("pivotSearch") || "Pivot Search"}
                          </Button>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        <div className="text-sm font-semibold">{cve.vulnerabilityName}</div>
                        <p className="text-sm text-muted-foreground">{cve.shortDescription}</p>
                        
                        {cve.requiredAction && (
                          <div className="p-3 rounded-lg bg-muted/40 border text-xs space-y-1">
                            <div className="font-semibold text-foreground uppercase tracking-wider">{t("requiredAction") || "Required Action"}</div>
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
                  <p className="text-muted-foreground font-medium">{t("noCvesFound") || "No CVEs found"}</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {filteredRecentCves.map((cve) => {
                    const sev = getCvssSeverity(cve.cvss);
                    return (
                      <Card key={cve.id} className="border shadow-sm bg-card hover:shadow-md transition-all border-primary/10 hover:border-primary/20">
                        <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-primary/5">
                          <div className="flex flex-wrap items-center gap-2.5">
                            <Badge variant="outline" className="font-mono text-sm border-primary/30 text-primary bg-primary/5 font-bold">
                              {cve.id}
                            </Badge>
                            <Badge variant="outline" className={`${sev.color} font-bold`}>
                              {t("severity") || "Severity"}: {sev.label} {cve.cvss ? `(${cve.cvss})` : ""}
                            </Badge>
                            <Badge variant="outline" className="bg-blue-500/5 text-blue-400 border-blue-500/20 font-medium text-[10px]">
                              Source: {cve.source || "NIST NVD"}
                            </Badge>
                            {cve.vectorString && (
                              <span className="text-[10px] font-mono text-muted-foreground/75 bg-muted/30 px-2 py-0.5 rounded border border-muted/50">
                                {cve.vectorString}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2.5 shrink-0 self-end sm:self-auto">
                            <span className="text-xs text-muted-foreground/70">
                              {t("publishDate") || "Published"}: {cve.Published ? new Date(cve.Published).toLocaleDateString() : "N/A"}
                            </span>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2.5 rounded text-xs gap-1 border-primary/20 hover:bg-primary/5"
                              onClick={() => handlePivotSearch(cve.id)}
                              title={t("pivotSearchTooltip") || "Pivot search on dashboard"}
                            >
                              <Eye className="h-3 w-3" />
                              {t("pivotSearch") || "Pivot Search"}
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent className="pt-4 space-y-4">
                          {/* Description */}
                          <div className="space-y-1.5">
                            <h4 className="text-xs font-semibold text-foreground/80 uppercase tracking-wider">Description</h4>
                            <p className="text-sm text-muted-foreground leading-relaxed">{cve.summary}</p>
                          </div>

                          {/* Mitigation Section */}
                          {cve.mitigation && (
                            <div className="p-3.5 rounded-xl bg-emerald-500/5 border border-emerald-500/10 space-y-1.5">
                              <h4 className="text-xs font-bold text-emerald-500 flex items-center gap-1.5 uppercase tracking-wider">
                                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                                Recommended Mitigation & Remediation
                              </h4>
                              <p className="text-xs text-muted-foreground/90 leading-relaxed">{cve.mitigation}</p>
                            </div>
                          )}

                          {/* References/URLs */}
                          {cve.references && cve.references.length > 0 && (
                            <div className="space-y-2">
                              <h4 className="text-xs font-semibold text-foreground/80 uppercase tracking-wider">Reference Links (NIST & Vendor Advisories)</h4>
                              <div className="flex flex-wrap gap-2">
                                {cve.references.map((url, idx) => {
                                  let label = "Reference Link";
                                  try {
                                    const hostname = new URL(url).hostname;
                                    label = hostname.replace("www.", "");
                                  } catch (e) {}
                                  return (
                                    <a
                                      key={idx}
                                      href={url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="inline-flex items-center gap-1 text-[11px] font-medium text-primary hover:underline bg-primary/5 hover:bg-primary/10 border border-primary/10 px-2 py-0.5 rounded transition-all"
                                    >
                                      {label}
                                      <ExternalLink className="h-2.5 w-2.5" />
                                    </a>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </TabsContent>
          </Tabs>

        </div>
      </div>
      <Footer />
    </div>
  );
};

export default CveDashboard;
