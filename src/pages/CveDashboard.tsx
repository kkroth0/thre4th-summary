import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, Shield, AlertTriangle, Search, Eye, BarChart2, RefreshCw, ExternalLink, X, ChevronLeft, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  const { t, language, tr } = useLanguage();
  
  // CVE Dashboard States
  const [recentCves, setRecentCves] = useState<CveItem[]>([]);
  const [exploitedCves, setExploitedCves] = useState<ExploitedCve[]>([]);
  const [searchCveQuery, setSearchCveQuery] = useState("");
  const [loadingCves, setLoadingCves] = useState(true);
  const [loadingExploited, setLoadingExploited] = useState(true);
  const [cveError, setCveError] = useState<string | null>(null);

  // Filters State
  const [selectedVendor, setSelectedVendor] = useState("all");
  const [selectedSoftware, setSelectedSoftware] = useState("all");
  const [selectedSeverity, setSelectedSeverity] = useState("all");

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
  const [lastUpdatedCves, setLastUpdatedCves] = useState<Date | null>(null);
  const [isRefreshingCves, setIsRefreshingCves] = useState(false);

  // Load from local storage cache on mount
  useEffect(() => {
    const cachedRecent = localStorage.getItem("cached_recent_cves");
    const cachedExploited = localStorage.getItem("cached_exploited_cves");
    
    if (cachedRecent) {
      try { setRecentCves(JSON.parse(cachedRecent)); } catch (e) { console.error(e); }
    }
    if (cachedExploited) {
      try { setExploitedCves(JSON.parse(cachedExploited)); } catch (e) { console.error(e); }
    }
  }, []);

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
      
      setRecentCves(prev => {
        const merged = [...prev];
        const seenIds = new Set(merged.map(item => item.id));
        recentData.forEach((item: CveItem) => {
          if (!seenIds.has(item.id)) {
            merged.push(item);
            seenIds.add(item.id);
          }
        });
        merged.sort((a, b) => new Date(b.Published).getTime() - new Date(a.Published).getTime());
        localStorage.setItem("cached_recent_cves", JSON.stringify(merged));
        return merged;
      });

      setExploitedCves(prev => {
        const merged = [...prev];
        const seenIds = new Set(merged.map(item => item.cveID));
        exploitedData.forEach((item: ExploitedCve) => {
          if (!seenIds.has(item.cveID)) {
            merged.push(item);
            seenIds.add(item.cveID);
          }
        });
        merged.sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime());
        localStorage.setItem("cached_exploited_cves", JSON.stringify(merged));
        return merged;
      });

      setLastUpdatedCves(new Date());
    } catch (err: any) {
      console.error(err);
      if (!isBackground) {
        setCveError(err.message);
      } else {
        toast.error(tr({ pt: "Erro ao atualizar CVEs em segundo plano", en: "Failed to background refresh CVEs", es: "Error al actualizar CVEs en segundo plano", fr: "Échec de l'actualisation des CVE en arrière-plan" }));
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
    toast.success(tr({ pt: `Pesquisando ${cveId} no painel...`, en: `Searching ${cveId} on main dashboard...`, es: `Buscando ${cveId} en el panel...`, fr: `Recherche de ${cveId} dans le tableau de bord...` }));
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

  // Extract unique vendors from exploitedCves
  const uniqueVendors = useMemo(() => {
    const vendors = new Set<string>();
    exploitedCves.forEach(cve => {
      if (cve.vendorProject) {
        vendors.add(cve.vendorProject);
      }
    });
    return Array.from(vendors).sort();
  }, [exploitedCves]);

  // Extract unique products from exploitedCves (filtered by selectedVendor if active)
  const uniqueSoftwares = useMemo(() => {
    const products = new Set<string>();
    exploitedCves.forEach(cve => {
      if (selectedVendor !== "all" && cve.vendorProject !== selectedVendor) {
        return;
      }
      if (cve.product) {
        products.add(cve.product);
      }
    });
    return Array.from(products).sort();
  }, [exploitedCves, selectedVendor]);

  // Reset selectedSoftware when selectedVendor changes if it's no longer in the list
  useEffect(() => {
    if (selectedSoftware !== "all" && !uniqueSoftwares.includes(selectedSoftware)) {
      setSelectedSoftware("all");
    }
  }, [selectedVendor, uniqueSoftwares, selectedSoftware]);

  // Filter CVEs
  const filteredRecentCves = useMemo(() => {
    return recentCves.filter(cve => {
      // 0. Month/Year Filter
      const d = new Date(cve.Published);
      if (d.getMonth() !== selectedMonth || d.getFullYear() !== selectedYear) {
        return false;
      }

      // 1. Text Search Filter
      const queryMatch = 
        (cve.id ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
        (cve.summary ?? '').toLowerCase().includes(searchCveQuery.toLowerCase());
      
      if (!queryMatch) return false;

      // 2. Vendor Filter (matching summary since recentCves don't have structured vendor fields)
      if (selectedVendor !== "all") {
        const vendorLower = selectedVendor.toLowerCase();
        if (!(cve.summary ?? '').toLowerCase().includes(vendorLower)) {
          return false;
        }
      }

      // 3. Software/Product Filter (matching summary)
      if (selectedSoftware !== "all") {
        const softwareLower = selectedSoftware.toLowerCase();
        if (!(cve.summary ?? '').toLowerCase().includes(softwareLower)) {
          return false;
        }
      }

      // 4. Severity Filter
      if (selectedSeverity !== "all") {
        const sev = getCvssSeverity(cve.cvss);
        if (sev.label !== selectedSeverity) {
          return false;
        }
      }

      return true;
    });
  }, [recentCves, searchCveQuery, selectedVendor, selectedSoftware, selectedSeverity, selectedMonth, selectedYear]);

  const filteredExploitedCves = useMemo(() => {
    return exploitedCves.filter(cve => {
      // 0. Month/Year Filter
      const d = new Date(cve.dateAdded);
      if (d.getMonth() !== selectedMonth || d.getFullYear() !== selectedYear) {
        return false;
      }

      // 1. Text Search Filter
      const queryMatch = 
        (cve.cveID ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
        (cve.vendorProject ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
        (cve.product ?? '').toLowerCase().includes(searchCveQuery.toLowerCase()) ||
        (cve.vulnerabilityName ?? '').toLowerCase().includes(searchCveQuery.toLowerCase());

      if (!queryMatch) return false;

      // 2. Vendor Filter
      if (selectedVendor !== "all" && cve.vendorProject !== selectedVendor) {
        return false;
      }

      // 3. Software/Product Filter
      if (selectedSoftware !== "all" && cve.product !== selectedSoftware) {
        return false;
      }

      // 4. Severity Filter (cross-referencing with recentCves if possible)
      if (selectedSeverity !== "all") {
        const recentMatch = recentCves.find(r => r.id === cve.cveID);
        const sevLabel = recentMatch ? getCvssSeverity(recentMatch.cvss).label : "Critical";
        if (sevLabel !== selectedSeverity) {
          return false;
        }
      }

      return true;
    });
  }, [exploitedCves, recentCves, searchCveQuery, selectedVendor, selectedSoftware, selectedSeverity, selectedMonth, selectedYear]);

  // Statistics calculation for CVEs
  const totalCvesTracked = filteredRecentCves.length + filteredExploitedCves.length;
  const validCvssList = filteredRecentCves
    .map(c => c.cvss)
    .filter((c): c is number => c !== null && c !== undefined && !isNaN(Number(c)))
    .map(Number);
  
  const exploitedCvssList = filteredExploitedCves
    .map(cve => {
      const recentMatch = recentCves.find(r => r.id === cve.cveID);
      return recentMatch ? recentMatch.cvss : null;
    })
    .filter((c): c is number => c !== null && c !== undefined && !isNaN(Number(c)))
    .map(Number);

  const combinedCvssList = [...validCvssList, ...exploitedCvssList];
  const averageCvss = combinedCvssList.length > 0 ? (combinedCvssList.reduce((a, b) => a + b, 0) / combinedCvssList.length).toFixed(1) : "8.2";

  // Detailed CVSS Severity counts
  const cvssDistribution = useMemo(() => {
    let critical = 0; // >= 9.0
    let high = 0;     // 7.0 - 8.9
    let medium = 0;   // 4.0 - 6.9
    let low = 0;      // 0.1 - 3.9
    let na = 0;       // null/NaN/0

    filteredRecentCves.forEach(cve => {
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

    filteredExploitedCves.forEach(cve => {
      const recentMatch = recentCves.find(r => r.id === cve.cveID);
      const val = recentMatch ? (recentMatch.cvss !== null && recentMatch.cvss !== undefined ? Number(recentMatch.cvss) : null) : null;
      
      if (val === null || isNaN(val)) {
        critical++;
      } else {
        if (val >= 9.0) critical++;
        else if (val >= 7.0) high++;
        else if (val >= 4.0) medium++;
        else if (val > 0) low++;
        else critical++;
      }
    });

    return { critical, high, medium, low, na };
  }, [filteredRecentCves, filteredExploitedCves, recentCves]);

  const criticalCount = cvssDistribution.critical;

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
    <PageLayout width="max-w-7xl">
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Shield className="h-6 w-6 text-primary" />
                {t("cveDashboard") || "CVE Dashboard"}
              </h1>
              <p className="text-xs text-muted-foreground mt-1">
                {tr({
                  pt: "Acompanhe e analise vulnerabilidades críticas recentemente publicadas e explorações ativas relatadas pela CISA",
                  en: "Track and analyze critical vulnerabilities and active exploits in the wild reported by CISA",
                  es: "Monitorea y analiza vulnerabilidades críticas recién publicadas y exploits activos reportados por CISA",
                  fr: "Suivez et analysez les vulnérabilités critiques récemment publiées et les exploits actifs signalés par la CISA",
                })}
              </p>
            </div>
            {/* Last updated and refresh controls */}
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              {isRefreshingCves && <span className="animate-pulse text-primary font-medium">{tr({ pt: "Atualizando...", en: "Refreshing...", es: "Actualizando...", fr: "Actualisation..." })}</span>}
              <span>
                {tr({ pt: "Última atualização: ", en: "Last updated: ", es: "Última actualización: ", fr: "Dernière mise à jour : " })}
                {lastUpdatedCves ? lastUpdatedCves.toLocaleTimeString() : "Pending"}
              </span>
              <Button
                variant="outline"
                size="icon"
                className="h-8 w-8 border-border/50 hover:bg-primary/5 shrink-0"
                disabled={loadingCves || isRefreshingCves}
                onClick={() => loadCves()}
                title={tr({ pt: "Atualizar dados", en: "Refresh data", es: "Actualizar datos", fr: "Actualiser les données" })}
              >
                <RefreshCw className={`h-4 w-4 ${(loadingCves || isRefreshingCves) ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </div>

          {/* Metrics row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="border shadow-sm bg-muted/40 ">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{tr({ pt: "Total de Ameaças", en: "Total Tracked", es: "Total Rastreado", fr: "Total Suivi" })}</span>
                <BarChart2 className="h-4 w-4 text-primary" />
              </CardHeader>
              <CardContent className="pt-0">
                <div className="text-2xl font-bold">{totalCvesTracked}</div>
              </CardContent>
            </Card>

            <Card className="border shadow-sm bg-muted/40 ">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("avgCvss") || "Avg CVSS"}</span>
                <Shield className="h-4 w-4 text-amber-500" />
              </CardHeader>
              <CardContent className="pt-0">
                <div className="text-2xl font-bold text-amber-500">{averageCvss}</div>
              </CardContent>
            </Card>

            <Card className="border shadow-sm bg-muted/40 ">
              <CardHeader className="py-4 flex flex-row items-center justify-between pb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("criticalCves") || "Critical CVEs"}</span>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent className="pt-0">
                <div className="text-2xl font-bold text-red-500">{criticalCount}</div>
              </CardContent>
            </Card>

            <Card className="border shadow-sm bg-muted/40 ">
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
            <Card className="border shadow-sm bg-muted/40 ">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <BarChart2 className="h-4 w-4 text-primary" />
                  {tr({ pt: "Distribuição de Severidade CVSS", en: "CVSS Severity Distribution", es: "Distribución de Severidad CVSS", fr: "Distribution de la Gravité CVSS" })}
                </CardTitle>
                <CardDescription className="text-xs">
                  {tr({ pt: "Contagem baseada nos relatórios de vulnerabilidades recentes + KEV", en: "Breakdown of recent CVEs + active exploits by CVSS score bands", es: "Desglose de CVEs recientes + exploits activos por bandas de puntuación CVSS", fr: "Répartition des CVE récents + exploits actifs par tranches de score CVSS" })}
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
            <Card className="border shadow-sm bg-muted/40  flex flex-col justify-between">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <Globe className="h-4 w-4 text-primary animate-pulse" />
                  {tr({ pt: "Fabricantes Mais Visados (CISA KEV)", en: "Top Targeted Vendors (CISA KEV)", es: "Proveedores Más Atacados (CISA KEV)", fr: "Fournisseurs les Plus Ciblés (CISA KEV)" })}
                </CardTitle>
                <CardDescription className="text-xs">
                  {tr({ pt: "Fabricantes com maior frequência no catálogo de exploração activa", en: "Most targeted vendors in CISA's Known Exploited Vulnerabilities catalog", es: "Proveedores con mayor frecuencia en el catálogo de explotación activa de CISA", fr: "Fournisseurs les plus fréquents dans le catalogue d'exploitation active de la CISA" })}
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-4 flex-1 flex flex-col justify-center space-y-3.5">
                {topTargetedVendors.length === 0 ? (
                  <div className="text-center text-xs text-muted-foreground py-8">
                    {tr({ pt: "Nenhum dado disponível.", en: "No data available.", es: "No hay datos disponibles.", fr: "Aucune donnée disponible." })}
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
                          <div className="h-2 w-full bg-muted/40 rounded-full overflow-hidden border border-border/50 flex">
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
              className="pl-9 bg-card h-11 rounded-xl"
            />
          </div>

          {/* Filters Bar */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 bg-muted/40  p-5 rounded-xl border border-border/50 ">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 flex-1">
              {/* Vendor Select */}
              <div className="flex flex-col gap-1.5">
                <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider pl-1">
                  {tr({ pt: "Fabricante", en: "Vendor", es: "Proveedor", fr: "Fournisseur" })}
                </span>
                <Select value={selectedVendor} onValueChange={setSelectedVendor}>
                  <SelectTrigger className="h-10.5 bg-background/40 border-border/50 rounded-xl text-xs font-semibold focus:ring-primary/20 hover:bg-background/60 transition-all">
                    <SelectValue placeholder={tr({ pt: "Todos Fabricantes", en: "All Vendors", es: "Todos los Proveedores", fr: "Tous les Fournisseurs" })} />
                  </SelectTrigger>
                  <SelectContent className="max-h-80 border-border/50 bg-popover/95  rounded-xl">
                    <SelectItem value="all" className="text-xs font-semibold rounded-lg">
                      {tr({ pt: "Todos Fabricantes", en: "All Vendors", es: "Todos los Proveedores", fr: "Tous les Fournisseurs" })}
                    </SelectItem>
                    {uniqueVendors.map(vendor => (
                      <SelectItem key={vendor} value={vendor} className="text-xs rounded-lg">
                        {vendor}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Software Select */}
              <div className="flex flex-col gap-1.5">
                <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider pl-1">
                  {tr({ pt: "Software / Produto", en: "Software / Product", es: "Software / Producto", fr: "Logiciel / Produit" })}
                </span>
                <Select value={selectedSoftware} onValueChange={setSelectedSoftware}>
                  <SelectTrigger className="h-10.5 bg-background/40 border-border/50 rounded-xl text-xs font-semibold focus:ring-primary/20 hover:bg-background/60 transition-all">
                    <SelectValue placeholder={tr({ pt: "Todos Softwares", en: "All Softwares", es: "Todos los Software", fr: "Tous les Logiciels" })} />
                  </SelectTrigger>
                  <SelectContent className="max-h-80 border-border/50 bg-popover/95  rounded-xl">
                    <SelectItem value="all" className="text-xs font-semibold rounded-lg">
                      {tr({ pt: "Todos Softwares", en: "All Softwares", es: "Todos los Software", fr: "Tous les Logiciels" })}
                    </SelectItem>
                    {uniqueSoftwares.map(software => (
                      <SelectItem key={software} value={software} className="text-xs rounded-lg">
                        {software}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Severity Select */}
              <div className="flex flex-col gap-1.5">
                <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider pl-1">
                  {tr({ pt: "Severidade", en: "Severity", es: "Severidad", fr: "Gravité" })}
                </span>
                <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                  <SelectTrigger className="h-10.5 bg-background/40 border-border/50 rounded-xl text-xs font-semibold focus:ring-primary/20 hover:bg-background/60 transition-all">
                    <SelectValue placeholder={tr({ pt: "Todas Severidades", en: "All Severities", es: "Todas las Severidades", fr: "Toutes les Gravités" })} />
                  </SelectTrigger>
                  <SelectContent className="border-border/50 bg-popover/95  rounded-xl">
                    <SelectItem value="all" className="text-xs font-semibold rounded-lg">
                      {tr({ pt: "Todas Severidades", en: "All Severities", es: "Todas las Severidades", fr: "Toutes les Gravités" })}
                    </SelectItem>
                    <SelectItem value="Critical" className="text-xs rounded-lg text-red-500 font-medium">Critical</SelectItem>
                    <SelectItem value="High" className="text-xs rounded-lg text-orange-500 font-medium">High</SelectItem>
                    <SelectItem value="Medium" className="text-xs rounded-lg text-yellow-500 font-medium">Medium</SelectItem>
                    <SelectItem value="Low" className="text-xs rounded-lg text-green-500 font-medium">Low</SelectItem>
                    <SelectItem value="N/A" className="text-xs rounded-lg text-slate-400 font-medium">N/A</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Reset Filters Button */}
            {(selectedVendor !== "all" || selectedSoftware !== "all" || selectedSeverity !== "all" || searchCveQuery !== "") ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSelectedVendor("all");
                  setSelectedSoftware("all");
                  setSelectedSeverity("all");
                  setSearchCveQuery("");
                }}
                className="h-10 px-4 rounded-xl text-xs text-muted-foreground hover:text-foreground hover:bg-muted/50 gap-1.5 transition-all font-semibold shrink-0 self-start md:self-end"
              >
                <X className="h-4 w-4" />
                {tr({ pt: "Limpar Filtros", en: "Clear Filters", es: "Limpiar Filtros", fr: "Effacer les Filtres" })}
              </Button>
            ) : null}
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
                            className="h-7 px-2.5 rounded text-xs gap-1 border-border/50 hover:bg-primary/5"
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
                      <Card key={cve.id} className="border shadow-sm bg-card hover:shadow-md transition-all border-border/50 hover:border-border/50">
                        <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/50">
                          <div className="flex flex-wrap items-center gap-2.5">
                            <Badge variant="outline" className="font-mono text-sm border-border/50 text-primary bg-primary/5 font-bold">
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
                              className="h-7 px-2.5 rounded text-xs gap-1 border-border/50 hover:bg-primary/5"
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
                                  } catch {
                                    label = "Reference Link";
                                  }
                                  return (
                                    <a
                                      key={idx}
                                      href={url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="inline-flex items-center gap-1 text-[11px] font-medium text-primary hover:underline bg-primary/5 hover:bg-primary/10 border border-border/50 px-2 py-0.5 rounded transition-all"
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
    </PageLayout>
  );
};

export default CveDashboard;
