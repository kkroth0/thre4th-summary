import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Shield, AlertTriangle, Bug, FileSearch, Globe, Link as LinkIcon, Radar, Database, Eye, Search, BookOpen, Layers, LayoutGrid, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ThreatSummary } from "@/components/ThreatSummary";
import { VendorCard } from "@/components/VendorCard";
import { VendorContent } from "@/components/VendorContent";
import { VendorFilter } from "@/components/VendorFilter";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Footer } from "@/components/Footer";
import { HistorySidebar } from "@/components/HistorySidebar";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";

import { ThreatCharts } from "@/components/ThreatCharts";
import { VendorDataTable } from "@/components/VendorDataTable";
import { QuickActions } from "@/components/QuickActions";
import { ViewToggle } from "@/components/ViewToggle";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { MultiIpSummary } from "@/components/MultiIpSummary";
import { fetchThreatDataProgressive } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import jsPDF from "jspdf";
import html2canvas from "html2canvas";

interface SearchFormProps {
  query: string;
  setQuery: (query: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  className?: string;
}

const SearchForm = ({ query, setQuery, onSubmit, isLoading, className = "" }: SearchFormProps) => {
  const { t } = useLanguage();

  const ipv4Regex = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const extractedIps = query ? Array.from(new Set(query.match(ipv4Regex) || [])) : [];

  return (
    <div className={`w-full ${className}`}>
      <form onSubmit={onSubmit} className="w-full">
        <div className="flex flex-col gap-3 relative">
          <div className="relative group">
            <Textarea
              placeholder="Paste logs, IPs, domains, or hashes here (e.g. 8.8.8.8, malicious.com)..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="min-h-[140px] resize-y text-base p-4 bg-background/50 backdrop-blur-sm border-2 focus-visible:ring-primary/50 transition-all rounded-xl [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  onSubmit(e as any);
                }
              }}
            />
            {extractedIps.length > 0 && (
              <div className="absolute top-4 right-4 max-w-[50%] flex flex-wrap justify-end gap-1.5 opacity-80 pointer-events-none">
                {extractedIps.slice(0, 3).map(ip => (
                  <Badge key={ip} variant="secondary" className="font-mono text-[10px] px-1.5 py-0 shadow-sm border-primary/20 bg-primary/5 text-primary">
                    {ip}
                  </Badge>
                ))}
                {extractedIps.length > 3 && (
                  <Badge variant="outline" className="font-mono text-[10px] px-1.5 py-0 bg-background/80 shadow-sm backdrop-blur">
                    +{extractedIps.length - 3} more
                  </Badge>
                )}
              </div>
            )}
          </div>
          
          <div className="flex items-center justify-between mt-1">
            <div className="flex items-center gap-2 text-xs text-muted-foreground/80 font-medium">
              <CheckCircle2 className={`h-4 w-4 ${extractedIps.length > 0 ? "text-green-500" : "text-muted-foreground/40"}`} />
              {extractedIps.length > 0 
                ? `${extractedIps.length} target${extractedIps.length > 1 ? 's' : ''} parsed (max 35)` 
                : "Awaiting valid IOCs..."}
            </div>
            
            <Button
              type="submit"
              disabled={isLoading || extractedIps.length > 35 || (!query.trim())}
              size="lg"
              className="shadow-md hover:shadow-lg transition-all px-8 rounded-full font-semibold tracking-wide bg-gradient-to-r from-primary to-primary/80"
            >
              {isLoading ? t('analyzing') : <><Search className="mr-2 h-4 w-4" /> {t('analyze')}</>}
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
};

const ALL_VENDORS = [
  "IP Geolocation", "WHOIS", "VirusTotal", "AbuseIPDB", "AlienVault OTX",
  "Shodan", "URLhaus", "MalwareBazaar", "Google Safe Browsing",
  "PhishTank", "Pulsedive",
  "Hybrid Analysis", "CIRCL hashlookup",
  "Criminal IP", "MetaDefender", "PhishStats", "Ransomware.live",
  "OpenPhish", "DShield", "Team Cymru"
];

interface HistoryItem {
  query: string;
  timestamp: number;
  threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
}

const Index = () => {
  const [query, setQuery] = useState("");
  const [selectedVendors, setSelectedVendors] = useState<string[]>(ALL_VENDORS);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  // Changed data to results array to support multi-IP
  const [results, setResults] = useState<ThreatIntelligenceResult[]>([]);
  const [activeTab, setActiveTab] = useState<string>("overview");

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isExportingPDF, setIsExportingPDF] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"cards" | "table">("cards");
  const { toast } = useToast();
  const { t } = useLanguage();

  // Load saved preferences and history
  useEffect(() => {
    const savedVendors = localStorage.getItem("selectedVendors");
    if (savedVendors) {
      try {
        const parsed = JSON.parse(savedVendors);
        // Filter out vendors that are no longer in ALL_VENDORS
        const validVendors = parsed.filter((v: string) => ALL_VENDORS.includes(v));
        setSelectedVendors(validVendors.length > 0 ? validVendors : ALL_VENDORS);
      } catch (e) {
        console.error("Failed to parse saved vendors", e);
        setSelectedVendors(ALL_VENDORS);
      }
    }

    const savedHistory = localStorage.getItem("searchHistory");
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error("Failed to parse history", e);
      }
    }
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();

    const rawQuery = query.trim();

    if (!rawQuery) {
      toast({
        title: t('error'),
        description: t('inputRequired'),
        variant: "destructive",
      });
      return;
    }

    let queries: string[] = [];

    // Extract IPv4 addresses using robust regex
    const ipv4Regex = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    const extractedIps = rawQuery.match(ipv4Regex);

    if (extractedIps && extractedIps.length > 0) {
      // De-duplicate extracted IPs
      queries = Array.from(new Set(extractedIps));
    } else {
      // Fallback: Split by comma, newline, or space for domains/hashes
      queries = rawQuery.split(/[\s,]+/).filter(q => q.length > 0);
      // De-duplicate
      queries = Array.from(new Set(queries));
    }

    if (queries.length > 35) {
      toast({
        title: "Too many targets",
        description: "Please enter a maximum of 35 targets.",
        variant: "destructive",
      });
      return;
    }

    // Validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    const urlRegex = /^(http|https):\/\/[^ "]+$/;

    const invalidQueries = queries.filter(q =>
      !ipRegex.test(q) && !domainRegex.test(q) && !hashRegex.test(q) && !urlRegex.test(q)
    );

    if (invalidQueries.length > 0) {
      toast({
        title: t('invalidInput'),
        description: `Invalid format: ${invalidQueries.join(", ")}`,
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setResults([]); // Clear previous results
    setActiveTab("overview");

    try {
      // Initialize results with loading state
      const initialResults: ThreatIntelligenceResult[] = queries.map(q => ({
        query: q,
        overallScore: 0,
        threatLevel: "unknown",
        totalVendors: selectedVendors.length,
        detections: 0,
        vendorData: selectedVendors.map(vendorName => ({
          name: vendorName,
          data: {},
          loading: true
        }))
      }));
      setResults(initialResults);

      // Process each query
      await Promise.all(queries.map(async (q) => {
        const result = await fetchThreatDataProgressive(q, selectedVendors, (vendorData) => {
          setResults(prev => prev.map(r => {
            if (r.query === q) {
              return {
                ...r,
                vendorData: r.vendorData.map(v =>
                  v.name === vendorData.name ? { ...vendorData, loading: false } : v
                )
              };
            }
            return r;
          }));
        });

        // Update final result for this query
        setResults(prev => prev.map(r => r.query === q ? result : r));

        // Update history
        setHistory(prev => {
          const filtered = prev.filter(item => item.query !== result.query);
          const newHistory = [
            { query: result.query, timestamp: Date.now(), threatLevel: result.threatLevel },
            ...filtered
          ].slice(0, 50);
          localStorage.setItem("searchHistory", JSON.stringify(newHistory));
          return newHistory;
        });
      }));

    } catch (error) {
      console.error("Analysis error:", error);
      setError("Failed to fetch threat data");
      toast({
        title: t('error'),
        description: "Failed to fetch threat data",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const onPivot = (artifact: string) => {
    setQuery(artifact);
    // Use a timeout to allow state update before triggering search
    setTimeout(() => {
      const form = document.querySelector('form');
      if (form) form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }, 100);
  };

  const exportGlobalPDF = async () => {
    if (results.length === 0) return;
    setIsExportingPDF(true);
    toast({
      title: "Building Comprehensive Report",
      description: "Generating multi-page PDF evidence. Please do not switch tabs...",
    });

    try {
      const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const margin = 10;
      
      const addHeader = (title: string, subtitle: string) => {
        pdf.setFillColor(26, 26, 26);
        pdf.rect(0, 0, pdfWidth, 40, 'F');
        pdf.setTextColor(255, 255, 255);
        pdf.setFontSize(24);
        pdf.setFont("helvetica", "bold");
        pdf.text("ThreatSumm4ry", 14, 20);
        pdf.setFontSize(12);
        pdf.setFont("helvetica", "normal");
        pdf.text(title, 14, 30);
        if (subtitle) {
             pdf.text(subtitle, 14, 35);
        }
        pdf.text(new Date().toLocaleString(), pdfWidth - 14, 20, { align: "right" });
        pdf.setTextColor(0, 0, 0);
      };

      // PAGE 1: SCORING METHODOLOGY
      addHeader("HOW THREAT LEVEL IS SCORED", "Threat Level & Scoring Methodology");
      let y = 55;
      
      pdf.setFontSize(11);
      pdf.setFont("helvetica", "normal");
      const p1 = pdf.splitTextToSize(t('threatEngineExplanation'), pdfWidth - 28);
      pdf.text(p1, 14, y);
      y += p1.length * 5 + 5;

      pdf.setFontSize(12);
      pdf.setFont("helvetica", "bold");
      pdf.text(t('primaryVendorWeights'), 14, y);
      y += 8;

      pdf.setFontSize(10);
      pdf.setFont("helvetica", "bold");
      pdf.text("VirusTotal:", 14, y);
      pdf.setFont("helvetica", "normal");
      const vtDesc = pdf.splitTextToSize(t('vtWeightDesc'), pdfWidth - 45);
      pdf.text(vtDesc, 40, y);
      y += Math.max(1, vtDesc.length) * 5 + 3;

      pdf.setFontSize(10);
      pdf.setFont("helvetica", "bold");
      pdf.text("AbuseIPDB:", 14, y);
      pdf.setFont("helvetica", "normal");
      const abDesc = pdf.splitTextToSize(t('abuseIpdbWeightDesc'), pdfWidth - 45);
      pdf.text(abDesc, 40, y);
      y += Math.max(1, abDesc.length) * 5 + 8;

      pdf.setFontSize(12);
      pdf.setFont("helvetica", "bold");
      pdf.text(t('scoringThresholds'), 14, y);
      y += 8;

      const limits = [
         { label: "SAFE (0-30):", text: t('safeDesc') },
         { label: "SUSPICIOUS (31-70):", text: t('suspiciousDesc') },
         { label: "MALICIOUS (71-100):", text: t('maliciousDesc') }
      ];
      limits.forEach(l => {
         pdf.setFontSize(10);
         pdf.setFont("helvetica", "bold");
         pdf.text(l.label, 14, y);
         pdf.setFont("helvetica", "normal");
         const tDesc = pdf.splitTextToSize(l.text, pdfWidth - 65);
         pdf.text(tDesc, 55, y);
         y += Math.max(1, tDesc.length) * 5 + 3;
      });

      const originalTab = activeTab;

      // PAGE 2: OVERVIEW TAB CAPTURE
      if (results.length > 1) {
          setActiveTab("overview");
          await new Promise(r => setTimeout(r, 1000)); 
          
          const overviewTarget = document.getElementById(`pdf-export-overview`) as HTMLElement;
          if (overviewTarget) {
              pdf.addPage();
              const canvas = await html2canvas(overviewTarget, {
                scale: 2, useCORS: true, backgroundColor: "#121212", windowWidth: 1200
              });
              const imgData = canvas.toDataURL('image/png');
              
              const innerWidth = pdfWidth - (margin * 2);
              const imgProps = pdf.getImageProperties(imgData);
              const imgHeight = (imgProps.height * innerWidth) / imgProps.width;
              let imgYOffset = 0;

              while (imgYOffset < imgHeight) {
                const availableHeight = pdfHeight - 45 - margin;
                const drawY = 45 - imgYOffset;
                pdf.addImage(imgData, 'PNG', margin, drawY, innerWidth, imgHeight);
                addHeader("OVERVIEW PRINT EVIDENCE", "");
                
                imgYOffset += availableHeight;
                if (imgYOffset < imgHeight) {
                  pdf.addPage();
                }
              }
          }
      }

      // SUBSEQUENT PAGES: INDIVIDUAL TARGET REPORTS
      for (const res of results) {
          setActiveTab(res.query);
          await new Promise(r => setTimeout(r, 1200)); // allow charts to animate slightly
          
          let target = document.getElementById(`pdf-export-${res.query}`) as HTMLElement;
          if (target) {
              const actionsBar = target.querySelector('.flex-wrap.gap-2.animate-fade-in') as HTMLElement;
              if (actionsBar) actionsBar.style.display = 'none';

              const canvas = await html2canvas(target, {
                  scale: 2, useCORS: true, backgroundColor: "#121212", windowWidth: 1200
              });
              
              if (actionsBar) actionsBar.style.display = 'flex';

              const imgData = canvas.toDataURL('image/png');
              const innerWidth = pdfWidth - (margin * 2);
              const imgProps = pdf.getImageProperties(imgData);
              const imgHeight = (imgProps.height * innerWidth) / imgProps.width;
              let imgYOffset = 0;
              
              pdf.addPage();

              while (imgYOffset < imgHeight) {
                  const availableHeight = pdfHeight - 45 - margin;
                  const drawY = 45 - imgYOffset;
                  pdf.addImage(imgData, 'PNG', margin, drawY, innerWidth, imgHeight);
                  addHeader(`TARGET PRINT EVIDENCE: ${res.query}`, `Individual Analysis Report`);

                  imgYOffset += availableHeight;
                  if (imgYOffset < imgHeight) {
                      pdf.addPage();
                  }
              }
          }
      }

      setActiveTab(originalTab);
      pdf.save(`Comprehensive_Threat_Report_${Date.now()}.pdf`);
      
      toast({
        title: t('exportSuccess'),
        description: t('pdfDownloaded'),
      });

    } catch (err) {
       console.error("PDF generation failed:", err);
       toast({ title: t('error'), description: "Report generation failed.", variant: "destructive" });
    } finally {
       setIsExportingPDF(false);
    }
  };

  const handleReset = () => {
    setQuery("");
    setResults([]);
    setError(null);
  };

  const generateVendorUrls = (searchQuery: string) => {
    const detectType = () => {
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(searchQuery)) return "ip";
      if (/^[a-fA-F0-9]{32,64}$/.test(searchQuery)) return "hash";
      return "domain";
    };

    const type = detectType();
    const urls: string[] = [];

    if (type === "ip") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/ip-address/${searchQuery}`);
      urls.push(`AbuseIPDB: https://www.abuseipdb.com/check/${searchQuery}`);
      urls.push(`AlienVault OTX: https://otx.alienvault.com/indicator/ip/${searchQuery}`);
      urls.push(`Shodan: https://www.shodan.io/host/${searchQuery}`);
      urls.push(`Criminal IP: https://www.criminalip.io/asset/report/${searchQuery}`);
    } else if (type === "domain") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/domain/${searchQuery}`);
      urls.push(`AlienVault OTX: https://otx.alienvault.com/indicator/domain/${searchQuery}`);
      urls.push(`URLhaus: https://urlhaus.abuse.ch/browse.php?search=${searchQuery}`);
      urls.push(`PhishStats: https://phishstats.info/#/search?url=${searchQuery}`);
    } else if (type === "hash") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/file/${searchQuery}`);
      urls.push(`Hybrid Analysis: https://www.hybrid-analysis.com/search?query=${searchQuery}`);
      urls.push(`MalwareBazaar: https://bazaar.abuse.ch/browse.php?search=hash:${searchQuery}`);
      urls.push(`CIRCL: https://hashlookup.circl.lu/lookup/md5/${searchQuery}`);
    }

    return urls.join("\n\n");
  };

  const copyVendorLinks = (targetQuery: string) => {
    const links = generateVendorUrls(targetQuery);
    navigator.clipboard.writeText(links);
    toast({
      title: t('linksCopied'),
      description: `${links.split("\n\n").length} vendor links copied to clipboard`,
    });
  };

  const getVendorIcon = (name: string) => {
    switch (name) {
      case "VirusTotal": return <Shield className="h-5 w-5 text-primary" />;
      case "AbuseIPDB": return <AlertTriangle className="h-5 w-5 text-primary" />;
      case "AlienVault OTX": return <Eye className="h-5 w-5 text-primary" />;
      case "Shodan": return <Radar className="h-5 w-5 text-primary" />;
      case "URLhaus": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "MalwareBazaar": return <Bug className="h-5 w-5 text-primary" />;
      case "Google Safe Browsing": return <Shield className="h-5 w-5 text-primary" />;
      case "PhishTank": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "Pulsedive": return <Radar className="h-5 w-5 text-primary" />;
      case "Hybrid Analysis": return <Bug className="h-5 w-5 text-primary" />;
      case "CIRCL hashlookup": return <Database className="h-5 w-5 text-primary" />;
      case "Criminal IP": return <AlertTriangle className="h-5 w-5 text-primary" />;
      case "MetaDefender": return <Shield className="h-5 w-5 text-primary" />;
      case "PhishStats": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "Ransomware.live": return <Bug className="h-5 w-5 text-primary" />;
      case "WHOIS": return <FileSearch className="h-5 w-5 text-primary" />;
      case "IP Geolocation": return <Globe className="h-5 w-5 text-primary" />;
      default: return <Shield className="h-5 w-5 text-primary" />;
    }
  };

  const getVendorLink = (name: string) => {
    switch (name) {
      case "VirusTotal": return "https://virustotal.com";
      case "AbuseIPDB": return "https://abuseipdb.com";
      case "AlienVault OTX": return "https://otx.alienvault.com";
      case "Shodan": return "https://shodan.io";
      case "URLhaus": return "https://urlhaus.abuse.ch";
      case "MalwareBazaar": return "https://bazaar.abuse.ch";
      case "Google Safe Browsing": return "https://safebrowsing.google.com";
      case "PhishTank": return "https://phishtank.com";
      case "Pulsedive": return "https://pulsedive.com";
      case "Hybrid Analysis": return "https://hybrid-analysis.com";
      case "CIRCL hashlookup": return "https://hashlookup.circl.lu";
      case "Criminal IP": return "https://criminalip.io";
      case "MetaDefender": return "https://metadefender.opswat.com";
      case "PhishStats": return "https://phishstats.info";
      case "Ransomware.live": return "https://ransomware.live";
      case "WHOIS": return undefined;
      case "IP Geolocation": return undefined;
      default: return undefined;
    }
  };

  if (results.length === 0 && !isAnalyzing) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        {/* Top Navigation / Action Bar */}
        <div className="absolute top-4 right-4 md:top-6 md:right-8 flex items-center gap-3 animate-fade-in bg-background/80 backdrop-blur-md p-2 rounded-full border shadow-sm z-50">
          <Link to="/vendors">
            <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full hover:bg-muted font-medium" title="Vendor Directory">
              <BookOpen className="h-4 w-4" />
            </Button>
          </Link>
          <Link to="/dnsbl">
            <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full hover:bg-muted font-medium" title={t('dnsblCheck')}>
              <Shield className="h-4 w-4" />
            </Button>
          </Link>
          <div className="w-px h-4 bg-border mx-1" />
          <HistorySidebar
            history={history}
            onSelect={(q) => { setQuery(q); setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 100); }}
            onClear={() => { setHistory([]); localStorage.removeItem("searchHistory"); }}
          />
          <LanguageToggle />
          <ThemeToggle />
        </div>

        <div className="flex-1 flex flex-col items-center justify-center p-4">
          <div className="max-w-2xl w-full space-y-8 text-center">
            <div className="space-y-2 animate-fade-in">
              <h1 
                className="text-4xl md:text-6xl font-bold tracking-tight bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent cursor-pointer hover:opacity-80 transition-opacity"
                onClick={handleReset}
              >
                {t('appName')}
              </h1>
              <p className="text-xl text-muted-foreground">
                {t('dashboardTitle')}
              </p>
            </div>

            <div className="p-1 sm:p-2 animate-fade-in w-full">
              <SearchForm
                query={query}
                setQuery={setQuery}
                onSubmit={handleSearch}
                isLoading={isAnalyzing}
              />
            </div>

            <p className="text-sm text-muted-foreground animate-fade-in">
              Secure & Private Threat Analysis • API Keys Managed Locally
            </p>
          </div>
        </div>

        <Footer />
      </div >
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          {/* New Header Design */}
          <div className="flex flex-col gap-6 mb-8 animate-fade-in">
            {/* Top Unified Header */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h1 
                  className="text-3xl font-bold tracking-tight bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent cursor-pointer hover:opacity-80 transition-opacity"
                  onClick={handleReset}
                >
                  {t('appName')}
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  {selectedVendors.length} {t('vendorsEnabled')}
                </p>
              </div>

              {/* Centralized Navigation and Settings Actions */}
              <div className="flex items-center flex-wrap gap-2 bg-muted/30 p-1.5 rounded-full border shadow-sm">
                <Link to="/vendors">
                  <Button variant="ghost" size="sm" className="gap-2 h-8 rounded-full text-muted-foreground hover:text-foreground hover:bg-background">
                    <BookOpen className="h-4 w-4" />
                    <span className="hidden sm:inline">{t('vendors')}</span>
                  </Button>
                </Link>
                <Link to="/dnsbl">
                  <Button variant="ghost" size="sm" className="gap-2 h-8 rounded-full text-muted-foreground hover:text-foreground hover:bg-background">
                    <Shield className="h-4 w-4" />
                    <span className="hidden sm:inline">{t('dnsblCheck')}</span>
                  </Button>
                </Link>
                <div className="w-px h-4 bg-border mx-1" />
                {results.length > 0 && (
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="gap-2 h-8 rounded-full border-primary/20 hover:bg-primary/10"
                    onClick={exportGlobalPDF}
                    disabled={isExportingPDF}
                  >
                    <FileSearch className={`h-4 w-4 ${isExportingPDF ? "animate-pulse" : ""}`} />
                    <span className="hidden sm:inline">{isExportingPDF ? "Building Report..." : "Global PDF Report"}</span>
                  </Button>
                )}
                <div className="w-px h-4 bg-border mx-1" />
                <VendorFilter
                  selectedVendors={selectedVendors}
                  onVendorsChange={setSelectedVendors}
                />
                <HistorySidebar
                  history={history}
                  onSelect={(q) => { setQuery(q); setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 100); }}
                  onClear={() => { setHistory([]); localStorage.removeItem("searchHistory"); }}
                />
                <div className="w-px h-4 bg-border mx-1" />
                <LanguageToggle />
                <ThemeToggle />
              </div>
            </div>

            {/* In-page Re-search Bar */}
            <div className="flex flex-col bg-card p-4 rounded-xl border shadow-sm">
              <SearchForm
                query={query}
                setQuery={setQuery}
                onSubmit={handleSearch}
                isLoading={isAnalyzing}
                className="w-full"
              />
            </div>
          </div>

          {error && (
            <div className="bg-destructive/10 border border-destructive text-destructive px-4 py-3 rounded-lg animate-fade-in">
              <p>{t('error')}: {error}</p>
            </div>
          )}

          {results.length > 0 && (
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="w-full justify-start overflow-x-auto h-auto p-1 flex-wrap">
                <TabsTrigger value="overview" className="gap-2">
                  <LayoutGrid className="h-4 w-4" /> Overview
                </TabsTrigger>
                {results.map((result, idx) => (
                  <TabsTrigger key={idx} value={result.query} className="gap-2">
                    {result.threatLevel === "malicious" && <AlertTriangle className="h-3 w-3 text-destructive" />}
                    {result.query}
                  </TabsTrigger>
                ))}
              </TabsList>

              <TabsContent value="overview" className="mt-6 animate-fade-in">
                <div id="pdf-export-overview" className="space-y-6">
                  <MultiIpSummary
                    results={results}
                    onViewDetails={(q) => setActiveTab(q)}
                  />
                </div>
              </TabsContent>

              {results.map((data) => (
                <TabsContent key={data.query} value={data.query} className="mt-6 animate-fade-in">
                  <div id={`pdf-export-${data.query}`} className="space-y-6">
                    <QuickActions
                      data={data}
                    onRefresh={() => handleSearch()}
                    isLoading={isAnalyzing}
                    onCopyLinks={() => copyVendorLinks(data.query)}
                  />

                  <ThreatSummary
                    query={data.query}
                    overallScore={data.overallScore}
                    threatLevel={data.threatLevel}
                    totalVendors={data.totalVendors}
                    detections={data.detections}
                    vendorData={data.vendorData}
                  />

                  <ThreatCharts
                    vendorData={data.vendorData}
                    detections={data.detections}
                    totalVendors={data.totalVendors}
                  />

                  <div className="flex items-center justify-between mb-4 animate-fade-in">
                    <h2 className="text-2xl font-bold">{t('vendorResults')}</h2>
                    <ViewToggle view={view} onViewChange={setView} />
                  </div>

                  {view === "table" ? (
                    <VendorDataTable
                      vendorData={data.vendorData.filter(v => v.name !== "IP Geolocation")}
                      getVendorLink={getVendorLink}
                    />
                  ) : (
                    <div className="columns-1 md:columns-2 lg:columns-3 gap-4 space-y-4">
                      {data.vendorData
                        .filter(v => v.name !== "IP Geolocation")
                        .sort((a, b) => {
                          // Define vendor importance tiers
                          const tier1 = ["VirusTotal", "AbuseIPDB"];
                          const tier2 = ["Shodan", "AlienVault OTX", "Criminal IP"];
                          const tier3 = ["Pulsedive", "URLhaus", "PhishTank"];

                          const getTier = (name: string) => {
                            if (tier1.includes(name)) return 1;
                            if (tier2.includes(name)) return 2;
                            if (tier3.includes(name)) return 3;
                            return 4; // Others
                          };

                          const tierA = getTier(a.name);
                          const tierB = getTier(b.name);

                          // Sort by tier first, then alphabetically within tier
                          if (tierA !== tierB) return tierA - tierB;
                          return a.name.localeCompare(b.name);
                        })
                        .map((vendor) => (
                          <VendorCard
                            key={vendor.name}
                            title={vendor.name}
                            icon={getVendorIcon(vendor.name)}
                            externalLink={vendor.link}
                          >
                            <VendorContent vendor={vendor} onPivot={onPivot} />
                          </VendorCard>
                        ))}
                    </div>
                  )}
                  </div>
                </TabsContent>
              ))}
            </Tabs>
          )}

          {isAnalyzing && results.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 animate-fade-in">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mb-4"></div>
              <p className="text-lg text-muted-foreground">{t('analyzing')}</p>
            </div>
          )}

        </div>
      </div>
      <Footer />
    </div>
  );
};

export default Index;
