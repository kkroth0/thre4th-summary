import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { getFieldCategory } from "@/components/VendorDataTable";
import { Shield, AlertTriangle, Bug, FileSearch, Globe, Link as LinkIcon, Radar, Database, Eye, Search, BookOpen, Layers, LayoutGrid, CheckCircle2, Mail, ArrowRight, Upload, Copy, Check, Clock, Download, FileJson, FileCode, ChevronDown, Bookmark } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { exportResultsJSON, exportResultsNDJSON, exportResultsSTIX } from "@/utils/threatExport";
import { defangList } from "@/utils/defang";
import { Badge } from "@/components/ui/badge";
import { ThreatSummary } from "@/components/ThreatSummary";
import { VendorCard } from "@/components/VendorCard";
import { VendorContent } from "@/components/VendorContent";
import { VendorFilter } from "@/components/VendorFilter";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";

import { ThreatCharts } from "@/components/ThreatCharts";
import { IocTimeline } from "@/components/IocTimeline";
import { QuickActions } from "@/components/QuickActions";
import { ViewToggle } from "@/components/ViewToggle";
import { ThreatCorrelationGraph } from "@/components/ThreatCorrelationGraph";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { MultiIpSummary } from "@/components/MultiIpSummary";
import { fetchThreatDataProgressive, saveScan } from "@/services/threatApi";
import { ScanHistory } from "@/components/ScanHistory";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
// jsPDF + autoTable are loaded lazily inside exportGlobalPDF (see below) so the
// ~400KB PDF toolchain is only fetched when a user actually exports a report.

const TypingTitle = ({ language }: { language: string }) => {
  const line1 = language === "pt" ? "Uma consulta." : "One query.";
  const line2Prefix = language === "pt" ? "Vinte e um " : "Twenty-one ";
  
  const words = language === "pt" 
    ? ["vereditos.", "insights.", "análises.", "resultados.", "relatórios."]
    : ["verdicts.", "insights.", "analyses.", "results.", "reports."];

  const [text1, setText1] = useState("");
  const [text2Prefix, setText2Prefix] = useState("");
  const [dynamicWord, setDynamicWord] = useState("");
  const [wordIndex, setWordIndex] = useState(0);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    // Reset everything on language change
    setText1("");
    setText2Prefix("");
    setDynamicWord("");
    setWordIndex(0);
    setIsDeleting(false);
  }, [language]);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    
    // Phase 1: Type line 1
    if (text1.length < line1.length) {
      timer = setTimeout(() => {
        setText1(line1.substring(0, text1.length + 1));
      }, 50); // Typing speed for line 1
      return () => clearTimeout(timer);
    }
    
    // Phase 2: Type line 2 prefix after line 1 is fully typed
    if (text2Prefix.length < line2Prefix.length) {
      timer = setTimeout(() => {
        setText2Prefix(line2Prefix.substring(0, text2Prefix.length + 1));
      }, 50); // Typing speed for line 2 prefix
      return () => clearTimeout(timer);
    }

    // Phase 3: Cycle words
    const currentFullWord = words[wordIndex];
    if (!isDeleting) {
      // Type character
      if (dynamicWord.length < currentFullWord.length) {
        timer = setTimeout(() => {
          setDynamicWord(currentFullWord.substring(0, dynamicWord.length + 1));
        }, 60); // Typing speed for dynamic words
      } else {
        // Fully typed, wait then start deleting
        timer = setTimeout(() => {
          setIsDeleting(true);
        }, 1500); // Hold time
      }
    } else {
      // Delete character
      if (dynamicWord.length > 0) {
        timer = setTimeout(() => {
          setDynamicWord(dynamicWord.substring(0, dynamicWord.length - 1));
        }, 40); // Deleting speed
      } else {
        // Fully deleted, move to next word
        setIsDeleting(false);
        setWordIndex((prev) => (prev + 1) % words.length);
      }
    }

    return () => clearTimeout(timer);
  }, [text1, text2Prefix, dynamicWord, isDeleting, wordIndex, language, line1, line2Prefix, words]);

  return (
    <>
      {text1}
      {text1 === line1 && <br />}
      {text2Prefix}
      {dynamicWord}
      <span className="animate-pulse inline-block w-[4px] h-[0.9em] bg-primary ml-1.5 translate-y-[2px]" />
    </>
  );
};

interface SearchFormProps {
  query: string;
  setQuery: (query: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  className?: string;
  selectedVendors: string[];
  onVendorsChange: (vendors: string[]) => void;
}

const SearchForm = ({
  query,
  setQuery,
  onSubmit,
  isLoading,
  className = "",
  selectedVendors,
  onVendorsChange,
}: SearchFormProps) => {
  const { t, language } = useLanguage();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const ipRegex = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const domainRegex = /\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
  const hashRegex = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
  const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;

  const getExtractedIocs = () => {
    if (!query) return [];
    const ips: string[] = query.match(ipRegex) ?? [];
    const domains: string[] = query.match(domainRegex) ?? [];
    const hashes: string[] = query.match(hashRegex) ?? [];
    const cves: string[] = query.match(cveRegex) ?? [];

    const cleanDomains = domains.filter(d => {
      const ext = d.split('.').pop()?.toLowerCase() || '';
      return !["exe", "dll", "sys", "zip", "rar", "tar", "gz", "png", "jpg", "jpeg", "gif", "css", "js", "html", "htm", "txt", "log", "json", "xml", "pdf", "doc", "docx", "xls", "xlsx"].includes(ext);
    });

    return Array.from(new Set([
      ...ips,
      ...cleanDomains,
      ...hashes,
      ...cves.map(c => c.toUpperCase())
    ]));
  };

  const extractedIocs = getExtractedIocs();
  const hasMultipleLines = query.includes("\n") || extractedIocs.length > 1;

  // Keep textarea height fixed
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "40px";
    }
  }, [query]);

  const handleLogFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          const text = event.target.result as string;

          const ips: string[] = text.match(ipRegex) ?? [];
          const domains: string[] = text.match(domainRegex) ?? [];
          const hashes: string[] = text.match(hashRegex) ?? [];
          const cves: string[] = text.match(cveRegex) ?? [];

          const cleanDomains = domains.filter(d => {
            const ext = d.split('.').pop()?.toLowerCase() || '';
            return !["exe", "dll", "sys", "zip", "rar", "tar", "gz", "png", "jpg", "jpeg", "gif", "css", "js", "html", "htm", "txt", "log", "json", "xml", "pdf", "doc", "docx", "xls", "xlsx"].includes(ext);
          });

          const allIocs = Array.from(new Set([
            ...ips,
            ...cleanDomains,
            ...hashes,
            ...cves.map(c => c.toUpperCase())
          ]));

          if (allIocs.length > 0) {
            setQuery(allIocs.join("\n"));
            toast({
              title: language === "pt" ? "IOCs Extraídos" : "IOCs Extracted",
              description: language === "pt"
                ? `Extraídos ${allIocs.length} alvos únicos de ameaça do arquivo ${file.name}.`
                : `Extracted ${allIocs.length} unique threat targets from ${file.name}.`,
            });
          } else {
            toast({
              title: language === "pt" ? "Nenhum IOC Encontrado" : "No IOCs Found",
              description: language === "pt"
                ? "Não foi possível encontrar IPs, domínios, hashes ou CVEs válidos no arquivo."
                : "Could not find any valid IPs, domains, hashes, or CVEs in the file.",
              variant: "destructive"
            });
          }
        }
      };
      reader.readAsText(file);
      e.target.value = "";
    }
  };

  return (
    <div className={`w-full ${className}`}>
      <form onSubmit={onSubmit} className="w-full">
        <div className="space-y-3">
          {/* Search bar */}
          <div className="relative flex items-center bg-[#0B0E1C]/90  border border-white/[0.06] hover:border-border/50 focus-within:border-border/50 transition-all duration-500 shadow-[0_8px_40px_-12px_rgba(0,0,0,0.6)] focus-within:shadow-[0_8px_50px_-8px_rgba(30,96,255,0.15)] max-w-2xl mx-auto w-full rounded-full p-1.5 pl-5 flex-row items-center gap-2">

            {/* Search icon */}
            <div className="flex items-center shrink-0">
              <Search className="h-4 w-4 text-slate-500" />
            </div>

            {/* Unified textarea input */}
            <textarea
              ref={textareaRef}
              placeholder={language === "pt"
                ? "IP, domínio, hash, CVE — cole um ou vários..."
                : "IP, domain, hash, CVE — paste one or many..."
              }
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              rows={1}
              className="bg-transparent border-0 focus:outline-none focus-visible:ring-0 text-[13px] text-slate-200 placeholder:text-slate-500/70 flex-1 min-w-0 resize-none [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden leading-relaxed h-10 py-2.5 pl-2.5"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  onSubmit(e as any);
                }
              }}
            />

            {/* Actions row */}
            <div className="flex items-center gap-1.5 shrink-0 pr-0.5">
              {/* IOC count badge */}
              {extractedIocs.length > 1 && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-primary/10 border border-border/50 text-[10px] font-bold text-primary font-mono tracking-wide">
                  <div className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                  {extractedIocs.length} IOCs
                </div>
              )}

              {/* File upload */}
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleLogFileUpload}
                accept=".txt,.log,.csv,.json"
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="h-9 w-9 rounded-full flex items-center justify-center shrink-0 text-slate-500 hover:text-slate-300 hover:bg-white/[0.04] transition-all duration-200"
                title={language === "pt" ? "Enviar arquivo de log" : "Upload log file"}
              >
                <Upload className="h-4 w-4" />
              </button>

              {/* Submit */}
              <Button
                type="submit"
                disabled={isLoading || !query.trim()}
                size="icon"
                className="h-9 w-9 rounded-full bg-primary hover:bg-blue-600 transition-all duration-200 flex items-center justify-center shrink-0 border-0  shadow-primary/20 hover:shadow-blue-600/30 disabled:opacity-30 disabled:shadow-none"
                title={language === "pt" ? "Analisar" : "Analyze"}
              >
                {isLoading ? (
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                ) : (
                  <ArrowRight className="h-4 w-4 text-white" />
                )}
              </Button>
            </div>
          </div>

          {/* Parsed IOCs preview — only when many targets */}
          {extractedIocs.length > 1 && (
            <div className="flex flex-wrap items-center justify-center gap-1.5 max-w-2xl mx-auto animate-fade-in">
              {extractedIocs.slice(0, 6).map(ioc => (
                <span key={ioc} className="inline-flex items-center px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-[10px] font-mono text-slate-400 tracking-wide">
                  {ioc}
                </span>
              ))}
              {extractedIocs.length > 6 && (
                <span className="text-[10px] text-slate-500 font-medium">
                  +{extractedIocs.length - 6} more
                </span>
              )}
            </div>
          )}
        </div>
      </form>
    </div>
  );
};

const ALL_VENDORS = [
  "IP Geolocation", "WHOIS", "VirusTotal", "AbuseIPDB", "AlienVault OTX",
  "Shodan", "URLhaus", "MalwareBazaar", "ThreatFox", "Google Safe Browsing",
  "PhishTank", "Pulsedive",
  "Hybrid Analysis", "CIRCL hashlookup",
  "Criminal IP", "MetaDefender", "PhishStats", "Ransomware.live",
  "OpenPhish", "Team Cymru", "Censys"
];

const Index = () => {
  const { isCollapsed } = useSidebar();
  const { auth } = useAuth();
  const [savingScans, setSavingScans] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedVendors, setSelectedVendors] = useState<string[]>(ALL_VENDORS);

  // Changed data to results array to support multi-IP
  const [results, setResults] = useState<ThreatIntelligenceResult[]>([]);
  const [activeTab, setActiveTab] = useState<string>("overview");

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isExportingPDF, setIsExportingPDF] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"graph" | "cards">("graph");
  const [searchHistory, setSearchHistory] = useState<string[]>([]);
  const [copiedIocs, setCopiedIocs] = useState(false);
  const { toast } = useToast();
  const { t, language } = useLanguage();


  // Load saved preferences
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
  }, []);

  // Load recent search history
  useEffect(() => {
    const saved = localStorage.getItem("searchHistory");
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) setSearchHistory(parsed.filter((s) => typeof s === "string").slice(0, 8));
      } catch (e) {
        console.error("Failed to parse search history", e);
      }
    }
  }, []);

  // Persist a query to the recent-search list (most-recent first, de-duped, capped at 8).
  const pushSearchHistory = (raw: string) => {
    const entry = raw.trim();
    if (!entry) return;
    setSearchHistory((prev) => {
      const next = [entry, ...prev.filter((q) => q !== entry)].slice(0, 8);
      localStorage.setItem("searchHistory", JSON.stringify(next));
      return next;
    });
  };

  const clearSearchHistory = () => {
    setSearchHistory([]);
    localStorage.removeItem("searchHistory");
  };

  // Defang + copy every scanned IOC to the clipboard for safe pasting into
  // tickets, SIEM queries or firewall rules.
  const copyAllIocs = async () => {
    const text = defangList(results.map((r) => r.query));
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIocs(true);
      setTimeout(() => setCopiedIocs(false), 1500);
      toast({
        title: language === "pt" ? "IOCs copiados" : "IOCs copied",
        description: language === "pt"
          ? `${results.length} indicador(es) copiado(s) (defanged).`
          : `${results.length} indicator(s) copied (defanged).`,
      });
    } catch {
      toast({
        title: language === "pt" ? "Falha ao copiar" : "Copy failed",
        variant: "destructive",
      });
    }
  };

  // Handle pivot search from CVE dashboard
  useEffect(() => {
    const pivotQuery = localStorage.getItem("pivotSearchQuery");
    if (pivotQuery) {
      setQuery(pivotQuery);
      localStorage.removeItem("pivotSearchQuery");
      setTimeout(() => {
        const submitButton = document.querySelector('button[type="submit"]') as HTMLButtonElement;
        if (submitButton) {
          submitButton.click();
        }
      }, 300);
    }
  }, []);

  // Salva os resultados atuais (com veredito) no histórico da conta.
  const saveCurrentScans = async () => {
    const done = results.filter((r) => r.threatLevel && r.threatLevel !== "unknown");
    if (!done.length) return;
    setSavingScans(true);
    try {
      for (const r of done) {
        await saveScan({
          query: r.query,
          threatLevel: r.threatLevel,
          score: r.overallScore,
          detections: r.detections,
          totalVendors: r.totalVendors,
        });
      }
      toast({
        title: language === "pt" ? "Scan salvo" : "Scan saved",
        description: language === "pt" ? `${done.length} scan(s) no seu histórico.` : `${done.length} scan(s) in your history.`,
      });
    } catch (err) {
      toast({ title: t('error'), description: err instanceof Error ? err.message : "", variant: "destructive" });
    } finally {
      setSavingScans(false);
    }
  };

  const handleSearch = async (e?: React.FormEvent, override?: string) => {
    if (e) e.preventDefault();

    const rawQuery = (typeof override === "string" ? override : query).trim();

    if (!rawQuery) {
      toast({
        title: t('error'),
        description: t('inputRequired'),
        variant: "destructive",
      });
      return;
    }

    // Extract all potential tokens by splitting on whitespace, quotes, commas, brackets, etc.
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const hashPattern = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    const urlPattern = /^(http|https):\/\/[^ "]+$/;
    const cvePattern = /^CVE-\d{4}-\d{4,7}$/i;

    const tokens = rawQuery.split(/[\s,"'()\[\]{}|<>]+/).map(t => t.trim()).filter(t => t.length > 0);
    const uniqueTokens = Array.from(new Set(tokens));

    // Filter to only valid IOCs
    let queries = uniqueTokens.filter(q =>
      ipPattern.test(q) || domainPattern.test(q) || hashPattern.test(q) || urlPattern.test(q) || cvePattern.test(q)
    );

    // If no valid structured IOCs were found, fall back to the raw split tokens (to trigger type validation warnings properly)
    if (queries.length === 0) {
      queries = uniqueTokens;
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
    const cveRegex = /^CVE-\d{4}-\d{4,7}$/i;

    const invalidQueries = queries.filter(q =>
      !ipRegex.test(q) && !domainRegex.test(q) && !hashRegex.test(q) && !urlRegex.test(q) && !cveRegex.test(q)
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
    pushSearchHistory(rawQuery);

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

      // Process queries in batches to avoid overwhelming the backend
      const BATCH_SIZE = 3;
      for (let i = 0; i < queries.length; i += BATCH_SIZE) {
        const batch = queries.slice(i, i + BATCH_SIZE);
        await Promise.all(batch.map(async (q) => {
          try {
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
          } catch (err) {
            console.error(`Failed to fetch data for ${q}:`, err);
            // Mark this query as failed but don't stop other queries
            setResults(prev => prev.map(r => r.query === q ? {
              ...r,
              threatLevel: "unknown" as const,
              vendorData: r.vendorData.map(v => ({ ...v, isLoading: false, error: v.isLoading ? "Request failed" : v.error }))
            } : r));
          }
        }));
      }

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
      description: "Generating professional SOC intelligence report...",
    });

    try {
      const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
        import("jspdf"),
        import("jspdf-autotable"),
      ]);
      const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const W = doc.internal.pageSize.getWidth();
      const H = doc.internal.pageSize.getHeight();
      const M = 14; // margin
      const reportDate = new Date().toLocaleString();
      const reportId = `TS-${Date.now().toString(36).toUpperCase()}`;

      // ── Text sanitizer for jsPDF standard fonts (WinAnsi/Latin-1) ──
      // Vendor/scraped data sometimes arrives with HTML entities (&#8217;, &nbsp;)
      // or Unicode typography that the built-in font can't render, producing
      // garbage. Decode entities and normalize to Latin-1-safe characters so the
      // content stays legible.
      const decodeHtmlEntities = (s: string): string => s
        .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
        .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(parseInt(n, 10)))
        .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&(?:apos|#39);/gi, "'")
        .replace(/&hellip;/gi, '...').replace(/&mdash;/gi, '-').replace(/&ndash;/gi, '-');
      const S = (v: unknown): string => {
        let s = decodeHtmlEntities(String(v ?? ''));
        s = s
          .replace(/[‘’‚‛]/g, "'")
          .replace(/[“”„‟]/g, '"')
          .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g, '-')
          .replace(/…/g, '...')
          .replace(/[•·]/g, '-')
          .replace(/\u00a0/g, ' ')
          .replace(/[\u200b-\u200d\ufeff]/g, '');
        // Keep printable ASCII + Latin-1 (accented PT/EU letters), drop the rest
        return s.replace(/[^\t\n\r\x20-\x7E¡-ÿ]/g, '');
      };

      // Color palette
      const COLORS = {
        headerBg: [18, 18, 18] as [number, number, number],
        accent: [30, 96, 255] as [number, number, number],   // cyber blue
        safe: [34, 197, 94] as [number, number, number],
        suspicious: [245, 158, 11] as [number, number, number],
        malicious: [239, 68, 68] as [number, number, number],
        muted: [100, 116, 139] as [number, number, number],
        tableBg: [30, 30, 30] as [number, number, number],
        tableAlt: [38, 38, 38] as [number, number, number],
        white: [255, 255, 255] as [number, number, number],
        black: [0, 0, 0] as [number, number, number],
        textPrimary: [226, 232, 240] as [number, number, number],
        textSecondary: [148, 163, 184] as [number, number, number],
      };

      const getThreatColor = (level: string): [number, number, number] => {
        if (level === "malicious") return COLORS.malicious;
        if (level === "suspicious") return COLORS.suspicious;
        if (level === "safe") return COLORS.safe;
        return COLORS.muted;
      };

      // ── Reusable Drawing Utilities ──
      const drawPageHeader = (title: string, subtitle?: string) => {
        doc.setFillColor(...COLORS.headerBg);
        doc.rect(0, 0, W, 32, 'F');
        // Accent stripe
        doc.setFillColor(...COLORS.accent);
        doc.rect(0, 32, W, 1.5, 'F');
        // Logo text
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(18);
        doc.setFont("helvetica", "bold");
        doc.text("THREATSUMM4RY", M, 14);
        // Subtitle
        doc.setFontSize(9);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(...COLORS.textSecondary);
        doc.text(title, M, 22);
        if (subtitle) doc.text(subtitle, M, 27);
        // Right-aligned metadata
        doc.setFontSize(8);
        doc.text(reportDate, W - M, 14, { align: "right" });
        doc.text(`Report ID: ${reportId}`, W - M, 20, { align: "right" });
        doc.setTextColor(...COLORS.black);
      };

      const drawPageFooter = () => {
        const pageCount = (doc as any).internal.getNumberOfPages();
        // Skip the cover (page 1); number content pages from 1.
        for (let i = 2; i <= pageCount; i++) {
          doc.setPage(i);
          doc.setFillColor(...COLORS.headerBg);
          doc.rect(0, H - 10, W, 10, 'F');
          doc.setFontSize(7);
          doc.setTextColor(...COLORS.textSecondary);
          doc.text(`ThreatSumm4ry Intelligence Report · ${reportId}`, M, H - 4);
          doc.text(`Page ${i - 1} of ${pageCount - 1}`, W - M, H - 4, { align: "right" });
        }
      };

      const drawThreatPill = (x: number, y: number, level: string) => {
        const color = getThreatColor(level);
        const label = level.toUpperCase();
        const pillW = doc.getTextWidth(label) + 8;
        doc.setFillColor(...color);
        doc.roundedRect(x, y - 4, pillW, 6, 2, 2, 'F');
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(7);
        doc.setFont("helvetica", "bold");
        doc.text(label, x + 4, y);
        doc.setTextColor(...COLORS.black);
        return pillW;
      };

      const drawSectionTitle = (y: number, title: string): number => {
        doc.setFillColor(...COLORS.accent);
        doc.rect(M, y, 3, 7, 'F');
        doc.setFontSize(12);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(40, 40, 40);
        doc.text(title, M + 6, y + 5.5);
        doc.setTextColor(...COLORS.black);
        return y + 12;
      };

      // ── Professional cover page ──
      const drawCoverPage = (malCount: number, suspCount: number, safeCount: number, topScore: number) => {
        // Full dark background
        doc.setFillColor(...COLORS.headerBg);
        doc.rect(0, 0, W, H, 'F');
        // Brand
        doc.setTextColor(...COLORS.white);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(13);
        doc.text("THREATSUMM4RY", M, 28);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(9);
        doc.setTextColor(...COLORS.textSecondary);
        doc.text("Advanced Threat Intelligence Platform", M, 34.5);
        // Title
        doc.setTextColor(...COLORS.white);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(32);
        doc.text("Threat Intelligence", M, 62);
        doc.text("Report", M, 76);
        // Accent rule
        doc.setFillColor(...COLORS.accent);
        doc.rect(M, 84, 52, 2, 'F');
        // Metadata
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10.5);
        doc.setTextColor(...COLORS.textPrimary);
        const metaY = 100;
        doc.text(`Generated:`, M, metaY);
        doc.text(`Report ID:`, M, metaY + 8);
        doc.text(`Indicators analyzed:`, M, metaY + 16);
        doc.text(`Classification:`, M, metaY + 24);
        doc.setTextColor(...COLORS.white);
        doc.setFont("helvetica", "bold");
        doc.text(reportDate, M + 48, metaY);
        doc.text(reportId, M + 48, metaY + 8);
        doc.text(String(results.length), M + 48, metaY + 16);
        doc.text("TLP:AMBER — Internal Use Only", M + 48, metaY + 24);
        // KPI cards
        const cardY = 150;
        const gap = 5;
        const cardW = (W - M * 2 - gap * 3) / 4;
        const cardH = 30;
        const cards: { label: string; value: number; color: [number, number, number] }[] = [
          { label: "TOTAL IOCs", value: results.length, color: COLORS.accent },
          { label: "MALICIOUS", value: malCount, color: COLORS.malicious },
          { label: "SUSPICIOUS", value: suspCount, color: COLORS.suspicious },
          { label: "SAFE", value: safeCount, color: COLORS.safe },
        ];
        cards.forEach((c, idx) => {
          const x = M + idx * (cardW + gap);
          doc.setFillColor(28, 28, 30);
          doc.roundedRect(x, cardY, cardW, cardH, 2.5, 2.5, 'F');
          doc.setFillColor(...c.color);
          doc.rect(x, cardY, cardW, 1.5, 'F');
          doc.setTextColor(...c.color);
          doc.setFont("helvetica", "bold");
          doc.setFontSize(22);
          doc.text(String(c.value), x + cardW / 2, cardY + 17, { align: "center" });
          doc.setTextColor(...COLORS.textSecondary);
          doc.setFont("helvetica", "bold");
          doc.setFontSize(7);
          doc.text(c.label, x + cardW / 2, cardY + 24, { align: "center" });
        });
        // Highest score line
        doc.setTextColor(...COLORS.textSecondary);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(9);
        doc.text(`Highest threat score observed: ${topScore}/100`, M, cardY + cardH + 12);
        // Footer note
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.muted);
        doc.text("Automatically generated by ThreatSumm4ry — aggregated multi-vendor threat intelligence.", M, H - 16);
        doc.text(reportDate, W - M, H - 16, { align: "right" });
      };

      // Helper: extract a specific vendor's data field
      const getVendorField = (res: ThreatIntelligenceResult, vendorName: string, field: string): string => {
        const vendor = res.vendorData.find(v => v.name === vendorName);
        if (!vendor || vendor.error) return "N/A";
        const val = vendor.data[field];
        if (val === undefined || val === null) return "N/A";
        if (Array.isArray(val)) return S(val.join(", "));
        return S(val);
      };

      // Helper: extract hostname
      const getHostname = (res: ThreatIntelligenceResult): string => {
        const abuse = res.vendorData.find(v => v.name === "AbuseIPDB");
        if (abuse?.data?.["Domain"]) return S(abuse.data["Domain"]);
        const vt = res.vendorData.find(v => v.name === "VirusTotal");
        if (vt?.data?.["Hostnames"]) {
          const h = vt.data["Hostnames"];
          return S(Array.isArray(h) ? h[0] || "N/A" : String(h));
        }
        return "N/A";
      };

      // ── Posture counts ──
      const safeCount = results.filter(r => r.threatLevel === "safe").length;
      const suspCount = results.filter(r => r.threatLevel === "suspicious").length;
      const malCount = results.filter(r => r.threatLevel === "malicious").length;
      const topScore = Math.max(0, ...results.map(r => r.overallScore ?? 0));

      // ═══════════════════════════════════════════════
      // COVER PAGE
      // ═══════════════════════════════════════════════
      drawCoverPage(malCount, suspCount, safeCount, topScore);

      // ═══════════════════════════════════════════════
      // PAGE 2: EXECUTIVE SUMMARY
      // ═══════════════════════════════════════════════
      doc.addPage();
      drawPageHeader("Executive Summary", `${results.length} indicator(s) analyzed`);
      let y = 42;

      // Background Container
      doc.setFillColor(245, 245, 245);
      doc.roundedRect(M, y, W - M * 2, 18, 3, 3, 'F');

      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(60, 60, 60);
      const statsY = y + 11;
      doc.text(`Total IOCs: ${results.length}`, M + 6, statsY);
      // --- DYNAMIC PILLS (RIGHT-ALIGNED) ---
      const pillPadding = 6;
      const pillGap = 4;
      const pillHeight = 7;  // Slightly shorter for a cleaner look
      const pillTopY = statsY - 4.8;

      doc.setFontSize(7);

      const pillData = [
        { label: `MALICIOUS: ${malCount}`, color: COLORS.malicious },
        { label: `SUSPICIOUS: ${suspCount}`, color: COLORS.suspicious },
        { label: `SAFE: ${safeCount}`, color: COLORS.safe }
      ];

      // 1. Calculate total width of all pills to right-align them
      const totalPillsWidth = pillData.reduce((acc, pill) => {
        return acc + doc.getTextWidth(pill.label) + pillPadding + pillGap;
      }, 0) - pillGap; // Subtract last gap

      // 2. Set starting X to be near the right edge of the grey box
      // (W - M) is the right edge of the container, - 6 for internal padding
      let px = (W - M) - totalPillsWidth - 6;

      pillData.forEach(pill => {
        const textWidth = doc.getTextWidth(pill.label);
        const pillWidth = textWidth + pillPadding;

        // Draw Pill
        doc.setFillColor(...pill.color);
        doc.roundedRect(px, pillTopY, pillWidth, pillHeight, 2, 2, 'F');

        // Draw Text
        doc.setTextColor(255, 255, 255);
        doc.text(pill.label, px + (pillPadding / 2), statsY);

        px += pillWidth + pillGap;
      });

      doc.setTextColor(...COLORS.black);
      y += 24;

      // ── Executive narrative ──
      y = drawSectionTitle(y, "Risk Posture");
      const malicious = results.filter(r => r.threatLevel === "malicious").map(r => S(r.query));
      const narrative =
        `This report consolidates multi-vendor threat intelligence for ${results.length} indicator(s). ` +
        `${malCount} were classified as MALICIOUS, ${suspCount} as SUSPICIOUS and ${safeCount} as SAFE, ` +
        `with a peak threat score of ${topScore}/100. ` +
        (malCount > 0
          ? `Immediate triage is recommended for the malicious indicator(s): ${malicious.slice(0, 8).join(", ")}${malicious.length > 8 ? ", …" : ""}.`
          : `No malicious indicators were identified in this batch; routine monitoring is advised.`);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9.5);
      doc.setTextColor(70, 70, 70);
      const narrativeLines = doc.splitTextToSize(narrative, W - M * 2);
      doc.text(narrativeLines, M, y);
      y += narrativeLines.length * 4.8 + 8;

      // Executive Overview Table
      y = drawSectionTitle(y, "IOC Overview");

      // Sort priority map
      const threatPriority = { "malicious": 1, "suspicious": 2, "safe": 3 };

      // Sort a copy of the results to avoid side-effects
      const sortedResults = [...results].sort((a, b) => {
        const pA = threatPriority[a.threatLevel.toLowerCase()] || 99;
        const pB = threatPriority[b.threatLevel.toLowerCase()] || 99;
        return pA - pB;
      });

      const overviewRows = sortedResults.map(r => [
        S(r.query) || 'N/A',
        getHostname(r) || 'N/A',
        (r.threatLevel || 'UNKNOWN').toUpperCase(),
        `${r.overallScore ?? 0}/100`,
        `${r.detections ?? 0}/${r.totalVendors ?? 0}`,
        getVendorField(r, "VirusTotal", "Detection Rate") || '0/0',
        getVendorField(r, "AbuseIPDB", "Abuse Confidence Score") || '0',
      ]);

      autoTable(doc, {
        startY: y,
        head: [['IOC Target', 'Hostname', 'Threat Level', 'Score', 'Detections', 'VT Rate', 'AbuseIPDB']],
        body: overviewRows,
        margin: { top: 36, bottom: 16, left: M, right: M },
        styles: {
          fontSize: 8,
          cellPadding: 3,
          textColor: [40, 40, 40],
          lineColor: [220, 220, 220],
          lineWidth: 0.2,
        },
        headStyles: {
          fillColor: COLORS.headerBg,
          textColor: COLORS.white,
          fontStyle: 'bold',
          fontSize: 7,
        },
        alternateRowStyles: {
          fillColor: [248, 248, 248],
        },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 32 },
          2: { cellWidth: 22, halign: 'center' },
          3: { cellWidth: 16, halign: 'center' },
          4: { cellWidth: 20, halign: 'center' },
        },
        didDrawCell: (data) => {
          // Draw Threat Level pills in column 2 (index 2)
          if (data.section === 'body' && data.column.index === 2) {
            // Safety check for cell text
            const cellText = String(data.cell.raw || '');
            const { x: cellX, y: cellY, width: cellW, height: cellH } = data.cell;

            // 1. Wipe the existing text drawn by autoTable
            const bgColor = data.row.index % 2 === 0 ? [255, 255, 255] : [248, 248, 248];
            doc.setFillColor(...(bgColor as [number, number, number]));
            doc.rect(cellX + 0.1, cellY + 0.1, cellW - 0.2, cellH - 0.2, 'F');

            // 2. Draw the pill
            const level = cellText.toLowerCase();
            const color = getThreatColor(level);
            const pillW = Math.min(cellW - 4, 20);
            const pillX = cellX + (cellW - pillW) / 2;
            const pillY = cellY + (cellH / 2) - 2.5;

            doc.setFillColor(...color);
            doc.roundedRect(pillX, pillY, pillW, 5, 1.5, 1.5, 'F');

            // 3. Draw the text on top
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(6);
            doc.setFont("helvetica", "bold");
            // Use align: 'center' to ensure it stays inside the pill
            doc.text(cellText, cellX + cellW / 2, cellY + (cellH / 2) + 1, { align: 'center' });

            // Reset state for next cells
            doc.setTextColor(40, 40, 40);
          }
        },
      });

      // ═══════════════════════════════════════════════
      // PAGE 2: SCORING METHODOLOGY
      // ═══════════════════════════════════════════════
      doc.addPage();
      drawPageHeader(t('threatLevelScoringMethodology'));
      y = 42;

      y = drawSectionTitle(y, t('threatLevelScoringMethodology'));

      doc.setFontSize(9);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(60, 60, 60);
      const introText = doc.splitTextToSize(t('threatEngineExplanation'), W - M * 2);
      doc.text(introText, M, y);
      y += introText.length * 4.5 + 6;

      // Vendor weights table
      y = drawSectionTitle(y, t('primaryVendorWeights'));

      autoTable(doc, {
        startY: y,
        head: [['Vendor', 'Weight Rule']],
        body: [
          ['VirusTotal', t('vtWeightDesc')],
          ['AbuseIPDB', t('abuseIpdbWeightDesc')],
        ],
        margin: { top: 36, bottom: 16, left: M, right: M },
        styles: { fontSize: 8, cellPadding: 4, textColor: [40, 40, 40], lineColor: [220, 220, 220], lineWidth: 0.2 },
        headStyles: { fillColor: COLORS.headerBg, textColor: COLORS.white, fontStyle: 'bold', fontSize: 8 },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 35 } },
      });

      y = (doc as any).lastAutoTable.finalY + 10;

      // Scoring thresholds table
      y = drawSectionTitle(y, t('scoringThresholds'));

      autoTable(doc, {
        startY: y,
        head: [['Classification', 'Score Range', 'Description']],
        body: [
          ['SAFE', '0 – 30', t('safeDesc')],
          ['SUSPICIOUS', '31 – 70', t('suspiciousDesc')],
          ['MALICIOUS', '71 – 100', t('maliciousDesc')],
        ],
        margin: { top: 36, bottom: 16, left: M, right: M },
        styles: { fontSize: 8, cellPadding: 4, textColor: [40, 40, 40], lineColor: [220, 220, 220], lineWidth: 0.2 },
        headStyles: { fillColor: COLORS.headerBg, textColor: COLORS.white, fontStyle: 'bold', fontSize: 8 },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 30 },
          1: { cellWidth: 22, halign: 'center' },
        },
        didDrawCell: (data: any) => {
          if (data.section === 'body' && data.column.index === 0) {
            const cellText = data.cell.raw as string;
            const cellX = data.cell.x;
            const cellY = data.cell.y;
            const cellW = data.cell.width;
            const cellH = data.cell.height;

            doc.setFillColor(255, 255, 255);
            doc.rect(cellX + 0.2, cellY + 0.2, cellW - 0.4, cellH - 0.4, 'F');

            const color = getThreatColor(cellText.toLowerCase());
            const pillW = Math.min(cellW - 4, 26);
            const pillX = cellX + (cellW - pillW) / 2;
            const pillY = cellY + (cellH / 2) - 2.5;
            doc.setFillColor(...color);
            doc.roundedRect(pillX, pillY, pillW, 5.5, 1.5, 1.5, 'F');
            doc.setTextColor(...COLORS.white);
            doc.setFontSize(7);
            doc.setFont("helvetica", "bold");
            doc.text(cellText, cellX + cellW / 2, cellY + cellH / 2 + 1, { align: 'center' });
            doc.setTextColor(...COLORS.black);
          }
        },
      });

      // ═══════════════════════════════════════════════
      // PAGES 3+: INDIVIDUAL IOC DETAILED ANALYSIS
      // ═══════════════════════════════════════════════
      for (let i = 0; i < results.length; i++) {
        const res = results[i];
        doc.addPage();
        drawPageHeader(`IOC Analysis: ${S(res.query)}`, `Target ${i + 1} of ${results.length}`);
        let y = 42;

        // ── IOC Identity Card ──
        const cardHeight = 40;
        const cardWidth = W - M * 2;
        const statusColor = (getThreatColor(res.threatLevel) || [100, 100, 100]) as [number, number, number];
        const score = Math.max(0, Math.min(res.overallScore ?? 0, 100));

        // Card background + soft border
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(M, y, cardWidth, cardHeight, 4, 4, 'F');
        doc.setDrawColor(228, 233, 242);
        doc.setLineWidth(0.4);
        doc.roundedRect(M, y, cardWidth, cardHeight, 4, 4, 'S');
        // Left severity accent stripe
        doc.setFillColor(...statusColor);
        doc.roundedRect(M, y, 2.5, cardHeight, 4, 4, 'F');
        doc.rect(M + 1.5, y, 1, cardHeight, 'F');

        // --- LEFT: identity ---
        const leftX = M + 9;
        const rightPanelX = M + cardWidth * 0.62;
        const leftMaxW = rightPanelX - leftX - 6;
        const fitText = (text: string, maxW: number): string => {
          if (doc.getTextWidth(text) <= maxW) return text;
          let tt = text;
          while (tt.length > 4 && doc.getTextWidth(tt + '...') > maxW) tt = tt.slice(0, -1);
          return tt + '...';
        };
        const q = S(res.query);
        let qSize = 15;
        if (q.length > 46) qSize = 9; else if (q.length > 30) qSize = 11; else if (q.length > 20) qSize = 13;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(qSize);
        doc.setTextColor(28, 33, 48);
        doc.text(fitText(q, leftMaxW), leftX, y + 12);

        // Threat-level pill
        const lvl = String(res.threatLevel || 'unknown').toUpperCase();
        doc.setFontSize(7.5);
        const pillW = doc.getTextWidth(lvl) + 8;
        doc.setFillColor(...statusColor);
        doc.roundedRect(leftX, y + 16.5, pillW, 6, 3, 3, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFont("helvetica", "bold");
        doc.text(lvl, leftX + 4, y + 20.6);

        // Detections line
        doc.setFont("helvetica", "normal");
        doc.setFontSize(9);
        doc.setTextColor(90, 100, 120);
        doc.text(`Detections: ${res.detections}/${res.totalVendors} vendors flagged`, leftX, y + 32);

        // --- RIGHT: score panel ---
        doc.setDrawColor(224, 229, 238);
        doc.setLineWidth(0.3);
        doc.line(rightPanelX, y + 6, rightPanelX, y + cardHeight - 6);

        const sx = rightPanelX + 8;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(7);
        doc.setTextColor(120, 130, 148);
        doc.text("THREAT SCORE", sx, y + 11);

        // Big score + /100 (left-aligned, measured to avoid overlap)
        doc.setFontSize(30);
        doc.setTextColor(...statusColor);
        const scoreStr = String(score);
        doc.text(scoreStr, sx, y + 27);
        const sw = doc.getTextWidth(scoreStr);
        doc.setFontSize(11);
        doc.setTextColor(150, 158, 172);
        doc.text("/100", sx + sw + 2, y + 27);

        // Horizontal score bar
        const barX = sx;
        const barW = (W - M - 8) - barX;
        const barY = y + 31;
        doc.setFillColor(234, 237, 242);
        doc.roundedRect(barX, barY, barW, 3.5, 1.75, 1.75, 'F');
        const fillW = Math.max(2, (score / 100) * barW);
        doc.setFillColor(...statusColor);
        doc.roundedRect(barX, barY, fillW, 3.5, 1.75, 1.75, 'F')

        y += cardHeight + 10;

        // ── Geographic & Network Data Collection ──
        const networkData: string[][] = [];
        const addNetField = (label: string, value: any) => {
          const valStr = String(value || '');
          if (valStr && valStr !== "N/A" && valStr !== "Unknown" && valStr !== "0") {
            networkData.push([label, S(valStr)]);
          }
        };

        // 1. ISP (Prefer Geolocation, fallback to AbuseIPDB)
        const isp = getVendorField(res, "IP Geolocation", "ISP") !== "N/A"
          ? getVendorField(res, "IP Geolocation", "ISP")
          : getVendorField(res, "AbuseIPDB", "ISP");
        addNetField("ISP", isp);

        // 2. Organization
        addNetField("Organization", getVendorField(res, "IP Geolocation", "Organization"));

        // 3. Country (Prefer Geolocation, fallback to AbuseIPDB)
        const country = getVendorField(res, "IP Geolocation", "Country") !== "N/A"
          ? getVendorField(res, "IP Geolocation", "Country")
          : getVendorField(res, "AbuseIPDB", "Country");
        addNetField("Country", country);

        // 4. ASN (New field added)
        addNetField("ASN", getVendorField(res, "AbuseIPDB", "ASN"));

        // 5. Network / CIDR (New field added)
        addNetField("Network (CIDR)", getVendorField(res, "AbuseIPDB", "CIDR/Network"));

        // 6. City (New field added)
        addNetField("City", getVendorField(res, "IP Geolocation", "City"));

        // 7. Hostname
        addNetField("Hostname", getHostname(res));

        // ── Render Table ──
        if (networkData.length > 0) {
          y = drawSectionTitle(y, "Geographic & Network Data");

          const half = Math.ceil(networkData.length / 2);
          const bodyRows: string[][] = [];
          for (let r = 0; r < half; r++) {
            bodyRows.push([
              networkData[r]?.[0] || '', networkData[r]?.[1] || '',
              networkData[r + half]?.[0] || '', networkData[r + half]?.[1] || '',
            ]);
          }

          autoTable(doc, {
            startY: y,
            head: [['Property', 'Value', 'Property', 'Value']],
            body: bodyRows,
            margin: { top: 36, bottom: 16, left: M, right: M },
            styles: {
              fontSize: 8,
              cellPadding: 3,
              textColor: [40, 40, 40],
              lineColor: [220, 220, 220],
              lineWidth: 0.1
            },
            headStyles: {
              fillColor: [55, 65, 81],
              textColor: [255, 255, 255],
              fontStyle: 'bold'
            },
            columnStyles: {
              0: { fontStyle: 'bold', cellWidth: 32, fillColor: [249, 250, 251] },
              2: { fontStyle: 'bold', cellWidth: 32, fillColor: [249, 250, 251] },
            },
          });
          y = (doc as any).lastAutoTable.finalY + 10;
        }

        // ── Vendor Intelligence Breakdown ──
        y = drawSectionTitle(y, "Vendor Intelligence Breakdown");
        const CATEGORY_ORDER = ["Threat / Heuristics", "Network / IT", "Geo / Location", "Network Providers", "Reputation / Intel"];

        const vendorRows = res.vendorData
          .filter(v => v.name !== "IP Geolocation")
          .map(v => {
            const status = v.data["Status"] || 'Clean';
            const grouped: Record<string, string[]> = {};
            Object.entries(v.data).forEach(([k, val]) => {
              if (["Status", "All Vendors", "Hostnames"].includes(k)) return;
              const cat = getFieldCategory(k);
              if (!grouped[cat]) grouped[cat] = [];
              grouped[cat].push(S(`${k}: ${val}`));
            });

            const details = CATEGORY_ORDER
              .filter(cat => grouped[cat]?.length > 0)
              .map(cat => `► ${cat.toUpperCase()}\n${grouped[cat].join("\n")}`)
              .join("\n\n");

            return [S(v.name), S(status), S(details) || 'No notable findings', v.link || ''];
          });

        autoTable(doc, {
          startY: y,
          head: [['Vendor', 'Status', 'Intelligence Details', 'Link']],
          body: vendorRows,
          margin: { top: 36, bottom: 16, left: M, right: M },
          styles: { fontSize: 7, cellPadding: 4, textColor: [40, 40, 40], overflow: 'linebreak' },
          headStyles: { fillColor: [20, 20, 20], textColor: [255, 255, 255] },
          columnStyles: {
            0: { fontStyle: 'bold', cellWidth: 28 },
            1: { cellWidth: 22, halign: 'center' },
            3: { cellWidth: 30, fontSize: 6, textColor: (COLORS.accent as [number, number, number]) }
          },
          didDrawCell: (data) => {
            if (data.section === 'body' && data.column.index === 1) {
              const text = String(data.cell.raw || '');
              const { x, y: cy, width: cw, height: ch } = data.cell;

              // Clear background with tuple safety for TS
              const rowBg = (data.row.index % 2 === 0 ? [255, 255, 255] : [248, 248, 248]) as [number, number, number];
              doc.setFillColor(...rowBg);
              doc.rect(x + 0.1, cy + 0.1, cw - 0.2, ch - 0.2, 'F');

              const color = getThreatColor(text.toLowerCase().replace('clean', 'safe'));
              doc.setFillColor(...(color as [number, number, number]));
              doc.roundedRect(x + (cw - 18) / 2, cy + (ch / 2) - 2.5, 18, 5, 1.5, 1.5, 'F');

              doc.setTextColor(255, 255, 255);
              doc.setFontSize(6);
              doc.text(text.toUpperCase(), x + cw / 2, cy + (ch / 2) + 1, { align: 'center' });
            }
          },
          didDrawPage: (data) => {
            // CRITICAL: Only draw "cont." if the table actually overflowed onto a NEW page
            // @ts-ignore
            if (data.pageNumber > data.settings.startYPage) {
              drawPageHeader(`IOC ANALYSIS: ${S(res.query)} (cont.)`, `Target ${i + 1} of ${results.length}`);
            }
          }
        });
      }

      // ── Final: Apply footers to all pages ──
      drawPageFooter();

      doc.save(`ThreatSumm4ry_Report_${reportId}.pdf`);

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

  const VendorFavicon = ({ name, fallbackIcon }: { name: string; fallbackIcon: React.ReactNode }) => {
    const [error, setError] = useState(false);

    if (error) return <>{fallbackIcon}</>;

    const domainMap: Record<string, string> = {
      "VirusTotal": "virustotal.com",
      "AbuseIPDB": "abuseipdb.com",
      "AlienVault OTX": "alienvault.com",
      "Shodan": "shodan.io",
      "URLhaus": "abuse.ch",
      "MalwareBazaar": "abuse.ch",
      "Google Safe Browsing": "google.com",
      "PhishTank": "phishtank.com",
      "Pulsedive": "pulsedive.com",
      "Hybrid Analysis": "hybrid-analysis.com",
      "CIRCL hashlookup": "circl.lu",
      "Criminal IP": "criminalip.io",
      "MetaDefender": "opswat.com",
      "PhishStats": "phishstats.info",
      "Ransomware.live": "ransomware.live",
      "WHOIS": "who.is",
      "IP Geolocation": "ip-api.com",
      "Censys": "censys.io",
      "OpenPhish": "openphish.com",
      "Team Cymru": "team-cymru.com"
    };

    const domain = domainMap[name] || "google.com";

    return (
      <img
        src={`https://www.google.com/s2/favicons?sz=32&domain=${domain}`}
        alt=""
        className="w-5 h-5 rounded-sm object-contain shrink-0"
        onError={() => setError(true)}
      />
    );
  };

  const getVendorIcon = (name: string) => {
    let fallback = <Shield className="h-5 w-5 text-primary" />;
    switch (name) {
      case "VirusTotal": fallback = <Shield className="h-5 w-5 text-primary" />; break;
      case "AbuseIPDB": fallback = <AlertTriangle className="h-5 w-5 text-primary" />; break;
      case "AlienVault OTX": fallback = <Eye className="h-5 w-5 text-primary" />; break;
      case "Shodan": fallback = <Radar className="h-5 w-5 text-primary" />; break;
      case "URLhaus": fallback = <LinkIcon className="h-5 w-5 text-primary" />; break;
      case "MalwareBazaar": fallback = <Bug className="h-5 w-5 text-primary" />; break;
      case "Google Safe Browsing": fallback = <Shield className="h-5 w-5 text-primary" />; break;
      case "PhishTank": fallback = <LinkIcon className="h-5 w-5 text-primary" />; break;
      case "Pulsedive": fallback = <Radar className="h-5 w-5 text-primary" />; break;
      case "Hybrid Analysis": fallback = <Bug className="h-5 w-5 text-primary" />; break;
      case "CIRCL hashlookup": fallback = <Database className="h-5 w-5 text-primary" />; break;
      case "Criminal IP": fallback = <AlertTriangle className="h-5 w-5 text-primary" />; break;
      case "MetaDefender": fallback = <Shield className="h-5 w-5 text-primary" />; break;
      case "PhishStats": fallback = <LinkIcon className="h-5 w-5 text-primary" />; break;
      case "Ransomware.live": fallback = <Bug className="h-5 w-5 text-primary" />; break;
      case "WHOIS": fallback = <FileSearch className="h-5 w-5 text-primary" />; break;
      case "IP Geolocation": fallback = <Globe className="h-5 w-5 text-primary" />; break;
      default: fallback = <Shield className="h-5 w-5 text-primary" />; break;
    }
    return <VendorFavicon name={name} fallbackIcon={fallback} />;
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
      <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 relative overflow-hidden ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
        {/* Glowing background gradient mesh */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-950/15 via-background to-background pointer-events-none z-0" />

        <Header onLogoClick={handleReset} />

        {/* Top inline navbar inside the content area (Desktop only) */}
        <div className="relative z-10 flex justify-between items-center w-full max-w-7xl mx-auto py-6 px-4 md:px-8 border-b border-border/50 hidden md:flex">
          {/* Brand/Logo */}
          <div className="flex items-center gap-2.5">
            <div className="h-7 w-7 rounded bg-primary flex items-center justify-center font-black text-primary-foreground text-[11px] shadow-md shadow-primary/30 select-none">
              T
            </div>
            <span className="font-extrabold tracking-tight text-base text-slate-100 font-sans">
              {t('appName')}
            </span>
          </div>

          {/* Center Links */}
          <div className="flex items-center gap-5 flex-wrap justify-center">
            <Link
              to="/features"
              className="text-xs font-semibold text-muted-foreground hover:text-foreground hover:underline underline-offset-4 transition-all duration-200"
            >
              {t('features') || 'Features'}
            </Link>
            <Link
              to="/vendors"
              className="text-xs font-semibold text-muted-foreground hover:text-foreground hover:underline underline-offset-4 transition-all duration-200"
            >
              {t('vendors') || 'Vendors'}
            </Link>
            <Link
              to="/dnsbl"
              className="text-xs font-semibold text-muted-foreground hover:text-foreground hover:underline underline-offset-4 transition-all duration-200"
            >
              {t('dnsblCheck') || 'DNSBL Check'}
            </Link>
            <Link
              to="/phishing-analyzer"
              className="text-xs font-semibold text-muted-foreground hover:text-foreground hover:underline underline-offset-4 transition-all duration-200"
            >
              {language === "pt" ? "Análise de Phishing" : "Phishing Analyzer"}
            </Link>
            <Link
              to="/newsletter"
              className="text-xs font-semibold text-muted-foreground hover:text-foreground hover:underline underline-offset-4 transition-all duration-200"
            >
              {language === "pt" ? "Coletor de Intel" : "Intel Collector"}
            </Link>
            <Link
              to="/cves"
              className="text-xs font-semibold text-muted-foreground hover:text-foreground hover:underline underline-offset-4 transition-all duration-200"
            >
              {language === "pt" ? "Painel de CVEs" : "CVE Dashboard"}
            </Link>
          </div>
        </div>

        <div className="relative z-10 flex-1 flex flex-col items-center justify-center p-4 min-h-[50vh]">
          <div className="max-w-2xl w-full space-y-8 text-center">
            <div className="flex flex-col items-center">
              {/* Hero Title & Description */}
              <div className="space-y-4">
                <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-foreground/50 bg-clip-text text-transparent leading-[1.1] md:leading-[1.1]">
                  <TypingTitle language={language} />
                </h1>
                <p className="text-sm md:text-base text-muted-foreground/80 max-w-xl mx-auto leading-relaxed">
                  {t('heroDescription') || 'Paste an IP, domain, or hash. ThreatSumm4ry aggregates intelligence from 21 vendors and returns a unified verdict in under two seconds.'}
                </p>
              </div>
            </div>

            {/* Main Capsule Search Bar */}
            <div className="p-1 sm:p-2 animate-fade-in w-full">
              <SearchForm
                query={query}
                setQuery={setQuery}
                onSubmit={handleSearch}
                isLoading={isAnalyzing}
                selectedVendors={selectedVendors}
                onVendorsChange={setSelectedVendors}
              />
            </div>

            {/* Try these Examples */}
            <div id="examples" className="animate-fade-in space-y-3 scroll-mt-6">
              <p className="text-[10px] font-bold text-muted-foreground/50 uppercase tracking-widest">
                {language === "pt" ? "Experimente estes exemplos" : "Try these examples"}
              </p>
              <div className="flex flex-wrap justify-center gap-2.5">
                {[
                  { ip: "14.103.115.208", flag: "🇨🇳" },
                  { ip: "51.210.208.8", flag: "🇫🇷" },
                  { ip: "103.65.237.234", flag: "🇮🇩" },
                  { ip: "1.1.1.1", flag: "☁️" },
                  { ip: "8.8.8.8", flag: "🔒" },
                ].map(({ ip, flag }) => (
                  <button
                    key={ip}
                    onClick={() => setQuery(prev => prev ? `${prev}\n${ip}` : ip)}
                    className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold border border-border/50 bg-muted/20 hover:bg-primary/5 hover:border-border/50 text-muted-foreground hover:text-foreground hover:scale-[1.03] active:scale-[0.97] transition-all cursor-pointer shadow-sm"
                  >
                    <span>{flag}</span>
                    <span>{ip}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Recent searches */}
            {searchHistory.length > 0 && (
              <div className="animate-fade-in space-y-3">
                <div className="flex items-center justify-center gap-2">
                  <p className="text-[10px] font-bold text-muted-foreground/50 uppercase tracking-widest">
                    {language === "pt" ? "Buscas recentes" : "Recent searches"}
                  </p>
                  <button
                    onClick={clearSearchHistory}
                    className="text-[10px] font-semibold text-muted-foreground/40 hover:text-destructive transition-colors"
                    title={language === "pt" ? "Limpar histórico" : "Clear history"}
                  >
                    {language === "pt" ? "limpar" : "clear"}
                  </button>
                </div>
                <div className="flex flex-wrap justify-center gap-2.5">
                  {searchHistory.map((entry) => {
                    const label = entry.replace(/\s+/g, " ").trim();
                    const short = label.length > 32 ? `${label.slice(0, 32)}…` : label;
                    return (
                      <button
                        key={entry}
                        onClick={() => setQuery(entry)}
                        title={label}
                        className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold border border-border/50 bg-muted/20 hover:bg-primary/5 hover:border-border/50 text-muted-foreground hover:text-foreground hover:scale-[1.03] active:scale-[0.97] transition-all cursor-pointer shadow-sm"
                      >
                        <Clock className="h-3 w-3 opacity-60" />
                        <span className="font-mono">{short}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Capabilities */}
            <div id="features" className="pt-10 border-t border-white/[0.04] mt-10 max-w-3xl mx-auto scroll-mt-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                {[
                  {
                    icon: Shield,
                    title: language === "pt" ? "21 Fontes" : "21 Sources",
                    desc: language === "pt" ? "Veredito unificado" : "Unified verdict"
                  },
                  {
                    icon: Radar,
                    title: language === "pt" ? "Correlação" : "Correlation",
                    desc: language === "pt" ? "Grafo interativo" : "Interactive graph"
                  },
                  {
                    icon: Database,
                    title: language === "pt" ? "Multi-formato" : "Multi-format",
                    desc: language === "pt" ? "IP, hash, CVE" : "IP, hash, CVE"
                  },
                  {
                    icon: FileSearch,
                    title: language === "pt" ? "PDF / SOC" : "PDF / SOC",
                    desc: language === "pt" ? "Relatórios prontos" : "Export ready"
                  }
                ].map((feat, index) => {
                  const Icon = feat.icon;
                  return (
                    <div key={index} className="flex flex-col items-center gap-2 p-4 rounded-xl border border-white/[0.04] bg-white/[0.015] hover:bg-white/[0.03] hover:border-border/50 transition-all duration-300">
                      <div className="h-8 w-8 rounded-lg bg-primary/8 border border-border/50 flex items-center justify-center text-primary">
                        <Icon className="h-4 w-4" />
                      </div>
                      <div>
                        <h3 className="font-bold text-[11px] text-foreground">{feat.title}</h3>
                        <p className="text-[10px] text-muted-foreground/50 mt-0.5">{feat.desc}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <Footer />
      </div>
    );
  }

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header onLogoClick={handleReset} />
      {/* Sticky Top Search Bar */}
      <div className="sticky top-16 lg:top-0 z-20 w-full border-b border-border/50 bg-background/55  px-4 md:px-8 py-3.5 animate-fade-in">
        <div className="max-w-7xl mx-auto">
          <SearchForm
            query={query}
            setQuery={setQuery}
            onSubmit={handleSearch}
            isLoading={isAnalyzing}
            className="w-full"
            selectedVendors={selectedVendors}
            onVendorsChange={setSelectedVendors}
          />
        </div>
      </div>

      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">

          {error && (
            <div className="bg-destructive/10 border border-destructive text-destructive px-4 py-3 rounded-lg animate-fade-in">
              <p>{t('error')}: {error}</p>
            </div>
          )}

          {results.length > 0 && (
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                <TabsList className="w-full sm:w-auto justify-start overflow-x-auto h-auto p-1 flex-wrap">
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

                <div className="flex items-center gap-2 self-start sm:self-auto">
                  {auth.authenticated && (
                    <>
                      <ScanHistory onPick={(q) => { setQuery(q); handleSearch(undefined, q); }} />
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-9 px-4 rounded-full border-border/50 hover:bg-primary/10 shadow-sm flex items-center gap-2"
                        onClick={saveCurrentScans}
                        disabled={savingScans}
                        title={language === "pt" ? "Salvar scan no histórico" : "Save scan to history"}
                      >
                        <Bookmark className="h-4 w-4" />
                        <span>{language === "pt" ? "Salvar" : "Save"}</span>
                      </Button>
                    </>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 px-4 rounded-full border-border/50 hover:bg-primary/10 shadow-sm flex items-center gap-2"
                    onClick={copyAllIocs}
                    title={language === "pt" ? "Copiar todos os IOCs (defanged)" : "Copy all IOCs (defanged)"}
                  >
                    {copiedIocs ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                    <span>{language === "pt" ? "Copiar IOCs" : "Copy IOCs"}</span>
                  </Button>

                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-9 px-4 rounded-full border-border/50 hover:bg-primary/10 shadow-sm flex items-center gap-2"
                        disabled={isExportingPDF}
                        title={isExportingPDF ? "Building Report..." : (language === "pt" ? "Exportar" : "Export")}
                      >
                        <Download className={`h-4 w-4 ${isExportingPDF ? "animate-pulse" : ""}`} />
                        <span>{isExportingPDF ? (language === "pt" ? "Gerando..." : "Building...") : (language === "pt" ? "Exportar" : "Export")}</span>
                        <ChevronDown className="h-3.5 w-3.5 opacity-60" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      <DropdownMenuItem onClick={exportGlobalPDF} className="gap-2 cursor-pointer">
                        <FileSearch className="h-4 w-4" /> {language === "pt" ? "Relatório PDF" : "PDF Report"}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => exportResultsJSON(results)} className="gap-2 cursor-pointer">
                        <FileJson className="h-4 w-4" /> JSON
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => exportResultsNDJSON(results)} className="gap-2 cursor-pointer">
                        <FileCode className="h-4 w-4" /> NDJSON (SIEM)
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => exportResultsSTIX(results)} className="gap-2 cursor-pointer">
                        <Shield className="h-4 w-4" /> STIX 2.1
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>

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
                      confidence={data.confidence}
                      disagreement={data.disagreement}
                      reportingVendors={data.reportingVendors}
                    />

                    <ThreatCharts
                      vendorData={data.vendorData}
                      detections={data.detections}
                      totalVendors={data.totalVendors}
                    />

                    <IocTimeline vendorData={data.vendorData} />

                    <div className="flex items-center justify-between mb-4 animate-fade-in">
                      <h2 className="text-2xl font-bold">{t('vendorResults')}</h2>
                      <ViewToggle view={view} onViewChange={setView} />
                    </div>

                    {view === "graph" ? (
                      <ThreatCorrelationGraph
                        query={data.query}
                        overallScore={data.overallScore}
                        threatLevel={data.threatLevel}
                        totalVendors={data.totalVendors}
                        detections={data.detections}
                        vendorData={data.vendorData}
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
