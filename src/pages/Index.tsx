import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getFieldCategory } from "@/components/VendorDataTable";
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
import autoTable from "jspdf-autotable";

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
      description: "Generating professional SOC intelligence report...",
    });

    try {
      const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const W = doc.internal.pageSize.getWidth();
      const H = doc.internal.pageSize.getHeight();
      const M = 14; // margin
      const reportDate = new Date().toLocaleString();
      const reportId = `TS-${Date.now().toString(36).toUpperCase()}`;

      // ── Color Palette ──
      const COLORS = {
        headerBg: [18, 18, 18] as [number, number, number],
        accent: [99, 102, 241] as [number, number, number],   // indigo
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
        for (let i = 1; i <= pageCount; i++) {
          doc.setPage(i);
          doc.setFillColor(...COLORS.headerBg);
          doc.rect(0, H - 10, W, 10, 'F');
          doc.setFontSize(7);
          doc.setTextColor(...COLORS.textSecondary);
          doc.text(`ThreatSumm4ry Intelligence Report`, M, H - 4);
          doc.text(`Page ${i} of ${pageCount}`, W - M, H - 4, { align: "right" });
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

      // Helper: extract a specific vendor's data field
      const getVendorField = (res: ThreatIntelligenceResult, vendorName: string, field: string): string => {
        const vendor = res.vendorData.find(v => v.name === vendorName);
        if (!vendor || vendor.error) return "N/A";
        const val = vendor.data[field];
        if (val === undefined || val === null) return "N/A";
        if (Array.isArray(val)) return val.join(", ");
        return String(val);
      };

      // Helper: extract hostname
      const getHostname = (res: ThreatIntelligenceResult): string => {
        const abuse = res.vendorData.find(v => v.name === "AbuseIPDB");
        if (abuse?.data?.["Domain"]) return String(abuse.data["Domain"]);
        const vt = res.vendorData.find(v => v.name === "VirusTotal");
        if (vt?.data?.["Hostnames"]) {
          const h = vt.data["Hostnames"];
          return Array.isArray(h) ? h[0] || "N/A" : String(h);
        }
        return "N/A";
      };

      // ═══════════════════════════════════════════════
      // PAGE 1: EXECUTIVE SUMMARY
      // ═══════════════════════════════════════════════
      drawPageHeader(`${results.length} IOC(s) Analisados`);
      let y = 42;

      // Summary stats bar
      const safeCount = results.filter(r => r.threatLevel === "safe").length;
      const suspCount = results.filter(r => r.threatLevel === "suspicious").length;
      const malCount = results.filter(r => r.threatLevel === "malicious").length;

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
        r.query || 'N/A',
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
        margin: { left: M, right: M },
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
        margin: { left: M, right: M },
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
        margin: { left: M, right: M },
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
        drawPageHeader(`IoC Analisado: ${res.query}`, `Target ${i + 1} of ${results.length}`);
        let y = 42;

        // ── IOC Identity Card (Gauge Style - Clean) ──
        const cardHeight = 45;
        const cardWidth = W - M * 2;

        // 1. Background & Soft Border
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(M, y, cardWidth, cardHeight, 4, 4, 'F');
        doc.setDrawColor(230, 235, 245);
        doc.setLineWidth(0.4);
        doc.roundedRect(M, y, cardWidth, cardHeight, 4, 4, 'S');

        // --- LEFT SIDE: IDENTITY ---
        doc.setFont("helvetica", "bold");
        doc.setFontSize(16);
        doc.setTextColor(30, 35, 50);
        doc.text(String(res.query || ''), M + 8, y + 12);

        // Status Pill with '!' Icon
        const statusColor = (getThreatColor(res.threatLevel) || [100, 100, 100]) as [number, number, number];
        const pillY = y + 15.5;
        doc.setFillColor(...statusColor);
        doc.roundedRect(M + 8, pillY, 42, 7, 3.5, 3.5, 'F');

        // White '!' Icon Circle
        doc.setFillColor(255, 255, 255);
        doc.circle(M + 11.5, pillY + 3.5, 2.2, 'F');
        doc.setFontSize(5.5);
        doc.setTextColor(...statusColor);
        doc.text("!", M + 11.2, pillY + 4.3);

        doc.setFontSize(7);
        doc.setTextColor(255, 255, 255);
        doc.text(String(res.threatLevel).toUpperCase(), M + 15, pillY + 4.8);

        // Detections Box (Stylized Blue)
        const detY = y + 29;
        doc.setFillColor(242, 248, 255);
        doc.roundedRect(M + 8, detY, 90, 10, 2, 2, 'F');

        // Simple Shield Icon Simulation
        doc.setDrawColor(70, 100, 150);
        doc.setLineWidth(0.5);
        doc.roundedRect(M + 12, detY + 3, 4.5, 4.5, 1, 1, 'S');

        doc.setFontSize(8.5);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(60, 80, 120);
        doc.text(`Total Detections: ${res.detections}/${res.totalVendors}`, M + 20, detY + 6.5);

        // --- RIGHT SIDE: SCORE & GAUGE ---
        const rightEdge = W - M - 12;
        const scoreVal = String(res.overallScore ?? 0);
        const mutedCol = (COLORS.muted || [150, 150, 150]) as [number, number, number];

        doc.setFontSize(7);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(110, 120, 140);
        doc.text("THREAT SCORE", rightEdge - 20, y + 10, { align: 'center' });

        doc.setFontSize(28);
        doc.setTextColor(...statusColor);
        doc.text(scoreVal, rightEdge - 11, y + 24, { align: 'right' });
        doc.setFontSize(10);
        doc.setTextColor(...mutedCol);
        doc.text("/100", rightEdge - 10, y + 24);

        // --- THE GAUGE ---
        const gX = rightEdge - 20;
        const gY = y + 42;
        const radius = 18;

        // 1. Background Arc (Semi-circle track)
        doc.setDrawColor(235, 240, 245);
        doc.setLineWidth(4);
        (doc as any).ellipse(gX, gY, radius, radius, 'S', 180, 0);

        // 2. Colored Progress Arc
        doc.setDrawColor(...statusColor);
        const scoreAngle = (Math.min(res.overallScore, 100) / 100) * 180;
        (doc as any).ellipse(gX, gY, radius, radius, 'S', 180, 180 - scoreAngle);

        // 3. The Needle
        const needleRad = (180 - scoreAngle) * (Math.PI / 180);
        const nx = gX + (radius - 3) * Math.cos(needleRad);
        const ny = gY - (radius - 3) * Math.sin(needleRad);

        doc.setDrawColor(...statusColor);
        doc.setLineWidth(1.8);
        doc.line(gX, gY, nx, ny);

        // Needle Base (The white circle with border)
        doc.setFillColor(255, 255, 255);
        doc.setDrawColor(...mutedCol);
        doc.setLineWidth(0.5);
        doc.circle(gX, gY, 2.8, 'FD');

        y += cardHeight + 10;

        // ── Geographic & Network Data Collection ──
        const networkData: string[][] = [];
        const addNetField = (label: string, value: any) => {
          const valStr = String(value || '');
          if (valStr && valStr !== "N/A" && valStr !== "Unknown" && valStr !== "0") {
            networkData.push([label, valStr]);
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
            margin: { left: M, right: M },
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
              grouped[cat].push(`${k}: ${val}`);
            });

            const details = CATEGORY_ORDER
              .filter(cat => grouped[cat]?.length > 0)
              .map(cat => `► ${cat.toUpperCase()}\n${grouped[cat].join("\n")}`)
              .join("\n\n");

            return [v.name, status, details || 'No notable findings', v.link || ''];
          });

        autoTable(doc, {
          startY: y,
          head: [['Vendor', 'Status', 'Intelligence Details', 'Link']],
          body: vendorRows,
          margin: { left: M, right: M },
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
              drawPageHeader(`IOC ANALYSIS: ${res.query} (cont.)`, `Target ${i + 1} of ${results.length}`);
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

            {/* Example IPs */}
            <div className="animate-fade-in space-y-2">
              <p className="text-xs font-medium text-muted-foreground/70 uppercase tracking-widest">Try these examples</p>
              <div className="flex flex-wrap justify-center gap-2">
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
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono font-medium border border-border/60 bg-muted/30 hover:bg-primary/10 hover:border-primary/40 text-muted-foreground hover:text-foreground transition-all cursor-pointer"
                  >
                    <span>{flag}</span>
                    <span>{ip}</span>
                  </button>
                ))}
              </div>
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
