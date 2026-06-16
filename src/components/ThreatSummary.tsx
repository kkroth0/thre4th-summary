
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ThreatBadge } from "./ThreatBadge";
import { Copy, Download, Info } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { VendorData } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface ThreatSummaryProps {
  query: string;
  overallScore: number;
  threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
  totalVendors: number;
  detections: number;
  vendorData?: VendorData[];
  confidence?: number;
  disagreement?: boolean;
  reportingVendors?: number;
}

export const ThreatSummary = ({ query, overallScore, threatLevel, totalVendors, detections, vendorData = [], confidence, disagreement, reportingVendors }: ThreatSummaryProps) => {
  const { toast } = useToast();
  const { t, language } = useLanguage();

  const formatVendorData = (vendor: VendorData): string => {
    let text = `\n${vendor.name}\n${'='.repeat(vendor.name.length)}\n`;
    Object.entries(vendor.data).forEach(([key, value]) => {
      if (typeof value === 'object' && !Array.isArray(value)) {
        text += `${key}:\n`;
        Object.entries(value).forEach(([subKey, subValue]) => {
          text += `  ${subKey}: ${subValue}\n`;
        });
      } else if (Array.isArray(value)) {
        text += `${key}: ${value.join(', ')}\n`;
      } else {
        text += `${key}: ${value}\n`;
      }
    });
    return text;
  };

  const handleCopy = () => {
    let fullReport = `THREAT INTELLIGENCE REPORT\n${'='.repeat(50)}\n\n`;
    fullReport += `Query: ${query}\n`;
    fullReport += `Overall Score: ${overallScore}/100\n`;
    fullReport += `Threat Level: ${threatLevel.toUpperCase()}\n`;
    fullReport += `Detections: ${detections}/${totalVendors} vendors\n`;
    fullReport += `Generated: ${new Date().toISOString()}\n`;
    fullReport += `\n${'='.repeat(50)}\n`;
    fullReport += `VENDOR DETAILS\n${'='.repeat(50)}`;

    vendorData.forEach(vendor => {
      fullReport += formatVendorData(vendor);
    });

    navigator.clipboard.writeText(fullReport);
    toast({
      title: t('copiedToClipboard'),
      description: t('reportCopied'),
    });
  };

  const handleExport = () => {
    toast({
      title: t('exportInitiated'),
      description: t('exportDesc'),
    });
  };

  return (
    <Card className="border border-primary/15 bg-card/45 backdrop-blur-md shadow-md shadow-primary/5">
      <CardHeader className="py-2.5 px-5 border-b border-primary/5">
        <CardTitle className="flex items-center justify-between text-xs font-bold tracking-wider uppercase text-muted-foreground/80">
          <span>{t('threatSummary')}</span>
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-3 text-xs gap-1.5 rounded-full border-primary/15 hover:bg-primary/5 transition-all duration-300"
              onClick={handleCopy}
            >
              <Copy className="h-3 w-3" />
              <span>{t('copySummary')}</span>
            </Button>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="py-3 px-5">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
          {/* Target Query Block */}
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">{t('query')}</p>
            <div className="flex items-center gap-2 group">
              <span className="font-mono font-semibold text-base bg-muted/40 px-2.5 py-1 rounded-lg border border-border/60 select-all truncate max-w-[200px]" title={query}>
                {query}
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-muted-foreground hover:text-foreground hover:bg-muted/80 rounded-full"
                onClick={() => {
                  navigator.clipboard.writeText(query);
                  toast({ description: t('copiedToClipboard') });
                }}
                title={t('copy')}
              >
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
            {(() => {
              const geoData = vendorData.find(v => v.name === "IP Geolocation")?.data;
              const reverseHostname = geoData?.["Reverse Hostname"];
              const abuseData = vendorData.find(v => v.name === "AbuseIPDB")?.data;
              const abuseHostnames = abuseData?.["Hostnames"];
              const shodanData = vendorData.find(v => v.name === "Shodan")?.data;
              const shodanHostnames = shodanData?.["Hostnames"];

              let hostname = null;
              if (reverseHostname && reverseHostname !== "Unknown" && reverseHostname !== "None") {
                hostname = reverseHostname;
              } else if (abuseHostnames && abuseHostnames !== "None" && abuseHostnames !== "Unknown") {
                hostname = abuseHostnames.split(",")[0].trim();
              } else if (shodanHostnames && shodanHostnames !== "None" && shodanHostnames !== "Unknown") {
                hostname = shodanHostnames.split(",")[0].trim();
              }

              if (hostname) {
                return (
                  <p className="text-xs text-muted-foreground break-all pl-2 border-l-2 border-primary/30 mt-1" title={hostname}>
                    {hostname}
                  </p>
                );
              }
              return null;
            })()}
          </div>

          {/* SVG Circular Risk Gauge Block */}
          <div className="flex items-center gap-3">
            <div className="relative h-16 w-16 flex items-center justify-center shrink-0">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                {/* Background Ring */}
                <circle
                  cx="50"
                  cy="50"
                  r="40"
                  className="stroke-muted/40"
                  strokeWidth="8"
                  fill="transparent"
                />
                {/* Foreground Ring with Glow */}
                <circle
                  cx="50"
                  cy="50"
                  r="40"
                  stroke={`url(#threatGradient-${threatLevel})`}
                  strokeWidth="8"
                  fill="transparent"
                  strokeDasharray="251.2"
                  strokeDashoffset={251.2 - (251.2 * Math.min(overallScore, 100)) / 100}
                  strokeLinecap="round"
                  className="transition-all duration-1000 ease-out"
                  filter="url(#glow-filter)"
                />
                
                {/* Definitions for Gradients and Glow Filters */}
                <defs>
                  <filter id="glow-filter" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                  <linearGradient id="threatGradient-safe" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#10b981" />
                    <stop offset="100%" stopColor="#059669" />
                  </linearGradient>
                  <linearGradient id="threatGradient-suspicious" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#f59e0b" />
                    <stop offset="100%" stopColor="#d97706" />
                  </linearGradient>
                  <linearGradient id="threatGradient-malicious" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#ef4444" />
                    <stop offset="100%" stopColor="#b91c1c" />
                  </linearGradient>
                  <linearGradient id="threatGradient-unknown" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#6b7280" />
                    <stop offset="100%" stopColor="#4b5563" />
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute flex flex-col items-center justify-center">
                <span className="text-xl font-extrabold tracking-tight">{overallScore}</span>
                <span className="text-[8px] text-muted-foreground uppercase font-semibold">Score</span>
              </div>
            </div>
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">{t('overallScore')}</p>
              <p className="text-xs font-mono font-medium mt-0.5 text-muted-foreground">{overallScore}/100 max</p>
            </div>
          </div>

          {/* Threat Level Badge Block */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">{t('threatLevel')}</span>
              <Dialog>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-4 w-4 rounded-full text-muted-foreground hover:text-foreground">
                    <Info className="h-3.5 w-3.5" />
                    <span className="sr-only">How Scoring Works</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-md">
                  <DialogHeader>
                    <DialogTitle>{t('threatLevelScoringMethodology')}</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4 text-sm mt-4">
                    <p>{t('threatEngineExplanation')}</p>
                    
                    <div className="space-y-2">
                      <h4 className="font-semibold border-b pb-1">{t('primaryVendorWeights')}</h4>
                      <ul className="space-y-1.5 list-disc pl-4 text-xs text-muted-foreground">
                        <li><strong className="text-foreground">VirusTotal:</strong> {t('vtWeightDesc')}</li>
                        <li><strong className="text-foreground">AbuseIPDB:</strong> {t('abuseIpdbWeightDesc')}</li>
                      </ul>
                    </div>

                    <div className="space-y-2">
                      <h4 className="font-semibold border-b pb-1">{t('scoringThresholds')}</h4>
                      <ul className="space-y-1.5 list-disc pl-4 text-xs text-muted-foreground">
                        <li><strong className="text-green-500">SAFE (0-30):</strong> {t('safeDesc')}</li>
                        <li><strong className="text-orange-500">SUSPICIOUS (31-70):</strong> {t('suspiciousDesc')}</li>
                        <li><strong className="text-red-500">MALICIOUS (71-100):</strong> {t('maliciousDesc')}</li>
                      </ul>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
            <ThreatBadge level={threatLevel} className="text-xs px-3 py-1 font-bold rounded-full w-fit shadow-sm" />
            {typeof confidence === "number" && (reportingVendors ?? 0) > 0 && (
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="text-[10px] font-mono text-muted-foreground">
                  {language === "pt" ? "Confiança" : "Confidence"}: <strong className="text-foreground">{confidence}%</strong>
                  <span className="opacity-60"> · {reportingVendors} {language === "pt" ? "fontes" : "vendors"}</span>
                </span>
                {disagreement && (
                  <span
                    className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-[9px] font-bold text-orange-500 uppercase tracking-wide"
                    title={language === "pt"
                      ? "Fontes divergem — revise o relatório minoritário antes de agir"
                      : "Vendors disagree — review the minority report before acting"}
                  >
                    <Info className="h-2.5 w-2.5" /> {language === "pt" ? "fontes divergem" : "vendors disagree"}
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Detections Info Block */}
          <div className="space-y-1.5">
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">{t('detections')}</p>
            <p className="text-3xl font-extrabold tracking-tight">
              {detections}<span className="text-sm font-semibold text-muted-foreground">/{totalVendors} vendors</span>
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
