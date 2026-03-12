import { Button } from "@/components/ui/button";
import { RefreshCw, Copy, Download, Share2, FileText, Zap, FileJson } from "lucide-react";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface QuickActionsProps {
  data: ThreatIntelligenceResult;
  onRefresh: () => void;
  isLoading: boolean;
  onCopyLinks: () => void;
  onExportFullReport?: () => void;
  isExportingPDF?: boolean;
}

export const QuickActions = ({ data, onRefresh, isLoading, onCopyLinks, onExportFullReport, isExportingPDF }: QuickActionsProps) => {
  const { toast } = useToast();
  const { t } = useLanguage();

  const extractCopyData = () => {
    const vtData = data.vendorData.find(v => v.name === "VirusTotal")?.data;
    const abuseData = data.vendorData.find(v => v.name === "AbuseIPDB")?.data;
    const geoData = data.vendorData.find(v => v.name === "IP Geolocation")?.data;

    const hostname = abuseData?.["Hostnames"] && abuseData["Hostnames"] !== "None" ? abuseData["Hostnames"].split(",")[0] : "—";
    const country = geoData?.["Country"] || abuseData?.["Country"] || "—";
    const isp = geoData?.["ISP"] || abuseData?.["ISP"] || "—";

    const vtScore = vtData?.["Detection Rate"] ? vtData["Detection Rate"] : "—";
    const abuseConf = abuseData?.["Abuse Confidence Score"] !== undefined ? `${abuseData["Abuse Confidence Score"]}% (Reports: ${abuseData["Total Reports"] || 0})` : "—";

    return `🛡️ ThreatSumm4ry Intelligence Report
================================
Target: ${data.query}
Hostname: ${hostname}
Threat Level: ${data.threatLevel.toUpperCase()}
Score: ${data.overallScore}/100
Detections: ${data.detections}/${data.totalVendors}

📍 Geographic & Network
Country: ${country}
ISP: ${isp}

🔍 Key Vendor Intelligence
VirusTotal: ${vtScore}
AbuseIPDB: ${abuseConf}`;
  };

  const handleCopy = () => {
    const text = extractCopyData();
    navigator.clipboard.writeText(text);
    toast({
      title: t('copied'),
      description: t('summaryCopied'),
    });
  };

  const handleExportPDF = () => {
    if (onExportFullReport) {
        onExportFullReport();
    }
  };

  const handleExportJSON = () => {
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-report-${data.query}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast({
      title: t('exportSuccess'),
      description: t('jsonDownloaded'),
    });
  };

  return (
    <div className="flex flex-wrap gap-2 animate-fade-in">
      <Button variant="outline" size="sm" onClick={onRefresh} disabled={isLoading}>
        <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
        {t('refresh')}
      </Button>
      <Button variant="outline" size="sm" onClick={handleCopy}>
        <Copy className="mr-2 h-4 w-4" />
        {t('copySummary')}
      </Button>
      <Button variant="outline" size="sm" onClick={onCopyLinks}>
        <Share2 className="mr-2 h-4 w-4" />
        {t('copyLinks')}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-2">
            <Download className="h-4 w-4" />
            {t('export')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={handleExportPDF} disabled={isExportingPDF}>
            <FileText className="mr-2 h-4 w-4" />
            {isExportingPDF ? "Building Report..." : t('downloadPdf')}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleExportJSON}>
            <FileJson className="mr-2 h-4 w-4" />
            {t('downloadJson')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
};
