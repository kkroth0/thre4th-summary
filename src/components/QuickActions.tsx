import { Button } from "@/components/ui/button";
import { RefreshCw, Copy, Link2 } from "lucide-react";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";

interface QuickActionsProps {
  data: ThreatIntelligenceResult;
  onRefresh: () => void;
  isLoading: boolean;
  onCopyLinks: () => void;
}

export const QuickActions = ({ data, onRefresh, isLoading, onCopyLinks }: QuickActionsProps) => {
  const { toast } = useToast();
  const { t } = useLanguage();

  const extractCopyData = () => {
    const vtData = data.vendorData.find(v => v.name === "VirusTotal")?.data;
    const abuseData = data.vendorData.find(v => v.name === "AbuseIPDB")?.data;
    const geoData = data.vendorData.find(v => v.name === "IP Geolocation")?.data;
    const shodanData = data.vendorData.find(v => v.name === "Shodan")?.data;
    const whoisData = data.vendorData.find(v => v.name === "WHOIS")?.data;

    // Resolve Hostname
    const reverseHostname = geoData?.["Reverse Hostname"];
    const abuseHostnames = abuseData?.["Hostnames"];
    const shodanHostnames = shodanData?.["Hostnames"];
    let resolvedHostname = "—";
    if (reverseHostname && reverseHostname !== "Unknown" && reverseHostname !== "None") {
      resolvedHostname = reverseHostname;
    } else if (abuseHostnames && abuseHostnames !== "None" && abuseHostnames !== "Unknown") {
      resolvedHostname = abuseHostnames.split(",")[0].trim();
    } else if (shodanHostnames && shodanHostnames !== "None" && shodanHostnames !== "Unknown") {
      resolvedHostname = shodanHostnames.split(",")[0].trim();
    }

    // Network / Geo
    const country = geoData?.["Country"] || abuseData?.["Country"] || "—";
    const isp = geoData?.["ISP"] || abuseData?.["ISP"] || "—";
    const asn = geoData?.["AS"] || vtData?.["ASN"] || "—";
    const proxyVpn = geoData?.["Proxy/VPN"] || "Unknown";
    const hosting = geoData?.["Hosting"] || "Unknown";

    // Key Indicators
    const indicators: string[] = [];
    if (whoisData && !whoisData.error) {
      if (whoisData["Registrar"] && whoisData["Registrar"] !== "Unknown") {
        indicators.push(`- Domain Registrar: ${whoisData["Registrar"]} (WHOIS)`);
      }
      if (whoisData["Created"] && whoisData["Created"] !== "Unknown") {
        indicators.push(`- Domain Created Date: ${whoisData["Created"]} (WHOIS)`);
      }
    }
    if (shodanData && !shodanData.error) {
      if (shodanData["Vulnerabilities"] && shodanData["Vulnerabilities"] !== "0 CVEs") {
        indicators.push(`- Vulnerabilities Found: ${shodanData["Vulnerabilities"]} (Shodan)`);
      }
      if (shodanData["Services"] && shodanData["Services"] !== "Unknown" && shodanData["Services"] !== "") {
        indicators.push(`- Detected Services: ${shodanData["Services"]} (Shodan)`);
      }
    }
    // Ports
    const ports = new Set<string>();
    data.vendorData.forEach(vendor => {
      if (vendor.data && vendor.data["Open Ports"] && vendor.data["Open Ports"] !== "None") {
        vendor.data["Open Ports"].split(", ").forEach((p: string) => ports.add(p));
      }
    });
    if (ports.size > 0) {
      indicators.push(`- Open Ports Found: ${Array.from(ports).slice(0, 5).join(", ")} (Multiple)`);
    }

    // Vendor Intelligence
    const vtScore = vtData?.["Detection Rate"] ? `${vtData["Detection Rate"]} (${vtData["Status"] || "Unknown"})` : "—";
    const abuseConf = abuseData?.["Abuse Confidence Score"] !== undefined ? `${abuseData["Abuse Confidence Score"]}% (Reports: ${abuseData["Total Reports"] || 0})` : "—";

    let report = `THREATSUMM4RY INTEL REPORT
========================================
Target: ${data.query}
Hostname: ${resolvedHostname}
Threat Level: ${data.threatLevel.toUpperCase()}
Overall Risk Score: ${data.overallScore}/100
Detections: ${data.detections}/${data.totalVendors} vendors

GEOGRAPHIC & NETWORK INFO
----------------------------------------
Country: ${country}
ISP: ${isp}
AS/ASN: ${asn}
Proxy/VPN: ${proxyVpn}
Hosting: ${hosting}

`;

    if (indicators.length > 0) {
      report += `KEY INDICATORS
----------------------------------------
${indicators.join("\n")}

`;
    }

    report += `VENDOR INTELLIGENCE
----------------------------------------
- VirusTotal: ${vtScore}
- AbuseIPDB: ${abuseConf}
========================================
Report generated on ${new Date().toLocaleString()} (Local Time)`;

    return report;
  };

  const handleCopy = () => {
    const text = extractCopyData();
    navigator.clipboard.writeText(text);
    toast({
      title: t('copied'),
      description: t('summaryCopied'),
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
        <Link2 className="mr-2 h-4 w-4" />
        {t('copyLinks')}
      </Button>
    </div>
  );
};
