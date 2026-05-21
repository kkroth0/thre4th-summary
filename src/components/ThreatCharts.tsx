import { Card } from "@/components/ui/card";
import { VendorData } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";
import { Shield, Globe, Server, MapPin, Radio, Key, ShieldAlert, Clock } from "lucide-react";

interface ThreatChartsProps {
  vendorData: VendorData[];
  detections: number;
  totalVendors: number;
}

export const ThreatCharts = ({ vendorData, detections, totalVendors }: ThreatChartsProps) => {
  const { t } = useLanguage();

  // Key Indicators (Vendor Specific)
  const getKeyIndicators = () => {
    const indicators: { type: string, value: string, source: string }[] = [];
    
    // Explicit VT Insights
    const vt = vendorData.find(v => v.name === "VirusTotal")?.data;
    if (vt && !vt.error && vt["Detection Rate"]) {
      indicators.push({ type: "Detection Engine Hits", value: vt["Detection Rate"], source: "VirusTotal" });
    }

    // Explicit AbuseIPDB Insights
    const abuse = vendorData.find(v => v.name === "AbuseIPDB")?.data;
    if (abuse && !abuse.error) {
      if (abuse["Abuse Confidence Score"]) indicators.push({ type: "Confidence Score", value: `${abuse["Abuse Confidence Score"]}%`, source: "AbuseIPDB" });
      if (abuse["Total Reports"] && abuse["Total Reports"] > 0) indicators.push({ type: "Crowdsourced Reports", value: `${abuse["Total Reports"]} reports`, source: "AbuseIPDB" });
      if (abuse["Tags"] && abuse["Tags"] !== "None") indicators.push({ type: "Behavior Tags", value: abuse["Tags"], source: "AbuseIPDB" });
    }

    // Explicit OTX Insights
    const otx = vendorData.find(v => v.name === "AlienVault OTX")?.data;
    if (otx && !otx.error && otx["Pulse Count"] && parseInt(otx["Pulse Count"]) > 0) {
      indicators.push({ type: "Threat Intelligence Pulses", value: `${otx["Pulse Count"]} pulses active`, source: "AlienVault OTX" });
    }

    // VPN/Proxy and Hosting status from IP Geolocation
    const geo = vendorData.find(v => v.name === "IP Geolocation")?.data;
    if (geo && !geo.error) {
      if (geo["Proxy/VPN"] === "Yes ⚠️" || geo["Proxy/VPN"] === "Yes") {
        indicators.push({ type: "VPN / Proxy Alert", value: "Active VPN/Proxy Detected", source: "IP Geolocation" });
      }
      if (geo["Hosting"] === "Yes") {
        indicators.push({ type: "Hosting Status", value: "Hosted on Datacenter / Cloud", source: "IP Geolocation" });
      }
    }

    // WHOIS Insights
    const whois = vendorData.find(v => v.name === "WHOIS")?.data;
    if (whois && !whois.error) {
      if (whois["Registrar"] && whois["Registrar"] !== "Unknown") {
        indicators.push({ type: "Domain Registrar", value: whois["Registrar"], source: "WHOIS" });
      }
      if (whois["Created"] && whois["Created"] !== "Unknown") {
        try {
          const createdDate = new Date(whois["Created"]).toLocaleDateString();
          indicators.push({ type: "Domain Created Date", value: createdDate, source: "WHOIS" });
        } catch {
          indicators.push({ type: "Domain Created Date", value: whois["Created"], source: "WHOIS" });
        }
      }
    }

    // Shodan Insights
    const shodan = vendorData.find(v => v.name === "Shodan")?.data;
    if (shodan && !shodan.error) {
      if (shodan["Vulnerabilities"] && shodan["Vulnerabilities"] !== "0 CVEs") {
        indicators.push({ type: "Vulnerabilities Found", value: shodan["Vulnerabilities"], source: "Shodan" });
      }
      if (shodan["Services"] && shodan["Services"] !== "Unknown" && shodan["Services"] !== "") {
        indicators.push({ type: "Detected Services", value: shodan["Services"], source: "Shodan" });
      }
    }
    
    // Fallback Prominent Open Ports
    const ports = new Set<string>();
    vendorData.forEach(vendor => {
      if (vendor.data && vendor.data["Open Ports"] && vendor.data["Open Ports"] !== "None") {
        vendor.data["Open Ports"].split(", ").forEach((p: string) => ports.add(p));
      }
    });

    if (ports.size > 0 && indicators.length < 5) {
      indicators.push({ type: "Open Ports Found", value: Array.from(ports).slice(0, 5).join(", "), source: "Multiple" });
    }

    return indicators;
  };

  // Geographic & Network Data
  const getNetworkData = () => {
    const data: Record<string, string> = {};
    const ipGeo = vendorData.find(v => v.name === "IP Geolocation")?.data;
    const vt = vendorData.find(v => v.name === "VirusTotal")?.data;

    if (ipGeo && !ipGeo.error) {
      if (ipGeo["ISP"] && ipGeo["ISP"] !== "Unknown") data["ISP"] = ipGeo["ISP"];
      if (ipGeo["Organization"] && ipGeo["Organization"] !== "Unknown") data["Organization"] = ipGeo["Organization"];
      if (ipGeo["Country"] && ipGeo["Country"] !== "Unknown") data["Country"] = ipGeo["Country"];
      if (ipGeo["Region"] && ipGeo["Region"] !== "Unknown") data["Region"] = ipGeo["Region"];
      if (ipGeo["City"] && ipGeo["City"] !== "Unknown") data["City"] = ipGeo["City"];
      if (ipGeo["Timezone"] && ipGeo["Timezone"] !== "Unknown") data["Timezone"] = ipGeo["Timezone"];
      if (ipGeo["AS"] && ipGeo["AS"] !== "Unknown") data["ASN/AS"] = ipGeo["AS"];
      if (ipGeo["Proxy/VPN"] && ipGeo["Proxy/VPN"] !== "No") data["Proxy/VPN"] = ipGeo["Proxy/VPN"];
      if (ipGeo["Hosting"] && ipGeo["Hosting"] !== "No") data["Hosting"] = ipGeo["Hosting"];
    }

    if (vt && !vt.error) {
      if (!data["ASN/AS"] && vt["ASN"] && vt["ASN"] !== "Unknown") data["ASN/AS"] = vt["ASN"];
      if (!data["Network"] && vt["Network"] && vt["Network"] !== "Unknown") data["Network"] = vt["Network"];
    }

    return data;
  };

  // Vendor Threat Scores
  const getVendorScore = (vendor: VendorData): { score: number, status: string } => {
    const data = vendor.data;
    if (!data || Object.keys(data).length === 0 || vendor.error) return { score: 0, status: "No Data" };

    // VirusTotal
    if (data["Detection Rate"]) {
      const parts = data["Detection Rate"].split("/");
      if (parts.length === 2) {
        return {
          score: Math.round((parseInt(parts[0]) / parseInt(parts[1])) * 100),
          status: data["Status"] || t('unknown')
        };
      }
    }

    // AbuseIPDB
    if (data["Abuse Confidence Score"]) {
      return {
        score: parseInt(data["Abuse Confidence Score"]),
        status: `Confidence: ${data["Abuse Confidence Score"]}%`
      };
    }

    // IPQualityScore
    if (data["Fraud Score"]) {
      return {
        score: parseInt(data["Fraud Score"]),
        status: data["Status"] || t('unknown')
      };
    }

    // Hybrid Analysis
    if (data["Threat Score"]) {
      return {
        score: parseInt(data["Threat Score"]),
        status: `Score: ${data["Threat Score"]}`
      };
    }

    // Fallback based on Status string
    const status = (data["Status"] || "").toLowerCase();
    if (status.includes("malicious") || status.includes("unsafe") || status.includes("phishing") || status.includes("high risk")) {
      return { score: 100, status: data["Status"] };
    }
    if (status.includes("suspicious") || status.includes("moderate risk")) {
      return { score: 60, status: data["Status"] };
    }
    if (status.includes("low risk")) {
      return { score: 30, status: data["Status"] };
    }

    return { score: 0, status: data["Status"] || t('clean') };
  };

  const vendorScores = vendorData
    .map(vendor => {
      const { score, status } = getVendorScore(vendor);
      return {
        name: vendor.name,
        score,
        status,
        fill: score > 70 ? "hsl(var(--destructive))" : score > 30 ? "#eab308" : "#10b981"
      };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const indicators = getKeyIndicators();
  const networkData = getNetworkData();
  const hasNetworkData = Object.keys(networkData).length > 0;

  return (
    <div className="grid gap-6 md:grid-cols-3 animate-fade-in">
      {/* Key Indicators Card */}
      <Card className="p-6 border border-primary/10 bg-card/45 backdrop-blur-md shadow-md shadow-primary/5 flex flex-col">
        <h3 className="text-sm font-bold tracking-wider uppercase text-muted-foreground mb-4">Key Indicators</h3>
        <div className="flex-1 space-y-4 max-h-[300px] overflow-y-auto pr-1.5 [scrollbar-width:thin] [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-muted/80 [&::-webkit-scrollbar-thumb]:rounded-full">
          {indicators.length > 0 ? indicators.map((ind, idx) => (
            <div key={idx} className="flex flex-col gap-1 border-b border-border/40 pb-3 last:border-0 last:pb-0">
              <span className="text-xs font-semibold text-foreground">{ind.type}</span>
              <span className="text-sm font-bold text-primary break-words mt-0.5">{ind.value}</span>
              <span className="text-[9px] text-muted-foreground/60 uppercase font-mono tracking-wider">src: {ind.source}</span>
            </div>
          )) : (
            <div className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border/60 rounded-xl bg-muted/10">
              <Shield className="h-7 w-7 text-muted-foreground/50 mb-2.5" />
              <p className="text-xs font-semibold text-muted-foreground">No indicators detected</p>
              <p className="text-[10px] text-muted-foreground/50 max-w-[180px] mt-1 leading-normal">
                This target did not trigger specific alerts on VT, AbuseIPDB or AlienVault.
              </p>
            </div>
          )}
        </div>
      </Card>

      {/* Geographic & Network Data Card */}
      <Card className="p-6 border border-primary/10 bg-card/45 backdrop-blur-md shadow-md shadow-primary/5 flex flex-col">
        <h3 className="text-sm font-bold tracking-wider uppercase text-muted-foreground mb-4">Geographic & Network Data</h3>
        <div className="flex-1 flex flex-col text-sm justify-center">
          {hasNetworkData ? (
            <div className="divide-y divide-border/40 w-full">
              {Object.entries(networkData).map(([key, value]) => {
                let Icon = Globe;
                if (key === "Country" || key === "Region" || key === "City") Icon = MapPin;
                else if (key === "ISP") Icon = Radio;
                else if (key === "Organization") Icon = Globe;
                else if (key === "ASN/AS" || key === "ASN") Icon = Key;
                else if (key === "Network" || key === "Hosting") Icon = Server;
                else if (key === "Timezone") Icon = Clock;
                else if (key === "Proxy/VPN") Icon = ShieldAlert;
                return (
                  <div key={key} className="flex items-center justify-between py-2.5 first:pt-0 last:pb-0">
                    <div className="flex items-center gap-2">
                      <Icon className="h-4 w-4 text-primary/70 shrink-0" />
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{key}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-foreground max-w-[170px] truncate" title={value}>
                      {value}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border/60 rounded-xl bg-muted/10">
              <Globe className="h-7 w-7 text-muted-foreground/50 mb-2.5" />
              <p className="text-xs font-semibold text-muted-foreground">No network data</p>
              <p className="text-[10px] text-muted-foreground/50 max-w-[180px] mt-1 leading-normal">
                Could not retrieve ISP, Country, or ASN geolocation info.
              </p>
            </div>
          )}
        </div>
      </Card>

      {/* Vendor Threat Scores Card */}
      <Card className="p-6 border border-primary/10 bg-card/45 backdrop-blur-md shadow-md shadow-primary/5 flex flex-col">
        <h3 className="text-sm font-bold tracking-wider uppercase text-muted-foreground mb-4">{t('vendorThreatScores')}</h3>
        <div className="flex-1 space-y-4 max-h-[300px] overflow-y-auto pr-1.5 [scrollbar-width:thin] [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-muted/80 [&::-webkit-scrollbar-thumb]:rounded-full">
          {vendorScores.length > 0 ? (
            vendorScores.map((vendor, idx) => {
              const statusBadgeColor = vendor.score > 70 ? "bg-destructive/10 text-destructive border-destructive/20" :
                                       vendor.score > 30 ? "bg-amber-500/10 text-amber-500 border-amber-500/20" :
                                       "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
              return (
                <div key={idx} className="space-y-1.5 border-b border-border/40 pb-3 last:border-0 last:pb-0">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-semibold text-foreground">{vendor.name}</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded border uppercase font-mono font-semibold tracking-wider ${statusBadgeColor}`}>
                        {vendor.status}
                      </span>
                      <div className="flex items-center gap-0.5">
                        <span className={`font-bold ${
                          vendor.score > 70 ? "text-destructive" :
                          vendor.score > 30 ? "text-amber-500" : "text-emerald-500"
                        }`}>{vendor.score}</span>
                        <span className="text-muted-foreground/60 text-[10px]">/100</span>
                      </div>
                    </div>
                  </div>
                  <div className="w-full bg-muted/40 h-2 rounded-full overflow-hidden border border-muted/20 relative shadow-inner">
                    <div
                      className="h-full rounded-full transition-all duration-1000 ease-out"
                      style={{
                        width: `${vendor.score}%`,
                        backgroundColor: vendor.fill,
                        boxShadow: `0 0 6px ${vendor.fill}80`
                      }}
                    />
                  </div>
                </div>
              );
            })
          ) : (
            <p className="text-xs text-muted-foreground">No vendor scores recorded.</p>
          )}
        </div>
      </Card>
    </div>
  );
};
