import { Card } from "@/components/ui/card";
import { VendorData } from "@/types/threat-intelligence";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";
import { useLanguage } from "@/contexts/LanguageContext";

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
      if (ipGeo["Proxy/VPN"] && ipGeo["Proxy/VPN"] !== "No") data["Proxy/VPN"] = ipGeo["Proxy/VPN"];
    }

    if (vt && !vt.error) {
      if (!data["ASN"] && vt["ASN"] && vt["ASN"] !== "Unknown") data["ASN"] = vt["ASN"];
      if (!data["Network"] && vt["Network"] && vt["Network"] !== "Unknown") data["Network"] = vt["Network"];
    }

    return Object.keys(data).length > 0 ? data : { "Status": "No network data available" };
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
        status: `Confidence: ${data["Abuse Confidence Score"]}`
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
        fill: score > 70 ? "hsl(var(--destructive))" : score > 30 ? "#eab308" : "hsl(var(--primary))"
      };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const indicators = getKeyIndicators();
  const networkData = getNetworkData();

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-popover border text-popover-foreground p-2 rounded shadow-md text-sm">
          <p className="font-semibold">{label}</p>
          <p>{t('score')}: {payload[0].value}/100</p>
          <p className="text-muted-foreground">{payload[0].payload.status}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="grid gap-4 md:grid-cols-3 animate-fade-in">
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Key Indicators</h3>
        <div className="space-y-4 max-h-[300px] overflow-y-auto pr-2">
          {indicators.length > 0 ? indicators.map((ind, idx) => (
            <div key={idx} className="flex flex-col gap-1 border-b pb-3 last:border-0">
              <span className="text-sm font-medium text-foreground">{ind.type}</span>
              <span className="text-xs text-muted-foreground break-words">{ind.value}</span>
              <span className="text-[10px] text-muted-foreground/70 uppercase">src: {ind.source}</span>
            </div>
          )) : (
            <p className="text-sm text-muted-foreground">No prominent indicators detected.</p>
          )}
        </div>
      </Card>

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Geographic & Network Data</h3>
        <div className="flex flex-col text-sm w-full divide-y">
          {Object.entries(networkData).map(([key, value]) => (
            <div key={key} className="grid grid-cols-1 sm:grid-cols-[130px_1fr] py-3 items-start gap-1 sm:gap-4">
              <span className="font-medium text-muted-foreground">{key}</span>
              <span className="text-foreground font-medium break-words sm:text-right">{value}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">{t('vendorThreatScores')}</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={vendorScores} layout="vertical" margin={{ left: 20 }}>
            <XAxis type="number" domain={[0, 100]} hide />
            <YAxis type="category" dataKey="name" width={100} style={{ fontSize: '12px' }} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="score" radius={[0, 4, 4, 0]}>
              {vendorScores.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
};
