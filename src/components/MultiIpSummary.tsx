import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { ThreatBadge } from "./ThreatBadge";
import { Copy, ArrowRight, ShieldAlert, Globe, Activity, FileSpreadsheet, Server, Info } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";

interface MultiIpSummaryProps {
    results: ThreatIntelligenceResult[];
    onViewDetails: (query: string) => void;
}

export const MultiIpSummary = ({ results, onViewDetails }: MultiIpSummaryProps) => {
    const { toast } = useToast();
    const { t } = useLanguage();

    const copyReport = (result: ThreatIntelligenceResult) => {
        const vtData = result.vendorData.find(v => v.name === "VirusTotal")?.data;
        const abuseData = result.vendorData.find(v => v.name === "AbuseIPDB")?.data;
        const geoData = result.vendorData.find(v => v.name === "IP Geolocation")?.data;

        const hostname = abuseData?.["Hostnames"] && abuseData["Hostnames"] !== "None" ? abuseData["Hostnames"].split(",")[0] : "—";
        const country = geoData?.["Country"] || abuseData?.["Country"] || "—";
        const isp = geoData?.["ISP"] || abuseData?.["ISP"] || "—";

        const vtScore = vtData?.["Detection Rate"] ? vtData["Detection Rate"] : "—";
        const abuseConf = abuseData?.["Abuse Confidence Score"] !== undefined ? `${abuseData["Abuse Confidence Score"]}% (Reports: ${abuseData["Total Reports"] || 0})` : "—";

        const text = `🛡️ ThreatSumm4ry Intelligence Report
================================
Target: ${result.query}
Hostname: ${hostname}
Threat Level: ${result.threatLevel.toUpperCase()}
Score: ${result.overallScore}/100
Detections: ${result.detections}/${result.totalVendors}

📍 Geographic & Network
Country: ${country}
ISP: ${isp}

🔍 Key Vendor Intelligence
VirusTotal: ${vtScore}
AbuseIPDB: ${abuseConf}`;
        navigator.clipboard.writeText(text);
        toast({
            title: "Copied",
            description: `Report for ${result.query} copied to clipboard`,
        });
    };

    return (
        <div className="rounded-md border bg-card hide-scrollbar-table [&>div]:[scrollbar-width:none] [&>div]:[-ms-overflow-style:none] [&>div::-webkit-scrollbar]:hidden">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Target</TableHead>
                            <TableHead>
                                <div className="flex items-center gap-1">
                                    Threat Level
                                    <Dialog>
                                        <DialogTrigger asChild>
                                            <Button variant="ghost" size="icon" className="h-4 w-4 rounded-full text-muted-foreground hover:text-foreground">
                                                <Info className="h-3 w-3" />
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
                            </TableHead>
                            <TableHead>Score</TableHead>
                        <TableHead><ShieldAlert className="inline h-4 w-4 mr-1 text-muted-foreground"/> VirusTotal</TableHead>
                        <TableHead><FileSpreadsheet className="inline h-4 w-4 mr-1 text-muted-foreground"/> AbuseIPDB</TableHead>
                        <TableHead><Activity className="inline h-4 w-4 mr-1 text-muted-foreground"/> OTX</TableHead>
                        <TableHead><Globe className="inline h-4 w-4 mr-1 text-muted-foreground"/> Country</TableHead>
                        <TableHead><Server className="inline h-4 w-4 mr-1 text-muted-foreground"/> ISP</TableHead>
                        <TableHead>Detections</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {results.map((result) => {
                        // Extract Vendor Data for extra columns
                        const vtData = result.vendorData.find(v => v.name === "VirusTotal")?.data;
                        const abuseData = result.vendorData.find(v => v.name === "AbuseIPDB")?.data;
                        const otxData = result.vendorData.find(v => v.name === "AlienVault OTX")?.data;
                        const geoData = result.vendorData.find(v => v.name === "IP Geolocation")?.data;

                        // Parse metrics
                        const vtScore = vtData?.["Detection Rate"] ? vtData["Detection Rate"] : "—";
                        
                        const abuseConf = abuseData?.["Abuse Confidence Score"] ? abuseData["Abuse Confidence Score"] : "—";
                        const abuseReports = abuseData?.["Total Reports"] ? `(${abuseData["Total Reports"]} rep)` : "";
                        const abuseCombined = abuseConf !== "—" ? `${abuseConf} ${abuseReports}` : "—";
                        
                        const otxStatus = otxData?.["Status"] ? otxData["Status"] : "—";
                        const otxPulses = otxData?.["Pulse Count"] ? `(${otxData["Pulse Count"]})` : "";
                        const otxCombined = otxStatus !== "—" ? `${otxStatus} ${otxPulses}` : "—";

                        const country = geoData?.["Country"] || abuseData?.["Country"] || "—";
                        const isp = geoData?.["ISP"] || abuseData?.["ISP"] || "—";
                        const hostname = abuseData?.["Hostnames"] && abuseData["Hostnames"] !== "None" 
                            ? abuseData["Hostnames"].split(",")[0] 
                            : "";

                        return (
                            <TableRow key={result.query} className="hover:bg-muted/50 transition-colors">
                                <TableCell className="font-mono">
                                    <div className="font-semibold">{result.query}</div>
                                    {hostname && <div className="text-xs text-muted-foreground mt-1 truncate max-w-[150px]" title={hostname}>{hostname}</div>}
                                </TableCell>
                            <TableCell>
                                <ThreatBadge level={result.threatLevel} />
                            </TableCell>
                            <TableCell>
                                <div className="flex items-center gap-2">
                                    <span className={`font-bold ${result.overallScore > 70 ? "text-destructive" :
                                            result.overallScore > 30 ? "text-orange-500" : "text-green-500"
                                        }`}>
                                        {result.overallScore}
                                    </span>
                                    <span className="text-muted-foreground text-xs">/100</span>
                                </div>
                            </TableCell>
                            <TableCell className="text-muted-foreground whitespace-nowrap">
                                {vtScore}
                            </TableCell>
                            <TableCell className="text-muted-foreground whitespace-nowrap">
                                {abuseCombined}
                            </TableCell>
                            <TableCell className="text-muted-foreground whitespace-nowrap">
                                {otxCombined}
                            </TableCell>
                            <TableCell className="text-muted-foreground whitespace-nowrap">
                                {country}
                            </TableCell>
                            <TableCell className="text-muted-foreground truncate max-w-[150px]" title={isp}>
                                {isp}
                            </TableCell>
                            <TableCell>
                                <span className={result.detections > 0 ? "text-destructive font-semibold" : ""}>{result.detections}</span>
                                <span className="text-muted-foreground text-xs ml-1">/{result.totalVendors}</span>
                            </TableCell>
                            <TableCell className="text-right">
                                <div className="flex justify-end gap-1">
                                    <Button variant="ghost" size="icon" onClick={() => copyReport(result)} title="Copy Summary" className="h-8 w-8">
                                        <Copy className="h-4 w-4" />
                                    </Button>
                                    <Button variant="ghost" size="icon" onClick={() => onViewDetails(result.query)} title="View Details" className="h-8 w-8">
                                        <ArrowRight className="h-4 w-4" />
                                    </Button>
                                </div>
                            </TableCell>
                        </TableRow>
                        );
                    })}
                </TableBody>
            </Table>
        </div>
    );
};
