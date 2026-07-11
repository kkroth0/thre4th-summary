import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import {
    Copy,
    ArrowRight,
    Globe,
    Server,
    Info,
    Check,
    Activity,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import { OverviewIpMap } from "@/components/OverviewIpMap";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";

/* ── Helpers ─────────────────────────────────────────────────────── */
const getFlagEmoji = (code: string) => {
    if (!code) return "";
    try {
        return String.fromCodePoint(...code.toUpperCase().split("").map(c => 127397 + c.charCodeAt(0)));
    } catch {
        return "";
    }
};

const parseCountry = (s: string) => {
    if (!s || s === "—") return { name: "—", code: "" };
    const m = s.match(/^(.*?)\s*\((.*?)\)$/);
    if (m) return { name: m[1].trim(), code: m[2].toUpperCase() };
    if (s.length === 2) return { name: s, code: s.toUpperCase() };
    return { name: s, code: "" };
};

/* ── Component ───────────────────────────────────────────────────── */
interface MultiIpSummaryProps {
    results: ThreatIntelligenceResult[];
    onViewDetails: (query: string) => void;
}

export const MultiIpSummary = ({ results, onViewDetails }: MultiIpSummaryProps) => {
    const { toast } = useToast();
    const { t, language } = useLanguage();
    const [copiedIp, setCopiedIp] = useState<string | null>(null);
    const pt = language === "pt";

    const handleCopy = (ip: string) => {
        navigator.clipboard.writeText(ip);
        setCopiedIp(ip);
        toast({ title: "Copied", description: `${ip} copied to clipboard` });
        setTimeout(() => setCopiedIp(null), 2000);
    };

    const copyReport = (r: ThreatIntelligenceResult) => {
        const vt = r.vendorData.find(v => v.name === "VirusTotal")?.data;
        const ab = r.vendorData.find(v => v.name === "AbuseIPDB")?.data;
        const geo = r.vendorData.find(v => v.name === "IP Geolocation")?.data;
        const hostname = ab?.["Hostnames"] && ab["Hostnames"] !== "None" ? ab["Hostnames"].split(",")[0] : "—";
        const country = geo?.["Country"] || ab?.["Country"] || "—";
        const isp = geo?.["ISP"] || ab?.["ISP"] || "—";
        const vtScore = vt?.["Detection Rate"] ?? "—";
        const abuseConf = ab?.["Abuse Confidence Score"] !== undefined ? `${ab["Abuse Confidence Score"]}%` : "—";

        const text = `🛡️ ThreatSumm4ry Report\n${"═".repeat(30)}\nTarget: ${r.query}\nHostname: ${hostname}\nThreat: ${r.threatLevel.toUpperCase()} (${r.overallScore}/100)\nDetections: ${r.detections}/${r.totalVendors}\n\n📍 ${country} · ${isp}\n🔍 VT: ${vtScore} · AbuseIPDB: ${abuseConf}`;
        navigator.clipboard.writeText(text);
        toast({ title: "Copied", description: `Report for ${r.query} copied` });
    };

    const totalDetections = results.reduce((sum, r) => sum + r.detections, 0);
    const maliciousCount = results.filter((r) => r.threatLevel === "malicious").length;
    const suspiciousCount = results.filter((r) => r.threatLevel === "suspicious").length;
    const maxScore = Math.max(0, ...results.map((r) => r.overallScore || 0));

    return (
        <div className="space-y-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <div>
                    <div className="flex items-center gap-2">
                        <h2 className="text-2xl font-black tracking-tight">
                            {pt ? "Resumo em cards" : "Card summary"}
                        </h2>
                        <Dialog>
                            <DialogTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-6 w-6 rounded-full text-muted-foreground hover:text-foreground">
                                    <Info className="h-3.5 w-3.5" />
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-md">
                                <DialogHeader>
                                    <DialogTitle>{t('threatLevelScoringMethodology')}</DialogTitle>
                                </DialogHeader>
                                <div className="space-y-4 text-sm mt-2">
                                    <p className="text-muted-foreground text-xs">{t('threatEngineExplanation')}</p>
                                    <div className="space-y-2">
                                        <h4 className="font-semibold border-b pb-1 text-xs uppercase tracking-wider">{t('scoringThresholds')}</h4>
                                        <ul className="space-y-1 list-disc pl-4 text-xs text-muted-foreground">
                                            <li><strong className="text-emerald-500">SAFE (0-30):</strong> {t('safeDesc')}</li>
                                            <li><strong className="text-amber-500">SUSPICIOUS (31-70):</strong> {t('suspiciousDesc')}</li>
                                            <li><strong className="text-red-500">MALICIOUS (71-100):</strong> {t('maliciousDesc')}</li>
                                        </ul>
                                    </div>
                                </div>
                            </DialogContent>
                        </Dialog>
                    </div>
                    <p className="mt-1 text-sm font-medium text-muted-foreground">
                        {pt
                            ? `${results.length} alvo(s) analisado(s) com foco em triagem rápida.`
                            : `${results.length} target(s) analyzed for fast triage.`}
                    </p>
                </div>

                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                    {[
                        [pt ? "Alvos" : "Targets", results.length, "text-foreground"],
                        [pt ? "Detecções" : "Detections", totalDetections, totalDetections ? "text-red-500" : "text-emerald-500"],
                        [pt ? "Críticos" : "Malicious", maliciousCount, "text-red-500"],
                        [pt ? "Maior score" : "Top score", maxScore, maxScore > 70 ? "text-red-500" : maxScore > 30 ? "text-amber-500" : "text-emerald-500"],
                    ].map(([label, value, color]) => (
                        <div key={String(label)} className="rounded-lg border border-border bg-card px-3 py-2 text-right">
                            <div className={`font-mono text-lg font-black ${color}`}>{value}</div>
                            <div className="text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{label}</div>
                        </div>
                    ))}
                </div>
            </div>

            <OverviewIpMap results={results} onViewDetails={onViewDetails} />

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                {results.map((result) => {
                    const vt = result.vendorData.find(v => v.name === "VirusTotal")?.data;
                    const ab = result.vendorData.find(v => v.name === "AbuseIPDB")?.data;
                    const geo = result.vendorData.find(v => v.name === "IP Geolocation")?.data;
                    const otxData = result.vendorData.find(v => v.name === "AlienVault OTX")?.data;

                    const vtScore = vt?.["Detection Rate"] ?? "-";
                    const abuseScore = ab?.["Abuse Confidence Score"] ?? null;
                    const country = geo?.["Country"] || ab?.["Country"] || "-";
                    const isp = geo?.["ISP"] || ab?.["ISP"] || "-";
                    const hostname = ab?.["Hostnames"] && ab["Hostnames"] !== "None" ? ab["Hostnames"].split(",")[0] : null;
                    const pulseCount = otxData && otxData["Pulse Count"] !== undefined ? Number(otxData["Pulse Count"]) : null;
                    const pulseText = pulseCount !== null ? `${pulseCount} pulse${pulseCount === 1 ? "" : "s"}` : "-";

                    const { name: countryName, code: countryCode } = parseCountry(country);
                    const flag = getFlagEmoji(countryCode);

                    const isM = result.threatLevel === "malicious";
                    const isS = result.threatLevel === "suspicious";
                    const accentClass = isM ? "text-red-500" : isS ? "text-amber-500" : "text-emerald-500";
                    const accentBg = isM ? "bg-red-500" : isS ? "bg-amber-500" : "bg-emerald-500";
                    const accentBorder = isM ? "border-red-500/25" : isS ? "border-amber-500/25" : "border-emerald-500/25";
                    const accentBgSoft = isM ? "bg-red-500/8" : isS ? "bg-amber-500/8" : "bg-emerald-500/8";
                    const labelText = isM ? (t('malicious') || "Malicious") : isS ? (t('suspicious') || "Suspicious") : result.threatLevel === "unknown" ? "Unknown" : (t('safe') || "Safe");
                    const abuseText = abuseScore !== null ? `${abuseScore}%` : "-";
                    const abuseColor = abuseScore !== null ? (Number(abuseScore) > 50 ? "text-red-500" : Number(abuseScore) > 10 ? "text-amber-500" : "text-emerald-500") : "text-muted-foreground";
                    const vtColor = parseInt(String(vtScore).split("/")[0]) > 0 ? "text-red-500" : "text-emerald-500";
                    const timelineCount = result.vendorData.reduce((sum, v) => sum + (v.timeline?.length || 0), 0);

                    return (
                        <article
                            key={result.query}
                            className={`group relative overflow-hidden rounded-lg border ${accentBorder} bg-card transition-all hover:-translate-y-0.5 hover:border-foreground/25 hover:shadow-lg`}
                        >
                            <div className={`absolute inset-x-0 top-0 h-1 ${accentBg}`} />
                            <div className="p-5">
                                <div className="mb-5 flex items-start justify-between gap-3">
                                    <div className="min-w-0">
                                        <div className="mb-2 text-[10px] font-black uppercase tracking-wide text-muted-foreground">Target</div>
                                        <div className="flex min-w-0 items-center gap-2">
                                            <button
                                                type="button"
                                                onClick={() => onViewDetails(result.query)}
                                                className="min-w-0 truncate font-mono text-lg font-black tracking-tight text-foreground hover:text-primary"
                                            >
                                                {result.query}
                                            </button>
                                            <button
                                                onClick={(e) => { e.stopPropagation(); handleCopy(result.query); }}
                                                className="shrink-0 rounded-md p-1 text-muted-foreground hover:bg-secondary hover:text-foreground"
                                                title={pt ? "Copiar IOC" : "Copy IOC"}
                                            >
                                                {copiedIp === result.query ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                                            </button>
                                        </div>
                                        {hostname && <div className="mt-1 truncate font-mono text-xs text-muted-foreground">{hostname}</div>}
                                    </div>
                                    <span className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-black ${accentBgSoft} ${accentClass} ${accentBorder}`}>
                                        <span className={`h-1.5 w-1.5 rounded-full ${accentBg}`} />
                                        {labelText}
                                    </span>
                                </div>

                                <div className="mb-5 grid grid-cols-[92px_1fr] gap-4">
                                    <div className="grid h-24 w-24 place-items-center rounded-lg border border-border bg-background">
                                        <div className="text-center">
                                            <div className={`font-mono text-3xl font-black ${accentClass}`}>{result.overallScore}</div>
                                            <div className="text-[10px] font-bold text-muted-foreground">/100</div>
                                        </div>
                                    </div>
                                    <div className="grid gap-2">
                                        {[
                                            ["VirusTotal", vtScore, vtColor],
                                            ["AbuseIPDB", abuseText, abuseColor],
                                            ["OTX", pulseText, pulseCount && pulseCount > 0 ? "text-red-500" : "text-muted-foreground"],
                                        ].map(([label, value, color]) => (
                                            <div key={label} className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2">
                                                <span className="text-xs font-bold text-muted-foreground">{label}</span>
                                                <span className={`truncate font-mono text-xs font-black ${color}`}>{value}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                <div className="mb-5 grid gap-2 text-sm">
                                    <div className="flex items-center gap-2 text-muted-foreground">
                                        <Globe className="h-4 w-4 shrink-0" />
                                        <span className="truncate">{flag && `${flag} `}{countryName}</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-muted-foreground">
                                        <Server className="h-4 w-4 shrink-0" />
                                        <span className="truncate">{isp}</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-muted-foreground">
                                        <Activity className="h-4 w-4 shrink-0" />
                                        <span>
                                            {result.detections}/{result.totalVendors} {pt ? "bases sinalizaram" : "sources flagged"} · {timelineCount} {pt ? "eventos datados" : "dated events"}
                                        </span>
                                    </div>
                                </div>

                                <div className="flex items-center gap-2 border-t border-border pt-4">
                                    <Button className="h-9 flex-1 justify-center" onClick={() => onViewDetails(result.query)}>
                                        {pt ? "Abrir análise" : "Open analysis"}
                                        <ArrowRight className="ml-1.5 h-4 w-4" />
                                    </Button>
                                    <Button variant="outline" size="icon" className="h-9 w-9" onClick={() => copyReport(result)} title={pt ? "Copiar resumo" : "Copy summary"}>
                                        <Copy className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        </article>
                    );
                })}
            </div>
        </div>
    );
};
