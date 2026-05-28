import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import {
    Copy,
    ArrowRight,
    Globe,
    Server,
    Info,
    Shield,
    Check,
    ShieldAlert,
    FileSpreadsheet,
    Activity,
    ChevronRight,
    Radar,
    Eye,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
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

const getVendorDomain = (name: string) => {
    switch (name) {
        case "VirusTotal": return "virustotal.com";
        case "AbuseIPDB": return "abuseipdb.com";
        case "AlienVault OTX": return "alienvault.com";
        case "Shodan": return "shodan.io";
        case "Censys": return "censys.io";
        case "WHOIS": return "who.is";
        case "IP Geolocation": return "ip-api.com";
        case "URLhaus": return "abuse.ch";
        case "MalwareBazaar": return "abuse.ch";
        case "Google Safe Browsing": return "google.com";
        case "PhishTank": return "phishtank.com";
        case "Pulsedive": return "pulsedive.com";
        case "Hybrid Analysis": return "hybrid-analysis.com";
        case "CIRCL hashlookup": return "circl.lu";
        case "Criminal IP": return "criminalip.io";
        case "MetaDefender": return "opswat.com";
        case "PhishStats": return "phishstats.info";
        case "Ransomware.live": return "ransomware.live";
        case "OpenPhish": return "openphish.com";
        case "DShield": return "dshield.org";
        case "Team Cymru": return "team-cymru.com";
        default: return "google.com";
    }
};

const getVendorShortName = (name: string) => {
    switch (name) {
        case "VirusTotal": return "VT";
        case "AbuseIPDB": return "Abuse";
        case "AlienVault OTX": return "OTX";
        case "Google Safe Browsing": return "Safe Browsing";
        case "Hybrid Analysis": return "Hybrid";
        default: return name;
    }
};

const getVendorDisplayInfo = (vendorName: string, data: any) => {
    if (!data || Object.keys(data).length === 0 || data.error) return null;

    let scoreText = "";
    let isThreat = false;
    let isSafe = true;

    switch (vendorName) {
        case "VirusTotal": {
            const rate = data["Detection Rate"];
            if (rate) {
                const parts = rate.split("/");
                const detected = parseInt(parts[0]) || 0;
                scoreText = rate;
                isThreat = detected > 0;
                isSafe = detected === 0;
            }
            break;
        }
        case "AbuseIPDB": {
            const conf = data["Abuse Confidence Score"];
            if (conf !== undefined) {
                const num = Number(conf) || 0;
                scoreText = `${num}%`;
                isThreat = num > 20;
                isSafe = num <= 10;
            }
            break;
        }
        case "AlienVault OTX": {
            const pulses = data["Pulse Count"];
            if (pulses !== undefined) {
                const num = Number(pulses) || 0;
                scoreText = `${num} pulse${num !== 1 ? "s" : ""}`;
                isThreat = num > 0;
                isSafe = num === 0;
            }
            break;
        }
        case "Shodan": {
            const vulns = data["Vulnerabilities"];
            const ports = data["Total Ports"];
            if (vulns && vulns !== "0 CVEs") {
                scoreText = vulns;
                isThreat = true;
                isSafe = false;
            } else if (ports !== undefined && ports > 0) {
                scoreText = `${ports} port${ports !== 1 ? "s" : ""}`;
                isThreat = false;
                isSafe = true;
            }
            break;
        }
        case "Pulsedive": {
            const risk = data["Risk"];
            if (risk) {
                scoreText = risk.toUpperCase();
                isThreat = risk === "high" || risk === "medium";
                isSafe = risk === "low" || risk === "none";
            }
            break;
        }
        case "Criminal IP": {
            const score = data["Score"];
            if (score !== undefined) {
                const num = Number(score) || 0;
                scoreText = `${num}/100`;
                isThreat = num > 50;
                isSafe = num <= 20;
            }
            break;
        }
        case "Hybrid Analysis": {
            const score = data["Threat Score"];
            if (score !== undefined) {
                const num = Number(score) || 0;
                scoreText = `${num}/100`;
                isThreat = num > 50;
                isSafe = num <= 20;
            }
            break;
        }
        default: {
            if (data["Score"] !== undefined) {
                scoreText = String(data["Score"]);
            } else if (data["Fraud Score"] !== undefined) {
                scoreText = `${data["Fraud Score"]}%`;
                const num = Number(data["Fraud Score"]) || 0;
                isThreat = num > 50;
                isSafe = num <= 20;
            } else if (data["Status"]) {
                scoreText = String(data["Status"]);
                const statusLower = scoreText.toLowerCase();
                isThreat = statusLower.includes("malicious") || statusLower.includes("suspicious") || statusLower.includes("unsafe") || statusLower.includes("high risk");
                isSafe = statusLower.includes("safe") || statusLower.includes("clean") || statusLower.includes("low risk");
            }
            break;
        }
    }

    if (!scoreText) return null;

    let colorClass = "text-emerald-400";
    if (isThreat) {
        colorClass = "text-red-400";
    } else if (!isSafe) {
        colorClass = "text-amber-400";
    }

    return {
        scoreText,
        colorClass,
    };
};


/* ── Component ───────────────────────────────────────────────────── */
interface MultiIpSummaryProps {
    results: ThreatIntelligenceResult[];
    onViewDetails: (query: string) => void;
}

export const MultiIpSummary = ({ results, onViewDetails }: MultiIpSummaryProps) => {
    const { toast } = useToast();
    const { t } = useLanguage();
    const [copiedIp, setCopiedIp] = useState<string | null>(null);

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

    return (
        <div className="space-y-2">
            {/* Header */}
            <div className="flex items-center gap-2 px-1 mb-1">
                <span className="text-xs font-bold text-foreground/80 tracking-wide">{results.length} Target{results.length !== 1 ? "s" : ""} Scanned</span>
                <Dialog>
                    <DialogTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-4 w-4 rounded-full text-muted-foreground/40 hover:text-foreground">
                            <Info className="h-2.5 w-2.5" />
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
                                    <li><strong className="text-emerald-500">SAFE (0–30):</strong> {t('safeDesc')}</li>
                                    <li><strong className="text-amber-500">SUSPICIOUS (31–70):</strong> {t('suspiciousDesc')}</li>
                                    <li><strong className="text-red-500">MALICIOUS (71–100):</strong> {t('maliciousDesc')}</li>
                                </ul>
                            </div>
                        </div>
                    </DialogContent>
                </Dialog>
            </div>

            {/* Result rows */}
            {results.map((result) => {
                const vt = result.vendorData.find(v => v.name === "VirusTotal")?.data;
                const ab = result.vendorData.find(v => v.name === "AbuseIPDB")?.data;
                const geo = result.vendorData.find(v => v.name === "IP Geolocation")?.data;

                const vtScore = vt?.["Detection Rate"] ?? null;
                const abuseScore = ab?.["Abuse Confidence Score"] ?? null;
                const country = geo?.["Country"] || ab?.["Country"] || null;
                const isp = geo?.["ISP"] || ab?.["ISP"] || null;

                const { name: countryName, code: countryCode } = parseCountry(country ?? "");
                const flag = getFlagEmoji(countryCode);

                const isM = result.threatLevel === "malicious";
                const isS = result.threatLevel === "suspicious";
                const accentColor = isM ? "#ef4444" : isS ? "#f59e0b" : "#10b981";
                const accentClass = isM ? "text-red-400" : isS ? "text-amber-400" : "text-emerald-400";
                const accentBg = isM ? "bg-red-500" : isS ? "bg-amber-500" : "bg-emerald-500";
                const accentBorder = isM ? "border-red-500/15" : isS ? "border-amber-500/15" : "border-emerald-500/15";
                const accentBgSoft = isM ? "bg-red-500/8" : isS ? "bg-amber-500/8" : "bg-emerald-500/8";
                const labelText = isM ? (t('malicious') || "Malicious") : isS ? (t('suspicious') || "Suspicious") : (t('safe') || "Safe");

                return (
                    <div
                        key={result.query}
                        className={`group relative flex items-center gap-3 rounded-xl border ${accentBorder} bg-white/[0.02] hover:bg-white/[0.04] transition-all duration-200 cursor-pointer px-3 py-2.5`}
                        onClick={() => onViewDetails(result.query)}
                    >
                        {/* Score ring — compact */}
                        <div className="relative shrink-0">
                            <svg width="40" height="40" viewBox="0 0 40 40" className="transform -rotate-90">
                                <circle cx="20" cy="20" r="16" fill="none" stroke="currentColor" strokeWidth="2.5" className="text-white/[0.04]" />
                                <circle
                                    cx="20" cy="20" r="16" fill="none"
                                    strokeWidth="2.5"
                                    strokeLinecap="round"
                                    stroke={accentColor}
                                    strokeDasharray={`${(result.overallScore / 100) * 100.5} 100.5`}
                                    className="transition-all duration-700"
                                    style={{ filter: `drop-shadow(0 0 3px ${accentColor}50)` }}
                                />
                            </svg>
                            <div className="absolute inset-0 flex items-center justify-center">
                                <span className={`text-[11px] font-black font-mono ${accentClass}`}>
                                    {result.overallScore}
                                </span>
                            </div>
                        </div>

                        {/* Target info */}
                        <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-sm text-foreground truncate">{result.query}</span>
                                <span className={`inline-flex items-center gap-1 px-2 py-px rounded-full text-[10px] font-bold ${accentBgSoft} ${accentClass} border ${accentBorder}`}>
                                    <span className={`h-1 w-1 rounded-full ${accentBg}`} />
                                    {labelText}
                                </span>
                                <button
                                    onClick={(e) => { e.stopPropagation(); handleCopy(result.query); }}
                                    className="p-0.5 rounded text-muted-foreground/30 hover:text-foreground transition-colors"
                                    title="Copy"
                                >
                                    {copiedIp === result.query
                                        ? <Check className="h-3 w-3 text-emerald-500" />
                                        : <Copy className="h-3 w-3" />}
                                </button>
                            </div>
                            <div className="flex items-center gap-2 mt-0.5 text-[11px] text-muted-foreground/50">
                                {country && countryName !== "—" && (
                                    <span className="flex items-center gap-1">
                                        {flag && <span className="text-xs">{flag}</span>}
                                        <span>{countryName}</span>
                                    </span>
                                )}
                                {isp && (
                                    <span className="truncate max-w-[160px]">{isp}</span>
                                )}
                            </div>
                        </div>

                        {/* Inline stats */}
                        <div className="hidden sm:flex items-center gap-2 flex-wrap max-w-[45%] justify-end shrink-0">
                            {result.vendorData.map((vendor) => {
                                if (vendor.name === "IP Geolocation" || vendor.name === "WHOIS") return null;
                                if (vendor.error || !vendor.data) return null;

                                const info = getVendorDisplayInfo(vendor.name, vendor.data);
                                if (!info) return null;

                                const domain = getVendorDomain(vendor.name);
                                const shortName = getVendorShortName(vendor.name);

                                return (
                                    <div
                                        key={vendor.name}
                                        className="flex items-center gap-1.5 bg-white/[0.02] border border-white/[0.04] px-2 py-0.5 rounded-md text-[9px] hover:bg-white/[0.05] transition-colors"
                                        title={`${vendor.name}: ${info.scoreText}`}
                                    >
                                        <img
                                            src={`https://www.google.com/s2/favicons?sz=32&domain=${domain}`}
                                            alt=""
                                            className="w-3.5 h-3.5 rounded-sm object-contain shrink-0"
                                            onError={(e) => {
                                                (e.target as HTMLElement).style.display = "none";
                                            }}
                                        />
                                        <span className="text-muted-foreground/60 font-semibold">{shortName}</span>
                                        <span className={`font-mono font-bold ${info.colorClass}`}>
                                            {info.scoreText}
                                        </span>
                                    </div>
                                );
                            })}
                        </div>

                        {/* Detection count */}
                        <div className="flex items-center gap-2 shrink-0">
                            <div className="text-center min-w-[32px]">
                                <div className="flex items-baseline justify-center gap-px">
                                    <span className={`text-sm font-black font-mono ${result.detections > 0 ? "text-red-400" : "text-emerald-400"}`}>
                                        {result.detections}
                                    </span>
                                    <span className="text-muted-foreground/30 text-[9px] font-mono">/{result.totalVendors}</span>
                                </div>
                                <span className="text-[8px] uppercase tracking-widest text-muted-foreground/30 font-bold">det.</span>
                            </div>

                            <button
                                onClick={(e) => { e.stopPropagation(); copyReport(result); }}
                                className="p-1.5 rounded-lg text-muted-foreground/30 hover:text-foreground hover:bg-white/[0.04] transition-all"
                                title="Copy report"
                            >
                                <Copy className="h-3 w-3" />
                            </button>
                            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/20 group-hover:text-foreground/40 group-hover:translate-x-0.5 transition-all duration-200" />
                        </div>
                    </div>
                );
            })}
        </div>
    );
};
