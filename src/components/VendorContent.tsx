import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ThreatBadge } from "@/components/ThreatBadge";
import { VendorData } from "@/types/threat-intelligence";
import { ClickableArtifact } from "@/components/ClickableArtifact";
import { Button } from "@/components/ui/button";
import { Code, Globe, Network, ExternalLink, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { fetchAbuseIPDBCidrBlock } from "@/services/threatApi";

interface VendorContentProps {
    vendor: VendorData;
    onPivot?: (artifact: string) => void;
}

// Keys holding complex/nested structures that shouldn't be rendered in the generic card display
const GENERIC_HIDDEN_KEYS = new Set(["Services Detail", "Reports", "All Vendors", "Hostnames"]);

export const VendorContent = ({ vendor, onPivot }: VendorContentProps) => {
    const { name, data, error, quota } = vendor;
    const [showRaw, setShowRaw] = useState(false);
    const [cidrLoading, setCidrLoading] = useState(false);
    const [cidrResults, setCidrResults] = useState<any>(null);
    const [cidrError, setCidrError] = useState<string | null>(null);

    const handleCheckCidr = async (cidr: string) => {
        if (!cidr) return;
        setCidrLoading(true);
        setCidrError(null);
        try {
            const res = await fetchAbuseIPDBCidrBlock(cidr);
            setCidrResults(res);
        } catch (err: any) {
            console.error(err);
            setCidrError(err?.message || "Failed to scan CIDR block reputation");
        } finally {
            setCidrLoading(false);
        }
    };

    const renderValue = (value: string) => {
        if (!onPivot) return value;
        return <ClickableArtifact text={value} onPivot={onPivot} />;
    };

    if ((vendor as any).loading) {
        return (
            <div className="flex flex-col items-center justify-center py-8 space-y-3">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                <p className="text-sm text-muted-foreground">Loading...</p>
            </div>
        );
    }

    if (error) {
        return <div className="text-destructive text-sm">{error}</div>;
    }

    if (!data || Object.keys(data).length === 0) {
        return <div className="text-muted-foreground text-sm">No data available</div>;
    }

    if (showRaw) {
        return (
            <div className="space-y-3">
                <Button variant="outline" size="sm" onClick={() => setShowRaw(false)} className="w-full">
                    <Code className="h-4 w-4 mr-2" />Hide Raw Data
                </Button>
                <pre className="text-xs bg-muted p-3 rounded-md overflow-auto max-h-96 border">{JSON.stringify(data, null, 2)}</pre>
            </div>
        );
    }

    // VirusTotal - Professional Display
    if (name === "VirusTotal") {
        const detectionRate = data["Detection Rate"] || "0/0";
        const [detected, total] = detectionRate.split("/").map(Number);
        const percentage = total > 0 ? (detected / total) * 100 : 0;
        const status = data["Status"] || "Unknown";
        const topDetectionsStr = data["Top Detections"] || "None";
        const topDetections = topDetectionsStr === "None" ? [] : topDetectionsStr.split(", ");
        const allVendors = data["All Vendors"] as Array<{ engine: string, category: string, result: string }> || [];

        const famousVendors = ['Fortinet', 'Kaspersky', 'Microsoft', 'Symantec', 'McAfee', 'Avast', 'AVG', 'BitDefender', 'ESET-NOD32', 'F-Secure', 'Palo Alto Networks', 'Sophos', 'Trend Micro', 'CrowdStrike', 'Avira', 'Comodo', 'DrWeb', 'GData', 'Malwarebytes'];
        const prioritizedVendors = [...allVendors].sort((a, b) => {
            const aFamous = famousVendors.some(f => a.engine.toLowerCase().includes(f.toLowerCase()));
            const bFamous = famousVendors.some(f => b.engine.toLowerCase().includes(f.toLowerCase()));
            const aDetected = a.category === "malicious" || a.category === "suspicious";
            const bDetected = b.category === "malicious" || b.category === "suspicious";
            if (aFamous && aDetected && !(bFamous && bDetected)) return -1;
            if (bFamous && bDetected && !(aFamous && aDetected)) return 1;
            if (aFamous && !bFamous) return -1;
            if (bFamous && !aFamous) return 1;
            if (aDetected && !bDetected) return -1;
            if (bDetected && !aDetected) return 1;
            return 0;
        }).slice(0, 10);

        return (
            <div className="space-y-3">
                <div><p className="text-sm text-muted-foreground mb-2">Detection Rate</p><div className="flex items-center gap-3"><Progress value={percentage} className="flex-1" /><span className="font-semibold">{detectionRate}</span></div></div>
                <div><p className="text-sm text-muted-foreground mb-2">Status</p><ThreatBadge level={status === "Malicious" ? "malicious" : status === "Suspicious" ? "suspicious" : "safe"} label={status} /></div>
                <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-xs text-muted-foreground">Malicious</p><p className="text-lg font-bold text-destructive">{data["Malicious"] || 0}</p></div>
                    <div><p className="text-xs text-muted-foreground">Suspicious</p><p className="text-lg font-bold text-orange-500">{data["Suspicious"] || 0}</p></div>
                    <div><p className="text-xs text-muted-foreground">Harmless</p><p className="text-lg font-bold text-green-500">{data["Harmless"] || 0}</p></div>
                    <div><p className="text-xs text-muted-foreground">Undetected</p><p className="text-lg font-bold text-muted-foreground">{data["Undetected"] || 0}</p></div>
                </div>
                {topDetections.length > 0 && (<div><p className="text-sm text-muted-foreground mb-2">Top Detections</p><div className="flex flex-wrap gap-1">{topDetections.map((d: string) => (<Badge key={d} variant="outline" className="text-xs">{d}</Badge>))}</div></div>)}
                {prioritizedVendors.length > 0 && (<div><p className="text-sm text-muted-foreground mb-2">Top Vendors ({prioritizedVendors.length} of {allVendors.length})</p><div className="grid grid-cols-2 gap-2 text-xs">{prioritizedVendors.map((v, idx) => (<div key={idx} className="flex justify-between items-center p-2 border rounded-md"><span className="font-medium truncate pr-2">{v.engine}</span><Badge variant={v.category === "malicious" ? "destructive" : v.category === "suspicious" ? "default" : v.category === "undetected" ? "outline" : "secondary"} className="text-xs shrink-0">{v.result || v.category}</Badge></div>))}</div></div>)}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">Network</p><p className="font-mono">{data["Network"]}</p></div>
                    <div><p className="text-muted-foreground">Country</p><p className="font-semibold">{data["Country"]}</p></div>
                    <div><p className="text-muted-foreground">AS Owner</p><p className="font-medium truncate" title={data["AS Owner"]}>{data["AS Owner"]}</p></div>
                    <div><p className="text-muted-foreground">ASN</p><p className="font-mono">{data["ASN"]}</p></div>
                    <div><p className="text-muted-foreground">Reputation</p><p className={`font-semibold ${(data["Reputation"] || 0) < 0 ? "text-destructive" : "text-green-500"}`}>{data["Reputation"] || 0}</p></div>
                    <div><p className="text-muted-foreground">Last Analysis</p><p className="text-xs">{data["Last Analysis"]}</p></div>
                </div>
                {data["Tags"] !== "None" && (<div><p className="text-sm text-muted-foreground mb-1">Tags</p><p className="text-xs text-muted-foreground">{data["Tags"]}</p></div>)}
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // AbuseIPDB - Professional Display
    if (name === "AbuseIPDB") {
        const score = parseInt(data["Abuse Confidence Score"] || "0");
        const reports = data["Reports"] as Array<{ date: string, comment: string, categories: number[], reporterId: string, reporterCountry: string }> || [];
        const categoryMap: Record<number, string> = { 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted" };

        return (
            <div className="space-y-3">
                <div><p className="text-sm text-muted-foreground mb-2">Abuse Confidence Score</p><div className="flex items-center gap-3"><Progress value={score} className="flex-1" /><span className={`font-semibold ${score > 50 ? "text-destructive" : "text-green-500"}`}>{score}%</span></div></div>
                <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-xs text-muted-foreground">Total Reports</p><p className="text-2xl font-bold">{data["Total Reports"] || 0}</p></div>
                    <div><p className="text-xs text-muted-foreground">Distinct Reporters</p><p className="text-2xl font-bold">{data["Distinct Reporters"] || 0}</p></div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">Country</p><p className="font-semibold">{data["Country"]}</p></div>
                    <div><p className="text-muted-foreground">Usage Type</p><p className="font-medium">{data["Usage Type"]}</p></div>
                    <div className="col-span-2"><p className="text-muted-foreground">ISP</p><p className="font-medium truncate" title={data["ISP"]}>{data["ISP"]}</p></div>
                    <div className="col-span-2"><p className="text-muted-foreground">Domain</p><p className="font-medium">{renderValue(data["Domain"])}</p></div>
                    {data["ASN"] && (
                        <div>
                            <p className="text-muted-foreground">ASN</p>
                            <a
                                href={`https://bgp.he.net/AS${data["ASN"]}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-primary hover:underline font-mono inline-flex items-center gap-1 font-semibold"
                            >
                                AS{data["ASN"]}
                                <ExternalLink className="h-3 w-3" />
                            </a>
                        </div>
                    )}
                    {data["CIDR/Network"] && (
                        <div>
                            <p className="text-muted-foreground">CIDR/Network</p>
                            <span className="font-mono font-semibold">{data["CIDR/Network"]}</span>
                        </div>
                    )}
                </div>
                {data["Hostnames"] !== "None" && (<div><p className="text-sm text-muted-foreground mb-1">Hostnames</p><p className="text-xs text-muted-foreground">{data["Hostnames"]}</p></div>)}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">Is Public</p><Badge variant={data["Is Public"] === "Yes" ? "default" : "secondary"} className="text-xs">{data["Is Public"]}</Badge></div>
                    <div><p className="text-muted-foreground">Is Whitelisted</p><Badge variant={data["Is Whitelisted"] === "Yes" ? "default" : "secondary"} className="text-xs">{data["Is Whitelisted"]}</Badge></div>
                </div>
                <div><p className="text-sm text-muted-foreground mb-1">Last Report</p><p className="font-mono text-xs">{data["Last Report"]}</p></div>

                {data["CIDR/Network"] && (
                    <div className="pt-3 border-t space-y-2">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-muted-foreground uppercase flex items-center gap-1.5">
                                <Network className="h-3.5 w-3.5 text-primary" />
                                Subnet Reputation
                            </span>
                            {!cidrResults && (
                                <Button
                                    variant="outline"
                                    size="xs"
                                    onClick={() => handleCheckCidr(data["CIDR/Network"])}
                                    disabled={cidrLoading}
                                    className="h-7 text-[10px] px-2 rounded hover:bg-primary hover:text-primary-foreground transition-all"
                                >
                                    {cidrLoading ? "Scanning Subnet..." : "Scan CIDR Block"}
                                </Button>
                            )}
                        </div>

                        {cidrError && (
                            <p className="text-xs text-destructive bg-destructive/5 p-2 rounded-md border border-destructive/20">
                                {cidrError}
                            </p>
                        )}

                        {cidrResults && (
                            <div className="space-y-2.5 bg-muted/40 border border-border/50 rounded-xl p-3 text-xs">
                                <div className="flex justify-between items-center text-[10px] text-muted-foreground uppercase font-medium">
                                    <span>Subnet: {cidrResults.cidr}</span>
                                    <span>Type: {cidrResults.addressSpaceDesc || "Public"}</span>
                                </div>
                                <div className="flex justify-between items-center bg-background/50 p-2 rounded-lg border border-border/30">
                                    <span>Reported Hosts:</span>
                                    <Badge variant={cidrResults.reportedAddress?.length > 0 ? "destructive" : "secondary"} className="font-mono">
                                        {cidrResults.reportedAddress?.length || 0} / {cidrResults.numPossibleHosts || 0}
                                    </Badge>
                                </div>
                                {cidrResults.reportedAddress && cidrResults.reportedAddress.length > 0 ? (
                                    <div className="space-y-1.5 max-h-[160px] overflow-y-auto pr-1">
                                        <p className="text-[10px] text-muted-foreground uppercase font-semibold">Reported IPs In Subnet</p>
                                        {cidrResults.reportedAddress.map((rep: any, idx: number) => (
                                            <div key={idx} className="flex justify-between items-center p-1.5 border border-border/40 rounded bg-background/30 hover:bg-background/60 transition-colors">
                                                <span className="font-mono font-medium">{rep.ipAddress}</span>
                                                <div className="flex items-center gap-1.5">
                                                    <span className="text-[10px] text-muted-foreground">({rep.numReports} rep)</span>
                                                    <Badge variant={rep.abuseConfidenceScore > 50 ? "destructive" : "default"} className="text-[10px] px-1 py-0 scale-90">
                                                        {rep.abuseConfidenceScore}%
                                                    </Badge>
                                                    {onPivot && (
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            className="h-5 w-5 hover:bg-primary/10 rounded"
                                                            onClick={() => onPivot(rep.ipAddress)}
                                                            title={`Pivot search to ${rep.ipAddress}`}
                                                        >
                                                            <Globe className="h-3 w-3 text-primary" />
                                                        </Button>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <div className="flex items-center gap-2 text-green-500 py-1 font-medium justify-center bg-green-500/5 rounded-lg border border-green-500/20">
                                        <ShieldCheck className="h-4 w-4" />
                                        <span>No reported abuse in this subnet block!</span>
                                    </div>
                                )}
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => setCidrResults(null)}
                                    className="w-full text-[10px] h-6 text-muted-foreground hover:text-foreground"
                                >
                                    Clear Results
                                </Button>
                            </div>
                        )}
                    </div>
                )}
                {reports.length > 0 && (
                    <div className="pt-3 border-t">
                        <p className="text-sm font-medium mb-2">Recent Reports ({reports.length})</p>
                        <div className="space-y-2">
                            {reports.map((report, idx) => (
                                <div key={idx} className="border rounded-md p-2 text-xs">
                                    <div className="flex justify-between items-start gap-2 mb-1">
                                        <div className="text-muted-foreground">{new Date(report.date).toLocaleString()}</div>
                                        <Badge variant="secondary" className="text-xs">{report.reporterCountry}</Badge>
                                    </div>
                                    <div className="flex flex-wrap gap-1 mb-1">{report.categories.map(cat => (<Badge key={cat} variant="destructive" className="text-xs">{categoryMap[cat] || `Cat ${cat}`}</Badge>))}</div>
                                    <p className="italic text-muted-foreground">"{report.comment}"</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // AlienVault OTX - Enhanced Display
    if (name === "AlienVault OTX") {
        const pulseCount = parseInt(data["Pulse Count"] || "0");
        const status = data["Status"] || "Clean";
        const pulsesStr = data["Pulses"] || "No recent activity";
        const pulses = pulsesStr === "No recent activity" ? [] : pulsesStr.split(", ");

        return (
            <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-xs text-muted-foreground">Pulse Count</p><p className="text-2xl font-bold">{pulseCount}</p></div>
                    <div><p className="text-xs text-muted-foreground">Status</p><ThreatBadge level={pulseCount > 0 ? "suspicious" : "safe"} label={status} /></div>
                </div>
                {pulses.length > 0 && (<div><p className="text-sm text-muted-foreground mb-2">Recent Pulses</p><div className="flex flex-wrap gap-1">{pulses.map((p: string, idx: number) => (<Badge key={idx} variant="destructive" className="text-xs">{p}</Badge>))}</div></div>)}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">Country</p><p className="font-semibold">{data["Country"]}</p></div>
                    <div><p className="text-muted-foreground">City</p><p className="font-medium">{data["City"]}</p></div>
                    <div><p className="text-muted-foreground">Reputation</p><p className={`font-semibold ${(data["Reputation"] || 0) < 0 ? "text-destructive" : "text-green-500"}`}>{data["Reputation"]}</p></div>
                    <div><p className="text-muted-foreground">ASN</p><p className="font-mono">{data["ASN"]}</p></div>
                </div>
                {data["Sections"] && (<div><p className="text-sm text-muted-foreground mb-1">Available Data</p><p className="text-xs text-muted-foreground">{data["Sections"]}</p></div>)}
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // Shodan - Enhanced Display
    if (name === "Shodan") {
        const portsStr = data["Open Ports"] || "None";
        const ports = portsStr === "None" ? [] : portsStr.split(", ");
        const vulnsCount = parseInt((data["Vulnerabilities"] as string || "0").replace(/[^\d]/g, ""));

        return (
            <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-xs text-muted-foreground">Total Ports</p><p className="text-2xl font-bold">{data["Total Ports"] || 0}</p></div>
                    <div><p className="text-xs text-muted-foreground">Vulnerabilities</p><p className="text-2xl font-bold text-destructive">{vulnsCount}</p></div>
                </div>
                {ports.length > 0 && (<div><p className="text-sm text-muted-foreground mb-2">Open Ports</p><div className="flex flex-wrap gap-1">{ports.map((p: string, idx: number) => (<Badge key={idx} variant="secondary" className="text-xs">{p}</Badge>))}</div></div>)}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">Organization</p><p className="font-medium">{data["Organization"]}</p></div>
                    <div><p className="text-muted-foreground">OS</p><p className="font-medium">{data["OS"]}</p></div>
                    <div><p className="text-muted-foreground">ISP</p><p className="font-medium truncate" title={data["ISP"]}>{data["ISP"]}</p></div>
                    <div><p className="text-muted-foreground">ASN</p><p className="font-mono">{data["ASN"]}</p></div>
                </div>
                {data["Services"] && data["Services"] !== "Unknown" && (<div><p className="text-sm text-muted-foreground mb-1">Services</p><p className="text-xs text-muted-foreground">{data["Services"]}</p></div>)}
                {data["Hostnames"] && data["Hostnames"] !== "None" && (<div><p className="text-sm text-muted-foreground mb-1">Hostnames</p><p className="text-xs text-muted-foreground">{data["Hostnames"]}</p></div>)}
                {data["Tags"] && data["Tags"] !== "None" && (<div><p className="text-sm text-muted-foreground mb-1">Tags</p><p className="text-xs text-muted-foreground">{data["Tags"]}</p></div>)}
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // Pulsedive - Enhanced Display
    if (name === "Pulsedive") {
        const risk = data["Risk"] || "Unknown";
        const riskNum = risk === "Unknown" ? 0 : risk === "high" ? 100 : risk === "medium" ? 50 : risk === "low" ? 25 : 0;
        const threatsStr = data["Threats"] || "None";
        const threats = threatsStr === "None" ? [] : threatsStr.split(", ");

        return (
            <div className="space-y-3">
                <div><p className="text-sm text-muted-foreground mb-2">Risk Level</p><div className="flex items-center gap-3"><Progress value={riskNum} className="flex-1" /><ThreatBadge level={risk === "high" ? "malicious" : risk === "medium" ? "suspicious" : "safe"} label={risk.toUpperCase()} /></div></div>
                {threats.length > 0 && (<div><p className="text-sm text-muted-foreground mb-2">Threats Detected</p><div className="flex flex-wrap gap-1">{threats.map((t: string, idx: number) => (<Badge key={idx} variant="destructive" className="text-xs">{t}</Badge>))}</div></div>)}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">Type</p><p className="font-medium">{data["Type"]}</p></div>
                    <div><p className="text-muted-foreground">Protocol</p><p className="font-medium">{data["Protocol"]}</p></div>
                    <div><p className="text-muted-foreground">Port</p><p className="font-mono">{data["Port"]}</p></div>
                    <div><p className="text-muted-foreground">Found</p><p className="text-xs">{data["Found"]}</p></div>
                </div>
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // Criminal IP - Enhanced Display
    if (name === "Criminal IP") {
        const score = parseInt(data["Score"] || "0");
        const issues = data["Issues"] || 0;

        return (
            <div className="space-y-3">
                <div><p className="text-sm text-muted-foreground mb-2">Threat Score</p><div className="flex items-center gap-3"><Progress value={score} className="flex-1" /><span className={`font-semibold ${score > 50 ? "text-destructive" : "text-green-500"}`}>{score}/100</span></div></div>
                <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-xs text-muted-foreground">Issues Found</p><p className="text-2xl font-bold text-destructive">{issues}</p></div>
                    <div><p className="text-xs text-muted-foreground">Classification</p><p className="text-lg font-semibold">{data["Classification"]}</p></div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div><p className="text-muted-foreground">VPN</p><Badge variant={data["VPN"] === "Yes" ? "default" : "secondary"} className="text-xs">{data["VPN"]}</Badge></div>
                    <div><p className="text-muted-foreground">Proxy</p><Badge variant={data["Proxy"] === "Yes" ? "default" : "secondary"} className="text-xs">{data["Proxy"]}</Badge></div>
                    <div><p className="text-muted-foreground">Tor</p><Badge variant={data["Tor"] === "Yes" ? "destructive" : "secondary"} className="text-xs">{data["Tor"]}</Badge></div>
                    <div><p className="text-muted-foreground">Cloud</p><Badge variant={data["Cloud"] === "Yes" ? "default" : "secondary"} className="text-xs">{data["Cloud"]}</Badge></div>
                </div>
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // Censys - Enhanced Display
    if (name === "Censys") {
        if (data["Status"]) {
            return (<div className="space-y-3"><p className="text-sm text-muted-foreground">{renderValue(String(data["Status"]))}</p></div>);
        }
        const portsStr = (data["Open Ports"] as string) || "None";
        const ports = portsStr === "None" ? [] : portsStr.split(", ");
        const servicesDetail = Array.isArray(data["Services Detail"]) ? (data["Services Detail"] as any[]) : [];
        const detailRow = (label: string, key: string) =>
            data[key] ? (<div><p className="text-muted-foreground">{label}</p><p className="font-medium break-all">{renderValue(String(data[key]))}</p></div>) : null;

        return (
            <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-xs text-muted-foreground">Services</p><p className="text-2xl font-bold">{data["Service Count"] || 0}</p></div>
                    <div><p className="text-xs text-muted-foreground">Open Ports</p><p className="text-2xl font-bold">{ports.length}</p></div>
                </div>
                {ports.length > 0 && (<div><p className="text-sm text-muted-foreground mb-2">Ports</p><div className="flex flex-wrap gap-1">{ports.map((p, idx) => (<Badge key={idx} variant="secondary" className="text-xs">{p}</Badge>))}</div></div>)}
                {servicesDetail.length > 0 && (
                    <div>
                        <p className="text-sm text-muted-foreground mb-2">Service Detail</p>
                        <div className="space-y-2">
                            {servicesDetail.slice(0, 8).map((s, idx) => (
                                <div key={idx} className="rounded-md border p-2 text-xs space-y-1">
                                    <div className="flex items-center gap-2">
                                        <Badge variant="outline" className="font-mono">{s.port}{s.transport ? `/${s.transport}` : ""}</Badge>
                                        {s.protocol && <span className="text-muted-foreground">{s.protocol}</span>}
                                        {s.tls && <Badge variant="secondary" className="text-[10px]">TLS {s.tls}</Badge>}
                                    </div>
                                    {s.software && <p className="text-muted-foreground">Software: <span className="font-medium text-foreground">{s.software}</span></p>}
                                    {s.http_title && <p className="text-muted-foreground truncate" title={s.http_title}>Title: <span className="font-medium text-foreground">{s.http_title}</span></p>}
                                    {s.cert_subject && <p className="text-muted-foreground break-all">Cert: <span className="font-medium text-foreground">{s.cert_subject}</span></p>}
                                </div>
                            ))}
                        </div>
                    </div>
                )}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    {detailRow("Software", "Software")}
                    {detailRow("HTTP Status", "HTTP Status")}
                    {detailRow("HTML Title", "HTML Title")}
                    {detailRow("TLS Version", "TLS Version")}
                    {detailRow("Certificate Subject", "Certificate Subject")}
                    {detailRow("Certificate Issuer", "Certificate Issuer")}
                    {detailRow("Certificate Names", "Certificate Names")}
                    {detailRow("Browser Trust", "Browser Trust")}
                    {detailRow("ASN", "ASN")}
                    {detailRow("BGP Prefix", "BGP Prefix")}
                    {detailRow("Location", "Location")}
                </div>
                <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
            </div>
        );
    }

    // Generic Enhanced Display for Others
    return (
        <div className="space-y-3">
            {Object.entries(data).filter(([key]) => !GENERIC_HIDDEN_KEYS.has(key)).slice(0, 8).map(([key, value]) => {
                if (key === "Status" && typeof value === "string") {
                    return (<div key={key}><p className="text-sm text-muted-foreground mb-2">{key}</p><ThreatBadge level={value.toLowerCase().includes("malicious") || value.toLowerCase().includes("suspicious") ? "malicious" : "safe"} label={value} /></div>);
                }
                return (
                    <div key={key}>
                        <p className="text-xs text-muted-foreground">{key}</p>
                        {Array.isArray(value) ? (
                            <div className="flex flex-wrap gap-1 mt-1">{value.slice(0, 5).map((v, idx: number) => {
                                const text = typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
                                return (<Badge key={idx} variant="secondary" className="text-xs">{onPivot ? <ClickableArtifact text={text} onPivot={onPivot} /> : text}</Badge>);
                            })}</div>
                        ) : (
                            <p className="text-sm font-medium">{renderValue(typeof value === "object" && value !== null ? JSON.stringify(value) : String(value))}</p>
                        )}
                    </div>
                );
            })}
            {quota && (
                <div className="pt-3 border-t text-xs text-muted-foreground">
                    <p className="font-semibold mb-1">API Quota:</p>
                    <div className="flex gap-4">
                        {quota.remaining !== undefined && <span>Remaining: {quota.remaining}</span>}
                        {quota.daily_remaining !== undefined && <span>Daily: {quota.daily_remaining}</span>}
                    </div>
                </div>
            )}
            <div className="pt-3 border-t"><Button variant="outline" size="sm" onClick={() => setShowRaw(true)} className="w-full"><Code className="h-4 w-4 mr-2" />Show Raw Data</Button></div>
        </div>
    );
};
