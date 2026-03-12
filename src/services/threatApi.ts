/// <reference types="vite/client" />
import { ThreatIntelligenceResult, VendorData } from "@/types/threat-intelligence";

// Helper to handle response
const handleResponse = async (response: Response, vendorName: string) => {
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${vendorName} API error: ${response.status} ${response.statusText} - ${errorText}`);
    }
    return response.json();
};

// Detect IOC type from query
const detectIOCType = (query: string): 'ip' | 'domain' | 'hash' | 'url' => {
    if (query.startsWith('http://') || query.startsWith('https://')) return 'url';
    if (/^[a-fA-F0-9]{32}$/.test(query)) return 'hash'; // MD5
    if (/^[a-fA-F0-9]{40}$/.test(query)) return 'hash'; // SHA1
    if (/^[a-fA-F0-9]{64}$/.test(query)) return 'hash'; // SHA256
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query)) return 'ip';
    return 'domain';
};

// Map vendors to IOC types they support
export const VENDOR_IOC_SUPPORT: Record<string, ('ip' | 'domain' | 'hash' | 'url')[]> = {
    "IP Geolocation": ['ip'],
    "WHOIS": ['domain'],
    "VirusTotal": ['ip', 'domain', 'hash', 'url'],
    "AbuseIPDB": ['ip'],
    "AlienVault OTX": ['ip', 'domain', 'hash'],
    "Shodan": ['ip'],
    "URLhaus": ['url', 'domain'],

};

// Formatting logic moved from individual fetch functions
const formatVendorData = (vendorName: string, data: any, query: string): any => {
    if (data.error) throw new Error(data.error);
    if (data.data?.Status && (data.data.Status.includes("only") || data.data.Status === "No data")) return data.data;

    switch (vendorName) {
        case "VirusTotal":
            // VirusTotal response is wrapped in data property, and backend wraps it in data property
            // So we need data.data.data
            const vtData = data.data?.data ? data.data.data : data.data;
            if (!vtData?.attributes?.last_analysis_stats) return { "Status": "No data available" };
            const vtAttrs = vtData.attributes;

            // Extract ALL detection vendors (not just malicious)
            const allDetections = vtAttrs.last_analysis_results || {};
            const detectionVendors = Object.keys(allDetections).map(engine => ({
                engine,
                category: allDetections[engine].category,
                result: allDetections[engine].result
            }));

            return {
                "Detection Rate": `${vtAttrs.last_analysis_stats.malicious || 0}/${Object.keys(vtAttrs.last_analysis_results || {}).length}`,
                "Status": vtAttrs.last_analysis_stats.malicious > 0 ? "Malicious" : "Clean",
                "Malicious": vtAttrs.last_analysis_stats.malicious || 0,
                "Suspicious": vtAttrs.last_analysis_stats.suspicious || 0,
                "Undetected": vtAttrs.last_analysis_stats.undetected || 0,
                "Harmless": vtAttrs.last_analysis_stats.harmless || 0,
                "Top Detections": Object.values(vtAttrs.last_analysis_results || {})
                    .filter((r: any) => r.category === "malicious")
                    .map((r: any) => r.engine_name)
                    .slice(0, 5).join(", ") || "None",
                "All Vendors": detectionVendors,  // All vendor results for detailed view
                "Reputation": vtAttrs.reputation || 0,
                "Network": vtAttrs.network || "Unknown",
                "AS Owner": vtAttrs.as_owner || "Unknown",
                "ASN": vtAttrs.asn || "Unknown",
                "Country": vtAttrs.country || "Unknown",
                "Last Analysis": vtAttrs.last_analysis_date ? new Date(vtAttrs.last_analysis_date * 1000).toLocaleString() : "Unknown",
                "Tags": vtAttrs.tags?.slice(0, 5).join(", ") || "None",
            };
        case "AbuseIPDB":
            // AbuseIPDB response is wrapped in data property, and backend wraps it in data property
            const abuseData = data.data?.data ? data.data.data : data.data;
            if (!abuseData) return { "Status": "No data available" };

            // Extract reports if available
            const reports = abuseData.reports?.slice(0, 5).map((r: any) => ({
                date: r.reportedAt,
                comment: r.comment || "No comment",
                categories: r.categories || [],
                reporterId: r.reporterId || "Unknown",
                reporterCountry: r.reporterCountryCode || "Unknown"
            })) || [];

            return {
                "Abuse Confidence Score": `${abuseData.abuseConfidenceScore || 0}%`,
                "Total Reports": abuseData.totalReports || 0,
                "Distinct Reporters": abuseData.numDistinctUsers || 0,
                "Last Report": abuseData.lastReportedAt || "Never",
                "Country": abuseData.countryCode || "Unknown",
                "Usage Type": abuseData.usageType || "Unknown",
                "ISP": abuseData.isp || "Unknown",
                "ASN": abuseData.asn || "Unknown",
                "CIDR": abuseData.cidr || abuseData.network || "Unknown",
                "Domain": abuseData.domain || "Unknown",
                "Hostnames": abuseData.hostnames?.slice(0, 3).join(", ") || "None",
                "Is Public": abuseData.isPublic ? "Yes" : "No",
                "Is Whitelisted": abuseData.isWhitelisted ? "Yes" : "No",
                "Reports": reports,  // Last 5 reports with details
            };
        case "AlienVault OTX":
            // OTX response is wrapped by backend in data property
            const otxData = data.data || data;
            if (!otxData.pulse_info) return { "Status": "No data available" };
            return {
                "Pulse Count": `${otxData.pulse_info.count || 0} pulses`,
                "Status": (otxData.pulse_info.count || 0) > 0 ? "Suspicious Activity" : "Clean",
                "Pulses": otxData.pulse_info.pulses?.slice(0, 3).map((p: any) => p.name).join(", ") || "No recent activity",
                "Reputation": otxData.reputation || 0,
                "Country": otxData.country_name || "Unknown",
                "City": otxData.city || "Unknown",
                "ASN": otxData.asn || "Unknown",
                "Sections": otxData.sections?.join(", ") || "None",
            };
        case "Shodan":
            return {
                "Open Ports": data.ports?.slice(0, 5).join(", ") || "None",
                "Services": Array.isArray(data.data) ? data.data.slice(0, 3).map((d: any) => d.product || d.port).join(", ") : "Unknown",
                "Vulnerabilities": data.vulns ? `${Object.keys(data.vulns).length} CVEs` : "0 CVEs",
            };
        case "URLhaus":
            if (data.query_status === "ok") {
                return {
                    "Status": data.urls?.length > 0 ? "Malicious URLs Found" : "Clean",
                    "URL Count": data.urls?.length || 0,
                    "Tags": data.urls?.[0]?.tags || [],
                };
            }
            return { "Status": "No data" };

        case "MalwareBazaar":
            if (data.query_status === "ok") {
                return {
                    "Status": "Sample Found",
                    "File Type": data.data?.[0]?.file_type || "Unknown",
                    "Signature": data.data?.[0]?.signature || "Unknown",
                };
            }
            return { "Status": "No samples found" };
        case "Google Safe Browsing":
            if (data.matches && data.matches.length > 0) {
                return {
                    "Status": "Unsafe",
                    "Threat Type": data.matches[0].threatType,
                };
            }
            return { "Status": "Safe" };
        case "PhishTank":
            return {
                "Status": data.results?.in_database ? (data.results.valid ? "Verified Phishing" : "Not Phishing") : "Unknown",
                "Verified": data.results?.verified ? "Yes" : "No",
            };
        case "Pulsedive":
            return {
                "Risk": data.risk || "Unknown",
                "Threats": Array.isArray(data.threats) ? data.threats.slice(0, 3).map((t: any) => typeof t === 'string' ? t : t.name || t.type || 'Unknown').join(", ") : "None",
                "Feeds": data.feeds?.length || 0,
            };



        case "Hybrid Analysis":
            if (Array.isArray(data) && data.length > 0) {
                return {
                    "Verdict": data[0].verdict || "Unknown",
                    "Threat Score": `${data[0].threat_score}/100`,
                    "AV Detect": `${data[0].av_detect}%`,
                };
            }
            return { "Status": "No analysis found" };
        case "CIRCL hashlookup":
            return {
                "Status": "Found in database",
                "File Name": data.FileName || "Unknown",
                "File Size": data.FileSize || "Unknown",
            };
        case "Criminal IP":
            return {
                "Score": typeof data.score === 'object' ? (data.score?.inbound || data.score?.value || JSON.stringify(data.score)) : (data.score || "Unknown"),
                "Issues": data.issues?.length || 0,
                "Status": data.is_malicious ? "Malicious" : "Clean",
            };
        case "MetaDefender":
            if (data.scan_results) {
                return {
                    "Detection Rate": `${data.scan_results?.total_detected_avs}/${data.scan_results?.total_avs}`,
                    "Status": data.scan_results?.total_detected_avs > 0 ? "Malicious" : "Clean",
                };
            }
            return {
                "Geo Location": data.geo_info?.country?.name || "Unknown",
                "Detected AVs": data.lookup_results?.detected_by || 0,
            };
        case "PhishStats":
            if (Array.isArray(data) && data.length > 0) {
                return {
                    "Status": "Found in Phishing Database",
                    "Records Found": data.length,
                    "Latest Score": data[0].score || "Unknown",
                    "Country": data[0].countrycode || "Unknown",
                };
            }
            return { "Status": "Not found in phishing database" };
        case "Ransomware.live":
            const matches = data.filter((victim: any) =>
                victim.post_url?.includes(query) || victim.website?.includes(query)
            );
            if (matches.length > 0) {
                return {
                    "Status": "Found in Ransomware Victims",
                    "Matches": matches.length,
                    "Group": matches[0].group_name || "Unknown",
                    "Discovered": matches[0].discovered || "Unknown",
                };
            }
            return { "Status": "Not found in ransomware database" };
        case "WHOIS":
            if (data.WhoisRecord) {
                const record = data.WhoisRecord;
                return {
                    "Registrar": record.registrarName || "Unknown",
                    "Created": record.createdDate || "Unknown",
                    "Expires": record.expiresDate || "Unknown",
                    "Status": record.status?.[0] || "Unknown",
                };
            }
            return { "Status": "No WHOIS data available" };

        case "Shodan":
            return {
                "Open Ports": data.ports?.slice(0, 5).join(", ") || "None",
                "Total Ports": data.ports?.length || 0,
                "Services": Array.isArray(data.data) ? data.data.slice(0, 3).map((d: any) => d.product || d.port).join(", ") : "Unknown",
                "Organization": data.org || "Unknown",
                "Hostnames": data.hostnames?.slice(0, 3).join(", ") || "None",
                "Domains": data.domains?.slice(0, 3).join(", ") || "None",
                "OS": data.os || "Unknown",
                "Last Update": data.last_update || "Unknown",
                "ASN": data.asn || "Unknown",
                "ISP": data.isp || "Unknown",
                "Vulnerabilities": data.vulns ? `${Object.keys(data.vulns).length} CVEs` : "0 CVEs",
                "Tags": data.tags?.slice(0, 5).join(", ") || "None"
            };
        case "IP Geolocation":
            if (data.status === "success") {
                return {
                    "Country": `${data.country} (${data.countryCode})`,
                    "Region": data.regionName || "Unknown",
                    "City": data.city || "Unknown",
                    "ZIP Code": data.zip || "N/A",
                    "Timezone": data.timezone || "Unknown",
                    "ISP": data.isp || "Unknown",
                    "Organization": data.org || "Unknown",
                    "AS": data.as || "Unknown",
                    "Proxy/VPN": data.proxy ? "Yes ⚠️" : "No",
                    "Hosting": data.hosting ? "Yes" : "No",
                    "Mobile": data.mobile ? "Yes" : "No",
                };
            }
            return { "Status": data.message || "No geolocation data available" };
        default:
            return data;
    }
};


// Helper to get vendor analysis link
const getVendorLink = (vendorName: string, query: string): string | undefined => {
    const encodedQuery = encodeURIComponent(query);
    switch (vendorName) {
        case "VirusTotal":
            if (query.includes(".")) return `https://www.virustotal.com/gui/search/${encodedQuery}`;
            return `https://www.virustotal.com/gui/file/${query}`;
        case "AbuseIPDB": return `https://www.abuseipdb.com/check/${query}`;
        case "AlienVault OTX": return `https://otx.alienvault.com/indicator/ip/${query}`;
        case "Shodan": return `https://www.shodan.io/host/${query}`;
        case "URLhaus": return `https://urlhaus.abuse.ch/browse/search/${encodedQuery}/`;
        case "ThreatFox": return `https://threatfox.abuse.ch/browse/`;
        case "MalwareBazaar": return `https://bazaar.abuse.ch/browse/`;
        case "Google Safe Browsing": return `https://transparencyreport.google.com/safe-browsing/search?url=${encodedQuery}`;
        case "PhishTank": return `https://phishtank.org/`;
        case "Pulsedive": return `https://pulsedive.com/indicator/?ioc=${encodedQuery}`;

        case "Hybrid Analysis": return `https://www.hybrid-analysis.com/search?query=${encodedQuery}`;
        case "CIRCL hashlookup": return `https://hashlookup.circl.lu/`;
        case "Criminal IP": return `https://www.criminalip.io/asset/report/${query}`;
        case "MetaDefender": return `https://metadefender.opswat.com/results/ip/${query}`;
        case "PhishStats": return `https://phishstats.info/`;
        case "Ransomware.live": return `https://ransomware.live/`;

        case "OpenPhish": return `https://openphish.com/`;
        case "DShield": return `https://isc.sans.edu/ipinfo.html?ip=${query}`;
        case "Team Cymru": return `https://team-cymru.com/community-services/ip-asn-mapping/`;
        case "WHOIS": return `https://who.is/whois/${query}`;
        case "IP Geolocation": return `https://ip-api.com/#${query}`;
        default: return undefined;
    }
};

// Generic fetcher for backend API
const fetchFromBackend = async (endpoint: string, query: string, vendorName: string): Promise<VendorData> => {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await handleResponse(response, vendorName);

        return {
            name: vendorName,
            data: formatVendorData(vendorName, data, query),
            link: getVendorLink(vendorName, query)
        };
    } catch (error) {
        return { name: vendorName, data: {}, error: (error as Error).message };
    }
};

// Exported fetch functions
export const fetchIPGeoData = (query: string) => fetchFromBackend('ipgeo', query, "IP Geolocation");
export const fetchWHOISData = (query: string) => fetchFromBackend('whois', query, "WHOIS");
export const fetchVirusTotalData = (query: string) => fetchFromBackend('virustotal', query, "VirusTotal");
export const fetchAbuseIPDBData = (query: string) => fetchFromBackend('abuseipdb', query, "AbuseIPDB");
export const fetchAlienVaultData = (query: string) => fetchFromBackend('alienvault', query, "AlienVault OTX");
export const fetchShodanData = (query: string) => fetchFromBackend('shodan', query, "Shodan");
export const fetchURLhausData = (query: string) => fetchFromBackend('urlhaus', query, "URLhaus");

export const fetchMalwareBazaarData = (query: string) => fetchFromBackend('malwarebazaar', query, "MalwareBazaar");
export const fetchGoogleSafeBrowsingData = (query: string) => fetchFromBackend('googlesafebrowsing', query, "Google Safe Browsing");
export const fetchPhishTankData = (query: string) => fetchFromBackend('phishtank', query, "PhishTank");
export const fetchPulsediveData = (query: string) => fetchFromBackend('pulsedive', query, "Pulsedive");

export const fetchHybridAnalysisData = (query: string) => fetchFromBackend('hybridanalysis', query, "Hybrid Analysis");
export const fetchCIRCLData = (query: string) => fetchFromBackend('circl', query, "CIRCL hashlookup");
export const fetchCriminalIPData = (query: string) => fetchFromBackend('criminalip', query, "Criminal IP");
export const fetchMetaDefenderData = (query: string) => fetchFromBackend('metadefender', query, "MetaDefender");
export const fetchPhishStatsData = (query: string) => fetchFromBackend('phishstats', query, "PhishStats");
export const fetchRansomwareLiveData = (query: string) => fetchFromBackend('ransomwarelive', query, "Ransomware.live");
export const fetchOpenPhishData = (query: string) => fetchFromBackend('openphish', query, "OpenPhish");
export const fetchDShieldData = (query: string) => fetchFromBackend('dshield', query, "DShield");
export const fetchTeamCymruData = (query: string) => fetchFromBackend('teamcymru', query, "Team Cymru");

export const checkDNSBL = async (ip: string, provider: string): Promise<{ listed: boolean; addresses?: string[]; status: string; error?: string }> => {
    try {
        const response = await fetch('/api/dnsbl', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: ip, provider })
        });
        if (!response.ok) throw new Error("API Error");
        return await response.json();
    } catch (error) {
        return { listed: false, status: "Error", error: (error as Error).message };
    }
};

export const fetchThreatData = async (query: string, selectedVendors?: string[]): Promise<ThreatIntelligenceResult> => {
    // Map vendor names to their fetch functions
    const vendorMap: Record<string, () => Promise<VendorData>> = {
        "IP Geolocation": () => fetchIPGeoData(query),
        "WHOIS": () => fetchWHOISData(query),
        "VirusTotal": () => fetchVirusTotalData(query),
        "AbuseIPDB": () => fetchAbuseIPDBData(query),
        "AlienVault OTX": () => fetchAlienVaultData(query),
        "Shodan": () => fetchShodanData(query),
        "URLhaus": () => fetchURLhausData(query),
        "MalwareBazaar": () => fetchMalwareBazaarData(query),
        "Google Safe Browsing": () => fetchGoogleSafeBrowsingData(query),
        "PhishTank": () => fetchPhishTankData(query),
        "Pulsedive": () => fetchPulsediveData(query),

        "Hybrid Analysis": () => fetchHybridAnalysisData(query),
        "CIRCL hashlookup": () => fetchCIRCLData(query),
        "Criminal IP": () => fetchCriminalIPData(query),
        "MetaDefender": () => fetchMetaDefenderData(query),
        "PhishStats": () => fetchPhishStatsData(query),
        "Ransomware.live": () => fetchRansomwareLiveData(query),
        "OpenPhish": () => fetchOpenPhishData(query),
        "DShield": () => fetchDShieldData(query),
        "Team Cymru": () => fetchTeamCymruData(query),
    };

    // Detect IOC type
    const iocType = detectIOCType(query);

    // If selectedVendors is provided, only query those vendors
    // Otherwise query all vendors that support this IOC type
    let vendorsToQuery = selectedVendors || Object.keys(vendorMap);

    // Filter by IOC support
    vendorsToQuery = vendorsToQuery.filter(vendor => {
        const supportedTypes = VENDOR_IOC_SUPPORT[vendor];
        return supportedTypes && supportedTypes.includes(iocType);
    });

    const fetchPromises = vendorsToQuery
        .filter(vendor => vendorMap[vendor]) // Ensure vendor exists in map
        .map(vendor => vendorMap[vendor]());


    const results = await Promise.all(fetchPromises);

    // Important vendor detection indicators
    const IMPORTANT_AV_VENDORS = [
        'Microsoft', 'Kaspersky', 'Bitdefender', 'ESET-NOD32', 'Avira',
        'Sophos', 'McAfee', 'Symantec', 'TrendMicro', 'F-Secure',
        'Fortinet', 'Palo Alto Networks', 'CrowdStrike'
    ];

    let isMalicious = false;
    let maliciousCount = 0;
    let totalChecked = 0;
    let maliciousReasons: string[] = [];

    // Check VirusTotal first (high priority)
    const virusTotal = results.find(v => v.name === "VirusTotal");
    if (virusTotal && !virusTotal.error && virusTotal.data) {
        const vtMalicious = virusTotal.data["Malicious"] || 0;
        const vtAllVendors = virusTotal.data["All Vendors"];

        // Auto-malicious if >3 detections
        if (vtMalicious > 3) {
            isMalicious = true;
            maliciousReasons.push(`VirusTotal: ${vtMalicious} detections`);
        }

        // Auto-malicious if important AV vendors detected it
        if (Array.isArray(vtAllVendors)) {
            const importantDetections = vtAllVendors.filter((v: any) =>
                v.category === 'malicious' && IMPORTANT_AV_VENDORS.some(av => v.engine.includes(av))
            );
            if (importantDetections.length > 0) {
                isMalicious = true;
                maliciousReasons.push(`VirusTotal: Detected by ${importantDetections.map((v: any) => v.engine).join(', ')}`);
            }
        }

        // Count VT as checked
        if (vtMalicious > 0) maliciousCount++;
        totalChecked++;
    }

    // Check AbuseIPDB (high priority)
    const abuse = results.find(v => v.name === "AbuseIPDB");
    if (abuse && !abuse.error && abuse.data["Abuse Confidence Score"]) {
        const abuseScore = parseInt(abuse.data["Abuse Confidence Score"] || "0");

        // Auto-malicious if 100% confidence
        if (abuseScore === 100) {
            isMalicious = true;
            maliciousReasons.push(`AbuseIPDB: 100% confidence (${abuse.data["Total Reports"]} reports)`);
        }

        // Count as malicious if >50%
        if (abuseScore > 50) maliciousCount++;
        totalChecked++;
    }

    // Check other vendors
    results.forEach(vendor => {
        // Skip VT and AbuseIPDB (already processed)
        if (vendor.name === "VirusTotal" || vendor.name === "AbuseIPDB") return;

        if (vendor.error || Object.keys(vendor.data).length === 0) return;

        const status = vendor.data["Status"];
        if (status && typeof status === "string") {
            totalChecked++;
            if (status.toLowerCase().includes("malicious") ||
                status.toLowerCase().includes("unsafe") ||
                status.toLowerCase().includes("phishing")) {
                maliciousCount++;
            }
        }
    });

    // Calculate score and threat level
    let overallScore = totalChecked > 0 ? Math.round((maliciousCount / totalChecked) * 100) : 0;
    let threatLevel: "safe" | "suspicious" | "malicious" | "unknown" = "unknown";

    // Override based on important detections
    if (isMalicious) {
        threatLevel = "malicious";
        overallScore = Math.max(overallScore, 75); // Ensure score reflects severity
    } else {
        if (overallScore > 70) threatLevel = "malicious";
        else if (overallScore > 30) threatLevel = "suspicious";
        else if (totalChecked > 0) threatLevel = "safe";
    }

    return {
        query,
        overallScore,
        threatLevel,
        totalVendors: results.length,
        detections: maliciousCount,
        vendorData: results,
    };
};

export const fetchThreatDataProgressive = async (
    query: string,
    selectedVendors: string[] | undefined,
    onProgress: (data: VendorData) => void
): Promise<ThreatIntelligenceResult> => {
    // Map vendor names to their fetch functions
    const vendorMap: Record<string, () => Promise<VendorData>> = {
        "IP Geolocation": () => fetchIPGeoData(query),
        "WHOIS": () => fetchWHOISData(query),
        "VirusTotal": () => fetchVirusTotalData(query),
        "AbuseIPDB": () => fetchAbuseIPDBData(query),
        "AlienVault OTX": () => fetchAlienVaultData(query),
        "Shodan": () => fetchShodanData(query),
        "URLhaus": () => fetchURLhausData(query),
        "MalwareBazaar": () => fetchMalwareBazaarData(query),
        "Google Safe Browsing": () => fetchGoogleSafeBrowsingData(query),
        "PhishTank": () => fetchPhishTankData(query),
        "Pulsedive": () => fetchPulsediveData(query),

        "Hybrid Analysis": () => fetchHybridAnalysisData(query),
        "CIRCL hashlookup": () => fetchCIRCLData(query),
        "Criminal IP": () => fetchCriminalIPData(query),
        "MetaDefender": () => fetchMetaDefenderData(query),
        "PhishStats": () => fetchPhishStatsData(query),
        "Ransomware.live": () => fetchRansomwareLiveData(query),
        "OpenPhish": () => fetchOpenPhishData(query),
        "DShield": () => fetchDShieldData(query),
        "Team Cymru": () => fetchTeamCymruData(query),
    };

    // Detect IOC type
    const iocType = detectIOCType(query);

    // Smart filtering
    let vendorsToQuery = selectedVendors || Object.keys(vendorMap);
    vendorsToQuery = vendorsToQuery.filter(vendor => {
        const supportedTypes = VENDOR_IOC_SUPPORT[vendor];
        return supportedTypes && supportedTypes.includes(iocType);
    });

    // Create promises that call onProgress when they complete
    const fetchPromises = vendorsToQuery
        .filter(vendor => vendorMap[vendor])
        .map(vendor => {
            return vendorMap[vendor]().then(data => {
                onProgress(data);
                return data;
            });
        });

    const results = await Promise.all(fetchPromises);

    // Important vendor detection indicators (same as fetchThreatData)
    const IMPORTANT_AV_VENDORS = [
        'Microsoft', 'Kaspersky', 'Bitdefender', 'ESET-NOD32', 'Avira',
        'Sophos', 'McAfee', 'Symantec', 'TrendMicro', 'F-Secure',
        'Fortinet', 'Palo Alto Networks', 'CrowdStrike'
    ];

    let isMalicious = false;
    let maliciousCount = 0;
    let totalChecked = 0;

    // Check VirusTotal first (high priority)
    const virusTotal = results.find(v => v.name === "VirusTotal");
    if (virusTotal && !virusTotal.error && virusTotal.data) {
        const vtMalicious = virusTotal.data["Malicious"] || 0;
        const vtAllVendors = virusTotal.data["All Vendors"];

        // Auto-malicious if >3 detections
        if (vtMalicious > 3) {
            isMalicious = true;
        }

        // Auto-malicious if important AV vendors detected it
        if (Array.isArray(vtAllVendors)) {
            const importantDetections = vtAllVendors.filter((v: any) =>
                v.category === 'malicious' && IMPORTANT_AV_VENDORS.some(av => v.engine.includes(av))
            );
            if (importantDetections.length > 0) {
                isMalicious = true;
            }
        }

        // Count VT as checked
        if (vtMalicious > 0) maliciousCount++;
        totalChecked++;
    }

    // Check AbuseIPDB (high priority)
    const abuse = results.find(v => v.name === "AbuseIPDB");
    if (abuse && !abuse.error && abuse.data["Abuse Confidence Score"]) {
        const abuseScore = parseInt(abuse.data["Abuse Confidence Score"] || "0");

        // Auto-malicious if 100% confidence
        if (abuseScore === 100) {
            isMalicious = true;
        }

        // Count as malicious if >50%
        if (abuseScore > 50) maliciousCount++;
        totalChecked++;
    }

    // Check other vendors
    results.forEach(vendor => {
        // Skip VT and AbuseIPDB (already processed)
        if (vendor.name === "VirusTotal" || vendor.name === "AbuseIPDB") return;

        if (vendor.error || Object.keys(vendor.data).length === 0) return;

        const status = vendor.data["Status"];
        if (status && typeof status === "string") {
            totalChecked++;
            if (status.toLowerCase().includes("malicious") ||
                status.toLowerCase().includes("unsafe") ||
                status.toLowerCase().includes("phishing")) {
                maliciousCount++;
            }
        }
    });

    // Calculate score and threat level
    let overallScore = totalChecked > 0 ? Math.round((maliciousCount / totalChecked) * 100) : 0;
    let threatLevel: "safe" | "suspicious" | "malicious" | "unknown" = "unknown";

    // Override based on important detections
    if (isMalicious) {
        threatLevel = "malicious";
        overallScore = Math.max(overallScore, 75); // Ensure score reflects severity
    } else {
        if (overallScore > 70) threatLevel = "malicious";
        else if (overallScore > 30) threatLevel = "suspicious";
        else if (totalChecked > 0) threatLevel = "safe";
    }

    return {
        query,
        overallScore,
        threatLevel,
        totalVendors: results.length,
        detections: maliciousCount,
        vendorData: results,
    };
};
