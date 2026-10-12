/// <reference types="vite/client" />
import { ThreatIntelligenceResult, VendorData, TimelineEvent } from "@/types/threat-intelligence";
import { detectAnalyzerQueryType, isPublicIpv6, type AnalyzerQueryType } from "@/utils/iocExtract";
import type { OrgThreatModel } from '@/utils/orgRelevance';

// Helper to handle response
const handleResponse = async (response: Response, vendorName: string) => {
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${vendorName} API error: ${response.status} ${response.statusText} - ${errorText}`);
    }
    return response.json();
};

// Detect IOC type from query
export const detectIOCType = (query: string): AnalyzerQueryType => detectAnalyzerQueryType(query);

// Map each vendor to the IOC types it can actually be queried for. This MUST stay
// in sync with what every backend endpoint in server/index.js accepts — a vendor
// missing here (or missing a type) is silently dropped by resolveVendorsToQuery,
// so an incomplete map means whole IOC types (hash/domain/url) get almost no
// coverage. Verified against the per-vendor `detectQueryType` guards in the API.
export const VENDOR_IOC_SUPPORT: Record<string, ('ip' | 'domain' | 'hash' | 'url')[]> = {
    "IP Geolocation": ['ip'],
    "WHOIS": ['domain'],
    "VirusTotal": ['ip', 'domain', 'hash', 'url'],
    "AbuseIPDB": ['ip'],
    "AlienVault OTX": ['ip', 'domain', 'hash', 'url'],
    "Shodan": ['ip', 'domain'],
    "URLhaus": ['url', 'domain', 'hash'],
    "MalwareBazaar": ['hash'],
    "ThreatFox": ['ip', 'domain', 'url', 'hash'],
    "PhishTank": ['url'],
    "PhishStats": ['url', 'domain'],
    "OpenPhish": ['url', 'domain'],
    // "Ransomware.live" e "Google Safe Browsing" saíram: o primeiro é feed de
    // vítimas recentes e ignora a consulta, o segundo nunca teve rota no server
    // (consultar dava 404). Os dois ficavam no mapa de vendors sem nunca serem
    // alcançados, porque este índice é que decide quem é consultado.
};

// Quantas fontes o produto realmente consulta. Derivado, nunca escrito à mão:
// a UI dizia "21 fontes" em três lugares enquanto o diretório dizia 18, e a
// diferença só cresceu quando vendor entrou ou saiu. Um número, uma origem.
export const IOC_SOURCE_COUNT = Object.keys(VENDOR_IOC_SUPPORT).length;

// Conservative allowlist: these repository endpoints use generic IPv6-capable
// indicator/host/IP paths. OTX is explicitly `/IPv4/`, so it receives no direct IPv6 queries.
export const IPV6_CAPABLE_VENDORS = new Set([
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox",
]);

export const resolveVendorsForQuery = (query: string, selectedVendors: string[]): string[] => {
    const iocType = detectIOCType(query);
    return selectedVendors.filter((vendor) =>
        VENDOR_IOC_SUPPORT[vendor]?.includes(iocType as 'ip' | 'domain' | 'hash' | 'url')
        && (!isPublicIpv6(query.trim()) || IPV6_CAPABLE_VENDORS.has(vendor))
    );
};

// Formatting logic moved from individual fetch functions
// A AbuseIPDB devolve categoria como número ([18, 22]); ninguém lê isso numa
// planilha entregue ao cliente. Tabela oficial da API v2.
const ABUSEIPDB_CATEGORIES: Record<number, string> = {
    1: "DNS comprometido", 2: "Envenenamento de DNS", 3: "Pedidos fraudulentos",
    4: "Ataque DDoS", 5: "Força bruta FTP", 6: "Ping of Death", 7: "Phishing",
    8: "Fraude VoIP", 9: "Proxy aberto", 10: "Spam em web", 11: "Spam por e-mail",
    12: "Spam em blog", 13: "IP de VPN", 14: "Varredura de portas", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Força bruta", 19: "Bot malicioso",
    20: "Host explorado", 21: "Ataque a aplicação web", 22: "SSH", 23: "IoT",
};

export const abuseCategoryNames = (categories: unknown): string[] =>
    (Array.isArray(categories) ? categories : [])
        .map((id: any) => ABUSEIPDB_CATEGORIES[Number(id)] || `Categoria ${id}`);

// Um pulse do OTX cru, reduzido ao que atribui um indicador a grupo/campanha.
// O `formatVendorData` guardava só o nome de três pulses e jogava o resto fora,
// que é justamente onde mora a atribuição.
export interface OtxPulseDetail {
    id: string;
    name: string;
    adversary: string;
    malwareFamilies: string[];
    attackIds: string[];
    tags: string[];
    tlp: string;
    created: string;
    modified: string;
}

const otxPulseDetails = (pulses: any[]): OtxPulseDetail[] =>
    (Array.isArray(pulses) ? pulses : []).map((p: any) => ({
        id: p.id || "",
        name: p.name || "",
        adversary: p.adversary || "",
        malwareFamilies: (p.malware_families || [])
            .map((m: any) => (typeof m === "string" ? m : m?.display_name || m?.id || ""))
            .filter(Boolean),
        // A OTX manda id, name e display_name ("T1566.001 - Spearphishing
        // Attachment"). Guardar só o id põe "T1056.001" numa planilha de
        // cliente, onde "T1056.001 - Keylogging" diz o que aconteceu.
        attackIds: (p.attack_ids || [])
            .map((a: any) => (typeof a === "string" ? a : a?.display_name || a?.id || ""))
            .filter(Boolean),
        tags: Array.isArray(p.tags) ? p.tags.filter(Boolean) : [],
        tlp: p.TLP || p.tlp || "",
        created: p.created || "",
        modified: p.modified || "",
    }));

export const formatVendorData = (vendorName: string, data: any, query: string): any => {
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
                // Campos de atribuição — a família sugerida pelo consenso dos
                // engines e o contexto colaborativo, que é onde a VT nomeia
                // campanha quando alguém nomeou.
                "Threat Classification": vtAttrs.popular_threat_classification?.suggested_threat_label || "",
                "Threat Names": (vtAttrs.popular_threat_classification?.popular_threat_name || [])
                    .map((n: any) => n?.value).filter(Boolean),
                "Crowdsourced Context": (vtAttrs.crowdsourced_context || []).map((c: any) => ({
                    title: c.title || "",
                    source: c.source || "",
                    detail: c.details || "",
                    severity: c.severity || "",
                    link: c.link || "",
                })),
                "All Tags": Array.isArray(vtAttrs.tags) ? vtAttrs.tags : [],
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
                categoryNames: abuseCategoryNames(r.categories),
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
                "Pulse Details": otxPulseDetails(otxData.pulse_info.pulses),
                "Reputation": otxData.reputation || 0,
                "Country": otxData.country_name || "Unknown",
                "City": otxData.city || "Unknown",
                "ASN": otxData.asn || "Unknown",
                "Sections": otxData.sections?.join(", ") || "None",
            };
        case "URLhaus":
            if (data.query_status === "ok") {
                // Payload lookup (hash query): URLhaus indexes the malware sample.
                if (data.md5_hash || data.sha256_hash) {
                    return {
                        "Status": "Malware Payload Found",
                        "Signature": data.signature || "Unknown",
                        "File Type": data.file_type || "Unknown",
                        "File Size": data.file_size ? `${data.file_size} bytes` : "Unknown",
                        "MD5": data.md5_hash || "Unknown",
                        "SHA256": data.sha256_hash || "Unknown",
                        "URL Count": data.url_count ?? data.urls?.length ?? 0,
                        "First Seen": data.firstseen || "Unknown",
                    };
                }
                // Host lookup (url/domain query).
                return {
                    "Status": data.urls?.length > 0 ? "Malicious URLs Found" : "Clean",
                    "URL Count": data.urls?.length || 0,
                    "Tags": data.urls?.[0]?.tags || [],
                };
            }
            return { "Status": "No data" };

        case "MalwareBazaar":
            if (data.query_status === "ok") {
                const mb = data.data?.[0] || {};
                return {
                    "Status": "Sample Found",
                    "File Type": mb.file_type || "Unknown",
                    "File Name": mb.file_name || "Unknown",
                    "Signature": mb.signature || "Unknown",
                    "MD5": mb.md5_hash || "Unknown",
                    "SHA256": mb.sha256_hash || "Unknown",
                    "File Size": mb.file_size ? `${mb.file_size} bytes` : "Unknown",
                    "Delivery Method": mb.delivery_method || "Unknown",
                    "Reporter": mb.reporter || "Unknown",
                    "Tags": Array.isArray(mb.tags) ? mb.tags.join(", ") : "None",
                    "First Seen": mb.first_seen || "Unknown",
                    "Last Seen": mb.last_seen || "Unknown",
                };
            }
            return { "Status": "No samples found" };

        case "ThreatFox":
            if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length > 0) {
                const tf = data.data[0];
                const malwares = Array.from(new Set(data.data.map((d: any) => d.malware_printable).filter(Boolean)));
                const allTags = Array.from(new Set(data.data.flatMap((d: any) => Array.isArray(d.tags) ? d.tags : [])));
                return {
                    "Status": "Malicious",
                    "Malware": malwares.slice(0, 5).join(", ") || tf.malware_printable || "Unknown",
                    "Threat Type": tf.threat_type_desc || tf.threat_type || "Unknown",
                    "Confidence": tf.confidence_level != null ? `${tf.confidence_level}%` : "Unknown",
                    "IOC Matches": data.data.length,
                    "Malpedia": tf.malware_malpedia || "N/A",
                    "Tags": allTags.slice(0, 8).join(", ") || "None",
                    "Reference": tf.reference || "N/A",
                    // Listas inteiras — as chaves acima cortam em 5/8 para caber
                    // na tela, e a atribuição precisa de todas.
                    "All Malware": malwares,
                    "All Tags": allTags,
                    "First Seen": tf.first_seen || "Unknown",
                    "Last Seen": tf.last_seen || "Unknown",
                };
            }
            return { "Status": "No data" };
        case "PhishTank":
            return {
                "Status": data.results?.in_database && data.results?.verified ? (data.results.valid ? "Verified Phishing" : "Clean") : "Unknown",
                "In Database": data.results?.in_database ? "Yes" : "No",
                "Verified": data.results?.verified ? "Yes" : "No",
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
            return { "Status": "Unknown", "Records Found": 0 };
        case "WHOIS":
            if (data.WhoisRecord) {
                const record = data.WhoisRecord;
                return {
                    "Registrar": record.registrarName || "Unknown",
                    "Created": record.createdDate || "Unknown",
                    "Expires": record.expiresDate || "Unknown",
                    "Updated": record.updatedDate || "Unknown",
                    "Nameservers": record.nameServers || [],
                    "Snapshot": record.snapshotTime || "Unknown",
                    "Status": record.status?.[0] || "Unknown",
                };
            }
            return { "Status": "No WHOIS data available" };

        case "Shodan": {
            const shodanData = data.data && !Array.isArray(data.data) ? data.data : data;
            // Domain queries hit /dns/domain — a different shape (subdomains + DNS records).
            if (shodanData.subdomains || (Array.isArray(shodanData.data) && shodanData.data[0]?.subdomain !== undefined)) {
                const records = Array.isArray(shodanData.data) ? shodanData.data : [];
                const byType = (t: string) => records.filter((r: any) => r.type === t);
                return {
                    "Status": records.length > 0 ? "DNS Records Found" : "No DNS data",
                    "Subdomains": Array.isArray(shodanData.subdomains) ? shodanData.subdomains.length : 0,
                    "Subdomain List": Array.isArray(shodanData.subdomains) ? shodanData.subdomains : [],
                    "DNS Records": records.map((record: any) => ({ subdomain: record.subdomain, type: record.type, value: record.value, last_seen: record.last_seen || null })),
                    "A Records": byType("A").map((r: any) => `${r.subdomain || "@"} → ${r.value}`).slice(0, 10).join(", ") || "None",
                    "MX Records": byType("MX").map((r: any) => r.value).slice(0, 5).join(", ") || "None",
                    "NS Records": byType("NS").map((r: any) => r.value).slice(0, 5).join(", ") || "None",
                    "TXT Records": byType("TXT").length,
                    "Total Records": records.length,
                    "Tags": Array.isArray(shodanData.tags) ? shodanData.tags.join(", ") : "None",
                };
            }
            const banners = Array.isArray(shodanData.data) ? shodanData.data : [];
            // The actual CVE list, not just a count. Shodan keys shodanData.vulns by CVE id.
            const hostVulns = shodanData.vulns ? Object.keys(shodanData.vulns) : [];
            // Preserve per-service banner details.
            const servicesDetail = banners.map((b: any) => ({
                port: b.port,
                transport: b.transport || "tcp",
                product: b.product || b._shodan?.module || null,
                version: b.version || null,
                cpe: Array.isArray(b.cpe23) ? b.cpe23.slice(0, 3) : (Array.isArray(b.cpe) ? b.cpe.slice(0, 3) : []),
                module: b._shodan?.module || null,
                http_server: b.http?.server || null,
                http_title: b.http?.title || null,
                ssl_version: Array.isArray(b.ssl?.versions) ? b.ssl.versions.join(", ") : null,
                ssl_jarm: b.ssl?.jarm || null,
                cert_subject: b.ssl?.cert?.subject?.CN || null,
                cert_issuer: b.ssl?.cert?.issuer?.CN || null,
                vulns: b.vulns ? Object.keys(b.vulns) : [],
                hostnames: Array.isArray(b.hostnames) ? b.hostnames.slice(0, 3) : [],
            }));
            const location = [shodanData.city, shodanData.region_code, shodanData.country_name].filter(Boolean).join(", ");
            return {
                "Open Ports": shodanData.ports?.slice(0, 12).join(", ") || "None",
                "Total Ports": shodanData.ports?.length || 0,
                "Services": banners.slice(0, 5).map((d: any) => d.product || `${d.port}/${d.transport || 'tcp'}`).join(", ") || "Unknown",
                "Organization": shodanData.org || "Unknown",
                "Hostnames": shodanData.hostnames?.slice(0, 5).join(", ") || "None",
                "Domains": shodanData.domains?.slice(0, 5).join(", ") || "None",
                "OS": shodanData.os || "Unknown",
                "Location": location || "Unknown",
                "Last Update": shodanData.last_update || "Unknown",
                "ASN": shodanData.asn || "Unknown",
                "ISP": shodanData.isp || "Unknown",
                "Vulnerabilities": `${hostVulns.length} CVEs`,
                "Vulnerability List": hostVulns,
                "Tags": shodanData.tags?.slice(0, 8).join(", ") || "None",
                "Services Detail": servicesDetail,
            };
        }
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
                    "Proxy/VPN": data.proxy === undefined ? "Unknown" : (data.proxy ? "Yes ⚠️" : "No"),
                    "Hosting": data.hosting === undefined ? "Unknown" : (data.hosting ? "Yes" : "No"),
                    "Mobile": data.mobile === undefined ? "Unknown" : (data.mobile ? "Yes" : "No"),
                    "Reverse Hostname": data.reverseHostname || "Unknown",
                    "Latitude": data.lat !== undefined ? String(data.lat) : "Unknown",
                    "Longitude": data.lon !== undefined ? String(data.lon) : "Unknown"
                };
            }
            return { "Status": data.message || "No geolocation data available" };
        case "OpenPhish":
            // Server returns { listed, status }. Surface a capital-S "Status" so the
            // verdict aggregator (which reads data["Status"]) actually counts the hit.
            return {
                "Status": data.listed ? "Phishing" : "Clean",
                "Listed": data.listed ? "Yes" : "No",
            };
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
        case "PhishTank": return `https://phishtank.org/`;

        case "PhishStats": return `https://phishstats.info/`;

        case "OpenPhish": return `https://openphish.com/`;
        case "WHOIS": return `https://who.is/whois/${query}`;
        case "IP Geolocation": return `https://ip-api.com/#${query}`;
        default: return undefined;
    }
};

// ---- IOC detection timeline -------------------------------------------------
// Normalize the many timestamp formats vendors return (unix seconds, ISO, and
// abuse.ch's "YYYY-MM-DD HH:MM:SS UTC") to an ISO string, or null if unusable.
const parseLooseDate = (v: any): string | null => {
    if (v == null) return null;
    let t: number;
    if (typeof v === "number") {
        if (!v) return null; // 0 / NaN are "no timestamp", not 1970
        t = v < 1e12 ? v * 1000 : v; // seconds vs ms
    } else {
        const s = String(v).trim();
        if (!s || /^(unknown|never|n\/a|none|0)$/i.test(s)) return null;
        // abuse.ch style: "2023-08-01 12:34:56 UTC"
        const normalized = s.replace(/\s+UTC$/i, "Z").replace(" ", "T");
        t = Date.parse(normalized);
        if (isNaN(t)) t = Date.parse(s);
    }
    if (isNaN(t)) return null;
    const d = new Date(t);
    const yr = d.getUTCFullYear();
    if (yr < 2000 || yr > new Date().getUTCFullYear() + 1) return null; // sanity bound
    return d.toISOString();
};

const pushEvent = (
    events: TimelineEvent[], vendor: string, label: string, raw: any, kind: TimelineEvent["kind"],
) => {
    const date = parseLooseDate(raw);
    if (date) events.push({ vendor, label, date, kind });
};

// Pull dated observations out of a vendor's RAW response (before display
// formatting) so every feed can contribute to one merged timeline.
const extractVendorTimestamps = (vendorName: string, data: any): TimelineEvent[] => {
    const e: TimelineEvent[] = [];
    const v = vendorName;
    try {
        switch (vendorName) {
            case "VirusTotal": {
                const a = (data.data?.data ? data.data.data : data.data)?.attributes;
                if (a) {
                    pushEvent(e, v, "First submission", a.first_submission_date, "first_seen");
                    pushEvent(e, v, "Last analysis", a.last_analysis_date, "analysis");
                    pushEvent(e, v, "Last modification", a.last_modification_date, "other");
                }
                break;
            }
            case "AbuseIPDB": {
                const a = data.data?.data ? data.data.data : data.data;
                if (a) {
                    pushEvent(e, v, "Last reported", a.lastReportedAt, "report");
                    (a.reports || []).slice(0, 5).forEach((r: any) => pushEvent(e, v, "Abuse report", r.reportedAt, "report"));
                }
                break;
            }
            case "AlienVault OTX": {
                const a = data.data || data;
                (a.pulse_info?.pulses || []).slice(0, 5).forEach((p: any) => pushEvent(e, v, `Pulse: ${p.name || "created"}`, p.created, "report"));
                break;
            }
            case "URLhaus": {
                pushEvent(e, v, "First seen", data.firstseen, "first_seen");
                pushEvent(e, v, "Last seen", data.lastseen, "last_seen");
                (data.urls || []).slice(0, 5).forEach((u: any) => pushEvent(e, v, "Malicious URL added", u.date_added, "report"));
                break;
            }
            case "MalwareBazaar": {
                const m = data.data?.[0];
                if (m) { pushEvent(e, v, "First seen", m.first_seen, "first_seen"); pushEvent(e, v, "Last seen", m.last_seen, "last_seen"); }
                break;
            }
            case "ThreatFox": {
                (data.data || []).slice(0, 8).forEach((d: any) => {
                    pushEvent(e, v, `First seen: ${d.malware_printable || "IOC"}`, d.first_seen, "first_seen");
                    pushEvent(e, v, "Last seen", d.last_seen, "last_seen");
                });
                break;
            }
            case "Shodan": {
                pushEvent(e, v, "Last update", data.last_update, "analysis");
                (Array.isArray(data.data) ? data.data : []).slice(0, 8).forEach((b: any) =>
                    pushEvent(e, v, b.subdomain !== undefined ? `DNS ${b.type} record` : `Service :${b.port}`, b.last_seen || b.timestamp, "other"));
                break;
            }
            case "WHOIS": {
                const r = data.WhoisRecord;
                if (r) {
                    pushEvent(e, v, "Domain registered", r.createdDate, "first_seen");
                    pushEvent(e, v, "Domain updated", r.updatedDate, "other");
                    pushEvent(e, v, "Domain expires", r.expiresDate, "other");
                }
                break;
            }
            case "PhishStats": {
                (Array.isArray(data) ? data : []).slice(0, 5).forEach((d: any) => pushEvent(e, v, "Phishing reported", d.date, "report"));
                break;
            }
        }
    } catch {
        /* best-effort: a malformed vendor payload must never break the search */
    }
    return e;
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
            link: getVendorLink(vendorName, query),
            timeline: extractVendorTimestamps(vendorName, data),
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
export const fetchAbuseIPDBCidrBlock = async (ip: string): Promise<any> => {
    const parts = ip.split('.');
    if (parts.length !== 4) throw new Error("Invalid IP address");
    const network = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;

    const response = await fetch('/api/abuseipdb/check-block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: network })
    });
    if (!response.ok) {
        throw new Error(`Failed to check block: ${response.statusText}`);
    }
    const res = await response.json();
    return res.data?.data ? res.data.data : res.data;
};
export const fetchAlienVaultData = (query: string) => fetchFromBackend('alienvault', query, "AlienVault OTX");
export const fetchShodanData = (query: string) => fetchFromBackend('shodan', query, "Shodan");
export const fetchURLhausData = (query: string) => fetchFromBackend('urlhaus', query, "URLhaus");

export const fetchMalwareBazaarData = (query: string) => fetchFromBackend('malwarebazaar', query, "MalwareBazaar");
export const fetchThreatFoxData = (query: string) => fetchFromBackend('threatfox', query, "ThreatFox");
export const fetchPhishTankData = (query: string) => fetchFromBackend('phishtank', query, "PhishTank");

export const fetchPhishStatsData = (query: string) => fetchFromBackend('phishstats', query, "PhishStats");
export const fetchOpenPhishData = (query: string) => fetchFromBackend('openphish', query, "OpenPhish");

// AV engines whose verdict alone is enough to mark an IOC malicious.
const IMPORTANT_AV_VENDORS = [
    'Microsoft', 'Kaspersky', 'Bitdefender', 'ESET-NOD32', 'Avira',
    'Sophos', 'McAfee', 'Symantec', 'TrendMicro', 'F-Secure',
    'Fortinet', 'Palo Alto Networks', 'CrowdStrike'
];

// Single source of truth mapping each vendor to its fetch call for a given query.
const buildVendorMap = (query: string): Record<string, () => Promise<VendorData>> => ({
    "IP Geolocation": () => fetchIPGeoData(query),
    "WHOIS": () => fetchWHOISData(query),
    "VirusTotal": () => fetchVirusTotalData(query),
    "AbuseIPDB": () => fetchAbuseIPDBData(query),
    "AlienVault OTX": () => fetchAlienVaultData(query),
    "Shodan": () => fetchShodanData(query),
    "URLhaus": () => fetchURLhausData(query),
    "MalwareBazaar": () => fetchMalwareBazaarData(query),
    "ThreatFox": () => fetchThreatFoxData(query),
    "PhishTank": () => fetchPhishTankData(query),
    "PhishStats": () => fetchPhishStatsData(query),
    "OpenPhish": () => fetchOpenPhishData(query),
});

// Resolve which vendors to actually query: the explicit selection (or all known
// vendors), narrowed to those that both exist in the map and support this IOC type.
const resolveVendorsToQuery = (
    query: string,
    vendorMap: Record<string, () => Promise<VendorData>>,
    selectedVendors: string[] | undefined,
): string[] =>
    resolveVendorsForQuery(query, selectedVendors || Object.keys(vendorMap))
        .filter(vendor => vendorMap[vendor]);

// Aggregate per-vendor results into an overall verdict. VirusTotal and AbuseIPDB
// carry extra weight (a strong signal from either forces "malicious"); every other
// vendor contributes a simple malicious/clean vote based on its Status string.
const scoreThreatResults = (query: string, results: VendorData[]): ThreatIntelligenceResult => {
    let isMalicious = false;
    let maliciousCount = 0;
    let totalChecked = 0;

    const virusTotal = results.find(v => v.name === "VirusTotal");
    if (virusTotal && !virusTotal.error && virusTotal.data) {
        const vtMalicious = virusTotal.data["Malicious"] || 0;
        const vtAllVendors = virusTotal.data["All Vendors"];

        if (vtMalicious > 3) isMalicious = true;

        if (Array.isArray(vtAllVendors)) {
            const importantDetections = vtAllVendors.filter((v: any) =>
                v.category === 'malicious' && IMPORTANT_AV_VENDORS.some(av => v.engine.includes(av))
            );
            if (importantDetections.length > 0) isMalicious = true;
        }

        if (vtMalicious > 0) maliciousCount++;
        totalChecked++;
    }

    const abuse = results.find(v => v.name === "AbuseIPDB");
    if (abuse && !abuse.error && abuse.data["Abuse Confidence Score"]) {
        const abuseScore = parseInt(abuse.data["Abuse Confidence Score"] || "0");
        if (abuseScore === 100) isMalicious = true;
        if (abuseScore > 50) maliciousCount++;
        totalChecked++;
    }

    results.forEach(vendor => {
        if (["VirusTotal", "AbuseIPDB", "WHOIS"].includes(vendor.name)) return;
        if (vendor.error || Object.keys(vendor.data).length === 0) return;

        const status = vendor.data["Status"];
        if (status && typeof status === "string") {
            if (["PhishTank", "PhishStats", "OpenPhish"].includes(vendor.name) &&
                !["Phishing", "Verified Phishing", "Found in Phishing Database", "Clean"].includes(status)) return;
            totalChecked++;
            if (status.toLowerCase().includes("malicious") ||
                status.toLowerCase().includes("unsafe") ||
                status.toLowerCase().includes("phishing")) {
                maliciousCount++;
            }
        }
    });

    let overallScore = totalChecked > 0 ? Math.round((maliciousCount / totalChecked) * 100) : 0;
    let threatLevel: "safe" | "suspicious" | "malicious" | "unknown" = "unknown";

    if (isMalicious) {
        threatLevel = "malicious";
        overallScore = Math.max(overallScore, 75);
    } else {
        if (overallScore > 70) threatLevel = "malicious";
        else if (overallScore > 30) threatLevel = "suspicious";
        else if (totalChecked > 0) threatLevel = "safe";
    }

    // Additive verdict metadata — purely informational, does not alter the
    // verdict above. Confidence = how strongly the reporting vendors agree with
    // each other; disagreement = a non-trivial malicious/clean split (a minority
    // report worth a second look). A strong trusted signal (isMalicious) floors
    // confidence at 80 since a high-weight engine flagged it.
    const cleanVotes = Math.max(0, totalChecked - maliciousCount);
    const majority = Math.max(maliciousCount, cleanVotes);
    let confidence = totalChecked > 0 ? Math.round((majority / totalChecked) * 100) : 0;
    if (isMalicious) confidence = Math.max(confidence, 80);
    const minority = Math.min(maliciousCount, cleanVotes);
    const disagreement = maliciousCount > 0 && cleanVotes > 0 && minority / totalChecked >= 0.2;

    return {
        query,
        overallScore,
        threatLevel,
        totalVendors: results.length,
        detections: maliciousCount,
        vendorData: results,
        confidence,
        disagreement,
        reportingVendors: totalChecked,
    };
};

export const fetchThreatData = async (query: string, selectedVendors?: string[]): Promise<ThreatIntelligenceResult> => {
    const vendorMap = buildVendorMap(query);
    const vendorsToQuery = resolveVendorsToQuery(query, vendorMap, selectedVendors);

    const results = await Promise.all(vendorsToQuery.map(vendor => vendorMap[vendor]()));
    return scoreThreatResults(query, results);
};

export const fetchThreatDataProgressive = async (
    query: string,
    selectedVendors: string[] | undefined,
    onProgress: (data: VendorData) => void
): Promise<ThreatIntelligenceResult> => {
    const vendorMap = buildVendorMap(query);
    const vendorsToQuery = resolveVendorsToQuery(query, vendorMap, selectedVendors);

    // Each vendor is wrapped in a timeout + catch so one slow/failed provider
    // doesn't lose the whole scan, and onProgress streams each result to the UI.
    const VENDOR_TIMEOUT_MS = 30_000;

    const fetchPromises = vendorsToQuery.map(vendor => {
        const timeoutPromise = new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`${vendor} timed out after ${VENDOR_TIMEOUT_MS / 1000}s`)), VENDOR_TIMEOUT_MS)
        );

        return Promise.race([vendorMap[vendor](), timeoutPromise])
            .then(data => {
                onProgress(data);
                return data;
            })
            .catch(err => {
                const errorData: VendorData = {
                    name: vendor,
                    data: { "Status": "Error" },
                    error: err?.message || "Request failed",
                };
                onProgress(errorData);
                return errorData;
            });
    });

    const results = await Promise.all(fetchPromises);
    return scoreThreatResults(query, results);
};

export interface DnsLookupResult {
    domain: string;
    records: {
        A: string[];
        AAAA: string[];
        MX: string[];
        TXT: string[];
        NS: string[];
        CNAME: string[];
    };
    dnsDumpster?: any;
}

export const fetchDnsLookup = async (domain: string): Promise<DnsLookupResult> => {
    const response = await fetch('/api/dns/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: domain })
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`DNS Lookup API error: ${response.status} - ${errorText}`);
    }
    return response.json();
};

// ─── Boletim diário (Feed Generator) ───────────────────────────────────────
// 1 URL = 1 boletim: o front escolhe uma URL -> o worker na VPS gera o JSON ->
// download -> o .pptx oficial é preenchido localmente com os templates.
// 'auto' só existe do lado do PEDIDO: o motor classifica sozinho depois de
// raspar a URL (mesma heurística que já é o padrão do CLI dele), e o job que
// volta pronto já traz o tipo concreto resolvido (deck_type no JSON).
export type DeckType = 'vuln' | 'campaign' | 'auto';

// Template do deck: 'avancado' = SRR novo (fundo branco, painéis, ícones e
// números de destaque); 'basico' = SRR V2; 'premium' = um modelo fechado por
// subtipo de ameaça (malware, phishing, ransomware/APT, CVE única ou várias).
// A escolha fica salva no navegador.
export type DeckTemplate = 'avancado' | 'basico' | 'premium';
const DECK_TEMPLATE_KEY = 'ts-deck-template';

export const loadDeckTemplate = (): DeckTemplate => {
    try {
        const raw = localStorage.getItem(DECK_TEMPLATE_KEY);
        return raw === 'basico' || raw === 'premium' ? raw : 'avancado';
    } catch {
        return 'avancado';
    }
};

export const saveDeckTemplate = (template: DeckTemplate): void => {
    try { localStorage.setItem(DECK_TEMPLATE_KEY, template); } catch { /* modo privado */ }
};

// Subtipo do template premium (só importa quando DeckTemplate === 'premium'):
// 'auto' (padrão) deixa o motor decidir pelo conteúdo do boletim; um valor
// concreto também define o DeckType sozinho (phishing é sempre campanha,
// cve_unica é sempre vulnerabilidade) -- o motor resolve isso, o front só
// manda o subtipo.
export type DeckSubtype = 'auto' | 'malware' | 'phishing' | 'ransomware' | 'cve_unica' | 'cve_varias';
const DECK_SUBTYPE_KEY = 'ts-deck-subtype';
const DECK_SUBTYPES: DeckSubtype[] = ['malware', 'phishing', 'ransomware', 'cve_unica', 'cve_varias'];

export const loadDeckSubtype = (): DeckSubtype => {
    try {
        const raw = localStorage.getItem(DECK_SUBTYPE_KEY) as DeckSubtype | null;
        return raw && DECK_SUBTYPES.includes(raw) ? raw : 'auto';
    } catch {
        return 'auto';
    }
};

export const saveDeckSubtype = (subtype: DeckSubtype): void => {
    try { localStorage.setItem(DECK_SUBTYPE_KEY, subtype); } catch { /* modo privado */ }
};

export interface DailySuggestion {
    title: string;
    url: string;
    source: string;
    pubDate: string;
    score: number;
    severity: string;
    cves: string[];
    kev: boolean;
    reasons: string[];
    suggestedType: DeckType;
}

export const fetchDailySuggestions = async (
    hours = 36,
    limit = 10,
): Promise<{ generatedAt: string; windowHours: number; count: number; suggestions: DailySuggestion[] }> => {
    const r = await fetch(`/api/feed/daily-suggestions?hours=${hours}&limit=${limit}`);
    if (!r.ok) throw new Error(`Suggestions API error: ${r.status}`);
    return r.json();
};

// Forma do JSON do boletim (sidecar gerado pelo motor — ver serialize.py). Campos
// opcionais porque variam por deck_type (vuln vs campaign) e podem faltar.
export interface BoletimReport {
    deck_type?: DeckType;
    source_url?: string;
    source_published?: string;    // publicação da fonte (≠ geração do boletim)
    generated_at?: string;
    tlp?: string;
    titulo?: string;
    sumario_executivo?: string;
    objetivo?: string;            // campaign: "Objetivo da Campanha"
    descricao?: string;
    pre_requisitos?: string[];    // vuln: "Pré-requisitos de Exploração"
    impactos?: string[];
    cve_id?: string;
    estado_exploracao?: string;   // vuln: "Explorada ativamente", "PoC público"…
    tecnologias_afetadas?: {
        fabricante?: string; software?: string; versao?: string; versao_corrigida?: string;
        cve?: string; cvss?: string; severidade?: string; cwe?: string; kev?: boolean;
    }[];
    // campaign: box "Superfície de Ataque Alvo". Objeto no motor atual; sidecars
    // antigos traziam uma tabela de tecnologias — os dois formatos são aceitos.
    superficie_de_ataque?:
        | { vetor_inicial?: string; superficie?: string; ativos_alvo?: string;
            ttps_principais?: string; perfil_vitimas?: string }
        | { categoria?: string; tecnologia?: string; utilizacao?: string }[];
    ator?: {
        threat_actor?: string; tipo?: string; motivation?: string;
        sectors?: string[]; origem?: string; nivel_atividade?: string;
        diferencial?: string; onion?: string[];
    };
    recomendacoes?: { titulo?: string; itens?: string[] }[];
    iocs?: { categoria?: string; tipo?: string; valor?: string }[];
    iocs_fontes?: string[];   // apêndices externos (repo/gist) de onde os IOCs foram coletados
    mitre_ttps?: { id?: string; nome?: string; tatica?: string; descricao?: string; contexto?: string; url?: string }[];
    referencias_coletadas?: { titulo?: string; url?: string }[];
    // Conteúdo extra do template avançado (risco, ações, destaques, cadeia...).
    srr_avancado?: Record<string, unknown>;
    // Consumo de LLM da geração deste boletim (custo real cobrado pela OpenRouter).
    consumo?: {
        modelos?: string[]; chamadas?: number;
        tokens_in?: number; tokens_out?: number; custo_usd?: number;
    };
}

// 1 URL = 1 boletim: o front pede a geração de uma URL; o worker na VPS gera o
// JSON e devolve. O front faz poll do job até ficar pronto e baixa o JSON.
export interface BoletimJob {
    id: string;
    url: string;
    type: DeckType;
    template?: DeckTemplate;   // ausente em boletim anterior à escolha de template
    subtype?: DeckSubtype;     // só com template premium; ausente/'auto' = motor escolheu
    title: string;
    status: 'pending' | 'done' | 'error';
    json: BoletimReport | null;
    error: string | null;
    createdAt: string;
    updatedAt: string;
    queuePosition?: number;   // quantos jobs pending estão à frente deste (0 = próximo)
    // Só na listagem (GET /api/feed/jobs), que não carrega o boletim: diz se
    // vale a pena buscar o JSON completo ao abrir.
    hasReport?: boolean;
    // Indexados na entrega do worker — ligam o boletim a outros reports.
    techniques?: string[];
    cves?: string[];
    // Anexos prontos: o deck no template SRR e o PDF dele convertido, ambos
    // preenchidos pelo worker na VPS (é lá que vivem os templates e o conversor)
    // e entregues junto do JSON. O valor é o nome do arquivo. Boletim antigo,
    // gerado antes disso, não tem nenhum — daí o opcional.
    deck?: { pptx?: string; pdf?: string };
}

// Lista de boletins do usuário, sem o JSON. O detalhe vem de fetchJob(id).
export const fetchJobList = async (): Promise<BoletimJob[]> => {
    const r = await fetch('/api/feed/jobs');
    if (!r.ok) throw new Error(`Feed API error: ${r.status}`);
    return (await r.json()).jobs || [];
};

export const deleteJob = async (id: string): Promise<void> => {
    const r = await fetch(`/api/feed/job/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(`Feed API error: ${r.status}`);
};

/** `urls` é uma story consolidada; uma URL só continua valendo. */
export const generateBoletim = async (
    urls: string | string[], type: DeckType, title = '', template: DeckTemplate = loadDeckTemplate(),
    subtype: DeckSubtype = 'auto',
): Promise<{ id: string; status: string }> => {
    const r = await fetch('/api/feed/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls: Array.isArray(urls) ? urls : [urls], type, title, template, subtype }),
    });
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || `Generate API error: ${r.status}`);
    }
    return r.json();
};

// Baixa um anexo pronto. Nem o .pptx nem o .pdf são montados no browser: os dois
// saem do template SRR preenchido na VPS — o PDF é o próprio deck convertido —,
// que é o único lugar com os templates e o conversor.
export const downloadBoletimDeck = async (job: BoletimJob, kind: 'pptx' | 'pdf'): Promise<void> => {
    const r = await fetch(`/api/feed/job/deck?id=${encodeURIComponent(job.id)}&kind=${kind}`);
    if (!r.ok) {
        if (r.status === 404) {
            throw new Error(`Este boletim não tem ${kind.toUpperCase()}: ele foi gerado antes de os arquivos passarem a vir prontos da VPS. Gere de novo para obtê-lo.`);
        }
        // 403 do gate de admin (PPTX) traz o motivo no corpo; sem corpo, o status.
        const reason = await r.json().catch(() => null);
        throw new Error(reason?.error || `Falha ao baixar o ${kind.toUpperCase()}: ${r.status}`);
    }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = job.deck?.[kind] || `${job.id}.${kind}`;
    a.click();
    URL.revokeObjectURL(url);
};

export const fetchJob = async (id: string): Promise<BoletimJob> => {
    const r = await fetch(`/api/feed/job?id=${encodeURIComponent(id)}`);
    if (!r.ok) throw new Error(`Job API error: ${r.status}`);
    return r.json();
};

export interface RansomwareVictim {
    id?: string;
    name: string;
    website?: string;
    group: string;
    country: string;
    countryName: string;
    sector: string;
    published?: string | null;
    discovered?: string | null;
    description?: string;
    screenshot?: string;
    permalink?: string;
    infostealer?: unknown;
    press?: unknown[];
    source: string;
}

export interface ThreatFoxRecentIoc {
    id?: string;
    value: string;
    type: string;
    malware: string;
    confidence: number;
    firstSeen?: string | null;
    lastSeen?: string | null;
    tags: string[];
    reporter?: string;
    reference?: string;
    source: string;
}

export interface CountItem {
    name: string;
    count: number;
    countryName?: string;
}

export interface DailySummaryEvent {
    id: string;
    kind: "advisory" | "ransomware";
    title: string;
    titlePt?: string | null;
    link?: string | null;
    source: string;
    timestamp: string;
    priority: "critical" | "high" | "context";
    category: "vulnerability" | "active-exploitation" | "ransomware" | "news";
    score: number;
    severity?: string | null;
    cves: string[];
    kev: boolean;
    reasons: string[];
    group?: string | null;
    countryName?: string | null;
    sector?: string | null;
}

export interface DailyNarrative {
    title: string;
    summary: string[];
    attentionTopics: Array<{
        title: string;
        assessment: string;
        eventIds: string[];
        recommendedAction?: string;
    }>;
}

export interface DailySummaryEdition {
    date: string;
    timezone: "America/Recife";
    windowStart: string;
    windowEnd: string;
    generatedAt: string;
    narrativeSource: "openrouter" | "deterministic";
    narrative: DailyNarrative;
    events: DailySummaryEvent[];
    sources: string[];
}

export interface DailyBriefResponse {
    edition: DailySummaryEdition;
    availableDates: string[];
}

export interface SectorOption {
    name: string;
    count: number;
}

export interface RegionOption {
    key: string;
    label: string;
}

export interface ThreatSectorsResponse {
    sectors: SectorOption[];
    regions: RegionOption[];
    defaultRegions: string[];
}

export interface ThreatMapData {
    generatedAt: string;
    windowDays: number;
    source: string;
    totalVictims?: number;
    victims: RansomwareVictim[];
    countries: CountItem[];
    groups: CountItem[];
    sectors: CountItem[];
    topCountry: CountItem | null;
    activeGroups: number;
    delta: {
        victims: number;
        previousVictims: number;
        percent: number;
        direction: "up" | "down" | "flat";
    };
    latam: {
        victims: number;
        countries: CountItem[];
        groups: CountItem[];
    };
}

const intelError = async (r: Response): Promise<never> => {
    const e = await r.json().catch(() => ({}));
    throw new Error((e as { error?: string }).error || `Intel API error: ${r.status}`);
};

export const fetchDailyBrief = async (date?: string): Promise<DailyBriefResponse> => {
    const query = date ? `?${new URLSearchParams({ date })}` : '';
    const r = await fetch(`/api/intel/daily-brief${query}`);
    if (!r.ok) return intelError(r);
    return r.json();
};

export const fetchThreatMap = async (
    days = 3,
    focus?: { sectors: string[]; regions: string[] },
): Promise<ThreatMapData> => {
    const params = new URLSearchParams({ days: String(days) });
    if (focus?.sectors.length) {
        params.set("sectors", focus.sectors.join(","));
        if (focus.regions.length) params.set("regions", focus.regions.join(","));
    }
    const r = await fetch(`/api/intel/threat-map?${params}`);
    if (!r.ok) return intelError(r);
    return r.json();
};

export const fetchThreatSectors = async (): Promise<ThreatSectorsResponse> => {
    const r = await fetch(`/api/intel/sectors`);
    if (!r.ok) return intelError(r);
    return r.json();
};

// ── Auth GitHub (allow-list). Geração usa a chave OpenRouter do servidor ─────
export interface AuthState { authenticated: boolean; login?: string; isAdmin?: boolean; isPremium?: boolean; }

// Estado de login (cookie de sessão é httpOnly — o front só sabe via /me).
export const fetchAuth = async (): Promise<AuthState> => {
    try {
        const r = await fetch('/api/auth/me');
        if (!r.ok) return { authenticated: false };
        return r.json();
    } catch { return { authenticated: false }; }
};

export const loginUrl = '/api/auth/github/login';
export const signupUrl = '/api/auth/github/login?signup=1';

// ─── Catálogo de feeds RSS monitorados pelo coletor ────────────────────────
export interface FeedHealth {
    ok: boolean; count: number; error: string | null; at: string;
    status?: "fresh" | "unchanged" | "stale" | "failed";
    fetchedCount?: number; lastSuccessfulAt?: string | null;
}
export interface FeedSource {
    url: string;
    source: string;
    layer: number;
    weight_boost: number;
    builtin: boolean;
    enabled: boolean;
    health: FeedHealth | null;
}
export interface FeedsResponse { feeds: FeedSource[]; isAdmin: boolean; }

const feedError = async (r: Response): Promise<never> => {
    const e = await r.json().catch(() => ({}));
    throw new Error((e as { error?: string }).error || `Feeds API error: ${r.status}`);
};

export const fetchFeeds = async (): Promise<FeedsResponse> => {
    const r = await fetch('/api/feeds');
    if (!r.ok) return feedError(r);
    return r.json();
};

export const addFeed = async (feed: { url: string; source: string; layer: number; weight_boost: number }): Promise<FeedSource[]> => {
    const r = await fetch('/api/feeds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(feed),
    });
    if (!r.ok) return feedError(r);
    return (await r.json()).feeds;
};

export const toggleFeed = async (url: string, enabled: boolean): Promise<FeedSource[]> => {
    const r = await fetch('/api/feeds', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, enabled }),
    });
    if (!r.ok) return feedError(r);
    return (await r.json()).feeds;
};

export const deleteFeed = async (url: string): Promise<FeedSource[]> => {
    const r = await fetch(`/api/feeds?url=${encodeURIComponent(url)}`, { method: 'DELETE' });
    if (!r.ok) return feedError(r);
    return (await r.json()).feeds;
};

export const logout = async (): Promise<void> => {
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
};

// ─── Allow-list (admin) ────────────────────────────────────────────────────
export interface AllowlistEntry { login: string; source: 'env' | 'dynamic'; admin: boolean; removable: boolean; }
export interface AllowlistResponse { allowlist: AllowlistEntry[]; org: string | null; }

const allowlistError = async (r: Response): Promise<never> => {
    const e = await r.json().catch(() => ({}));
    throw new Error((e as { error?: string }).error || `Allowlist API error: ${r.status}`);
};

export const fetchAllowlist = async (): Promise<AllowlistResponse> => {
    const r = await fetch('/api/admin/allowlist');
    if (!r.ok) return allowlistError(r);
    return r.json();
};

export const addAllowlistEntry = async (login: string): Promise<AllowlistEntry[]> => {
    const r = await fetch('/api/admin/allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login }),
    });
    if (!r.ok) return allowlistError(r);
    return (await r.json()).allowlist;
};

export const removeAllowlistEntry = async (login: string): Promise<AllowlistEntry[]> => {
    const r = await fetch(`/api/admin/allowlist?login=${encodeURIComponent(login)}`, { method: 'DELETE' });
    if (!r.ok) return allowlistError(r);
    return (await r.json()).allowlist;
};

// ─── Status das integrações (admin) ────────────────────────────────────────
export interface IntegrationStatus { name: string; env: string; configured: boolean; required: boolean; note?: string; }
export interface IntegrationsResponse { integrations: IntegrationStatus[]; keyless: string[]; }

export const fetchIntegrationStatus = async (): Promise<IntegrationsResponse> => {
    const r = await fetch('/api/admin/integrations');
    if (!r.ok) return allowlistError(r);
    return r.json();
};

// ─── Gate premium aberto (chave de desenvolvimento, admin) ─────────────────
export const fetchPremiumOpen = async (): Promise<boolean> => {
    const r = await fetch('/api/admin/premium-open');
    if (!r.ok) return allowlistError(r);
    return (await r.json()).premiumOpen === true;
};

export const setPremiumOpen = async (premiumOpen: boolean): Promise<boolean> => {
    const r = await fetch('/api/admin/premium-open', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ premiumOpen }),
    });
    if (!r.ok) return allowlistError(r);
    return (await r.json()).premiumOpen === true;
};

// Attack Surface: Shodan-led external exposure search with optional TCP validation.
export type AttackSurfaceMode = 'guided' | 'advanced';
export type AttackSurfaceTargetType = 'ip' | 'domain' | 'cidr' | 'org';
export type AttackSurfaceRisk = 'critical' | 'high' | 'medium' | 'low';
export type AttackSurfaceValidationStatus = 'open' | 'closed' | 'timeout' | 'udp_not_supported' | 'error' | 'not_requested';

export interface AttackSurfaceInput {
    mode: AttackSurfaceMode;
    targetType?: AttackSurfaceTargetType;
    target?: string;
    advancedQuery?: string;
    limit: number;
    page?: number;
    activeValidation: boolean;
}

export interface ShodanCreditStatus {
    plan: string | null;
    queryCredits: number | null;
}

export interface AttackSurfaceFinding {
    id: string;
    ip: string;
    port: number;
    transport: 'tcp' | 'udp';
    risk: AttackSurfaceRisk;
    riskScore: number;
    riskReasons: string[];
    service: string | null;
    product: string | null;
    version: string | null;
    organization: string | null;
    asn: string | null;
    hostnames: string[];
    country: string | null;
    city: string | null;
    source: { shodan: boolean };
    observedAt: string | null;
    cves: string[];
    tags: string[];
    bannerSnippet: string | null;
    validation: {
        attempted: boolean;
        status: AttackSurfaceValidationStatus;
        detail: string | null;
    };
    // Query que originou o achado, carimbada na junção do lote (o `query` da
    // resposta some quando N respostas viram uma só). Só o export usa.
    sourceQuery?: string;
}

export interface AttackSurfaceSummary {
    totalAssets: number;
    totalServices: number;
    criticalHighFindings: number;
    activelyConfirmedOpen: number;
    byRisk: Record<AttackSurfaceRisk, number>;
    providers: { shodan: boolean };
    warnings: string[];
    totalObserved: number;
}

export interface AttackSurfaceResponse {
    generatedAt: string;
    query: string;
    queryKind: 'host' | 'search';
    limit: number;
    activeValidation: boolean;
    summary: AttackSurfaceSummary;
    findings: AttackSurfaceFinding[];
    warnings: string[];
}

export const fetchAttackSurface = async (input: AttackSurfaceInput): Promise<AttackSurfaceResponse> => {
    const response = await fetch('/api/attack-surface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Attack Surface API error: ${response.status} ${response.statusText} - ${text}`);
    }
    return response.json();
};

export const fetchAttackSurfaceCredits = async (): Promise<ShodanCreditStatus> => {
    const response = await fetch('/api/attack-surface/credits');
    if (!response.ok) throw new Error('Unable to load Shodan credits');
    return response.json();
};

export type ExposureAssetType = 'domain' | 'ip' | 'cidr' | 'asn' | 'shodan_query';
export type ExposureStatus = 'never_run' | 'running' | 'success' | 'error' | 'config_error';
export type ExposureChangeSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ExposureChangeType = 'baseline_created' | 'service_added' | 'service_removed' | 'cve_added'
    | 'cve_removed' | 'risk_increased' | 'risk_decreased' | 'banner_changed' | 'validation_changed';

export interface ExposureSnapshotSummary {
    totalAssets: number;
    totalServices: number;
    criticalHighFindings: number;
    activelyConfirmedOpen: number;
    byRisk: Record<AttackSurfaceRisk, number>;
    highestRisk: AttackSurfaceRisk | null;
}

export interface ExposureAsset {
    id: string; ownerId: string; ownerLogin: string; label: string; type: ExposureAssetType; value: string;
    limit: number; activeValidation: boolean; scheduleEnabled: boolean; createdAt: string; updatedAt: string;
    lastRunAt: string | null; lastStatus: ExposureStatus; lastError: string | null; lastSnapshotId: string | null;
    lastRisk: AttackSurfaceRisk | null; lastSummary: ExposureSnapshotSummary | null;
}

export interface ExposureChange {
    id: string; assetId: string; snapshotId: string; detectedAt: string; severity: ExposureChangeSeverity;
    type: ExposureChangeType; title: string; description: string; ip: string | null; port: number | null;
    transport: 'tcp' | 'udp' | null; previous: unknown; current: unknown;
}

export interface ExposureSnapshot {
    id: string; assetId: string; ownerId: string; startedAt: string; completedAt: string | null;
    status: 'success' | 'error' | 'config_error'; error: string | null; input: AttackSurfaceInput;
    summary: ExposureSnapshotSummary; findings: AttackSurfaceFinding[]; changes: ExposureChange[]; warnings: string[];
}

export interface ExposureAssetInput {
    label: string; type: ExposureAssetType; value: string; limit: number;
    activeValidation: boolean; scheduleEnabled: boolean;
}

const exposureError = async (response: Response): Promise<never> => {
    const body = await response.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `Attack Surface Monitor API error: ${response.status}`);
};

export const fetchExposureAssets = async (): Promise<ExposureAsset[]> => {
    const response = await fetch('/api/exposure-watchlist/assets');
    if (!response.ok) return exposureError(response);
    return (await response.json()).assets;
};

export const createExposureAsset = async (input: ExposureAssetInput): Promise<ExposureAsset> => {
    const response = await fetch('/api/exposure-watchlist/assets', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
    });
    if (!response.ok) return exposureError(response);
    return (await response.json()).asset;
};

export const updateExposureAsset = async (id: string, input: ExposureAssetInput): Promise<ExposureAsset> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
    });
    if (!response.ok) return exposureError(response);
    return (await response.json()).asset;
};

export const deleteExposureAsset = async (id: string): Promise<void> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!response.ok) return exposureError(response);
};

export const runExposureAsset = async (id: string): Promise<{ asset: ExposureAsset; snapshot: ExposureSnapshot }> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}/run`, { method: 'POST' });
    if (!response.ok) return exposureError(response);
    return response.json();
};

export const fetchExposureSnapshots = async (id: string): Promise<ExposureSnapshot[]> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}/snapshots`);
    if (!response.ok) return exposureError(response);
    return (await response.json()).snapshots;
};

export const fetchExposureChanges = async (limit = 100): Promise<ExposureChange[]> => {
    const response = await fetch(`/api/exposure-watchlist/changes?limit=${encodeURIComponent(String(limit))}`);
    if (!response.ok) return exposureError(response);
    return (await response.json()).changes;
};

// ─── Scans salvos (histórico do IOC search, por usuário) ───────────────────
export interface SavedScan {
    id: string; query: string; queryType: string;
    threatLevel: string; score: number; detections: number; totalVendors: number; at: string;
}
export interface SaveScanInput { query: string; queryType?: string; threatLevel?: string; score?: number; detections?: number; totalVendors?: number; }

const scanError = async (r: Response): Promise<never> => {
    const e = await r.json().catch(() => ({}));
    throw new Error((e as { error?: string }).error || `Scans API error: ${r.status}`);
};

export const fetchScans = async (): Promise<SavedScan[]> => {
    const r = await fetch('/api/user/scans');
    if (!r.ok) return scanError(r);
    return (await r.json()).scans;
};

export const saveScan = async (input: SaveScanInput): Promise<SavedScan[]> => {
    const r = await fetch('/api/user/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!r.ok) return scanError(r);
    return (await r.json()).scans;
};

export const deleteScan = async (id: string): Promise<SavedScan[]> => {
    const r = await fetch(`/api/user/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!r.ok) return scanError(r);
    return (await r.json()).scans;
};

// BYOK genérico: quais providers têm chave configurada (booleans, nunca os valores).
export type ApiKeysState = Record<string, boolean>;

export const fetchApiKeys = async (): Promise<ApiKeysState> => {
    try {
        const r = await fetch('/api/user/keys');
        if (!r.ok) return {};
        const d = await r.json();
        return d.keys || {};
    } catch { return {}; }
};

export const saveApiKey = async (provider: string, key: string): Promise<void> => {
    const r = await fetch(`/api/user/keys/${encodeURIComponent(provider)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
    });
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || `Key API error: ${r.status}`);
    }
};

export const deleteApiKey = async (provider: string): Promise<void> => {
    const r = await fetch(`/api/user/keys/${encodeURIComponent(provider)}`, { method: 'DELETE' });
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || `Key API error: ${r.status}`);
    }
};

// ─── Knowledge: fontes curadas ─────────────────────────────────────────────
// O feed é fluxo e some; aqui fica só o que o usuário marcou pra guardar. Cada
// item nasce indexado por técnica/CVE, o que liga a fonte a outros reports.
export interface KnowledgeItem {
    id: string;
    title: string;
    url: string;
    host: string;
    source: string;
    publishedAt: string;
    savedAt: string;
    techniques: string[];
    cves: string[];
    /** Cobertura seguida. Ausente nos itens salvos antes de Seguir existir. */
    storyId?: string;
    /** Veículos no momento em que o usuário seguiu. */
    followedSourceCount?: number;
    /** Veículos agora — derivado na leitura, contra a cobertura ao vivo. */
    sourceCount?: number;
    /** Quantos entraram depois do follow. */
    newSources?: number;
    lastSeen?: string;
}

// O que a tela de origem manda: o servidor normaliza, extrai as técnicas do
// título e une com os CVEs que a origem já conhecia.
export interface KnowledgeInput {
    title: string;
    url: string;
    source?: string;
    publishedAt?: string;
    cves?: string[];
    /** Técnicas inferidas pelo coletor ("T1486" ou "T1486 — Data Encrypted…"). */
    techniques?: string[];
    storyId?: string;
    sourceCount?: number;
}

export const fetchKnowledge = async (): Promise<KnowledgeItem[]> => {
    const r = await fetch('/api/knowledge');
    if (!r.ok) throw new Error(`Knowledge API error: ${r.status}`);
    return (await r.json()).items || [];
};

export const saveKnowledge = async (input: KnowledgeInput): Promise<KnowledgeItem[]> => {
    const r = await fetch('/api/knowledge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || `Knowledge API error: ${r.status}`);
    }
    return (await r.json()).items || [];
};

export const deleteKnowledge = async (id: string): Promise<KnowledgeItem[]> => {
    const r = await fetch(`/api/knowledge/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(`Knowledge API error: ${r.status}`);
    return (await r.json()).items || [];
};

export const fetchJobRelated = async (id: string): Promise<{ reports: BoletimJob[] }> =>
    handleResponse(await fetch(`/api/feed/job/${encodeURIComponent(id)}/related`), 'Related');

// ─── Contexto da organização ───────────────────────────────────────────────
export interface OrgAsset { vendor: string; product: string; }

export interface OrgProfile {
    id: string;
    name: string;
    sectors: string[];
    regions: string[];
    assets: OrgAsset[];
    // Marcas e domínios da organização. São os termos que a vigilância de
    // phishing procura no urlscan; perfil sem marca não é vigiado.
    brands: string[];
    ot: { present: boolean; vendors: string[]; protocols: string[] };
    actors: string[];
    createdAt: string;
    updatedAt: string;
}

export interface OrgVocab { sectors: string[]; regions: string[]; }
export interface OrgAssetSuggestion { vendor: string; product: string; versions: string[]; seenOn: string[]; }

const orgError = async (response: Response): Promise<never> => {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Falha na requisição (${response.status})`);
};

const orgJson = async <T>(url: string, init?: RequestInit): Promise<T> => {
    const response = await fetch(url, init);
    if (!response.ok) return orgError(response);
    return response.json();
};

export interface NewsVendor {
    id: string;
    name: string;
    sector: string;
    aliases: string[];
}

export interface NewsMonitoringPreferences {
    mode: 'all' | 'selected';
    vendorIds: string[];
    updatedAt: string | null;
}

export interface NewsMonitoring {
    vendors: NewsVendor[];
    preferences: NewsMonitoringPreferences;
}

export const fetchNewsMonitoring = (): Promise<NewsMonitoring> => orgJson('/api/news/monitoring');
export const saveNewsMonitoring = (preferences: Pick<NewsMonitoringPreferences, 'mode' | 'vendorIds'>): Promise<{ preferences: NewsMonitoringPreferences }> =>
    orgJson('/api/news/monitoring', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(preferences),
    });

export const fetchOrgVocab = (): Promise<OrgVocab> => orgJson('/api/org/vocab');

export const fetchOrgProfiles = async (): Promise<OrgProfile[]> =>
    (await orgJson<{ profiles: OrgProfile[] }>('/api/org/profiles')).profiles;

const jsonBody = (method: string, profile: Partial<OrgProfile>): RequestInit => ({
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
});

export const createOrgProfile = (profile: Partial<OrgProfile>): Promise<OrgProfile> =>
    orgJson('/api/org/profiles', jsonBody('POST', profile));

export const updateOrgProfile = (id: string, profile: Partial<OrgProfile>): Promise<OrgProfile> =>
    orgJson(`/api/org/profiles/${encodeURIComponent(id)}`, jsonBody('PATCH', profile));

export const deleteOrgProfile = (id: string): Promise<{ ok: boolean }> =>
    orgJson(`/api/org/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });

export const fetchOrgThreatModel = (id: string): Promise<OrgThreatModel> =>
    orgJson(`/api/org/profiles/${encodeURIComponent(id)}/threat-model`);

export const fetchOrgAssetSuggestions = async (): Promise<OrgAssetSuggestion[]> =>
    (await orgJson<{ suggestions: OrgAssetSuggestion[] }>('/api/org/asset-suggestions')).suggestions;

// ─── Vigilância de marca (urlscan) ─────────────────────────────────────────
export type PhishHitStatus = 'new' | 'confirmed' | 'dismissed';

export interface PhishHit {
    id: string;
    profileId: string;
    apexDomain: string;
    domain: string;
    url: string;
    term: string | null;
    apexAgeDays: number | null;
    title: string;
    country: string;
    asn: string;
    ip: string;
    source: string;
    scanUrl: string;
    screenshot: string;
    firstSeen: string;
    lastSeen: string;
    score: number;
    reasons: string[];
    status: PhishHitStatus;
}

export interface PhishRun {
    lastRunAt?: string;
    lastStatus?: 'success' | 'error';
    lastError?: string | null;
    lastFound?: number;
}

export interface PhishHitsResponse {
    configured: boolean;
    hits: PhishHit[];
    run: PhishRun | null;
    intervalMs: number;
}

export const fetchPhishHits = (profileId: string, status?: PhishHitStatus): Promise<PhishHitsResponse> => {
    const params = new URLSearchParams({ profileId });
    if (status) params.set('status', status);
    return orgJson(`/api/phishing-watch/hits?${params}`);
};

export const setPhishHitStatus = (id: string, status: PhishHitStatus): Promise<{ hit: PhishHit }> =>
    orgJson(`/api/phishing-watch/hits/${encodeURIComponent(id)}/status`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }),
    });

export type TicketStatus = 'open' | 'analysis' | 'takedown' | 'down' | 'closed';

export interface TicketEvent { at: string; kind: string; by: string; note: string; }

export interface TakedownTarget { kind: 'hosting' | 'registrar' | 'channel'; email?: string; url?: string; label?: string; name?: string; }

export interface PhishTicket {
    id: string;
    profileId: string;
    apexDomain: string;
    domain: string;
    url: string;
    term: string | null;
    title: string;
    score: number;
    reasons: string[];
    scanUrl: string;
    screenshot: string;
    firstSeen: string;
    status: TicketStatus;
    openedAt: string;
    openedBy: 'auto' | 'manual';
    updatedAt: string;
    reopenedAt?: string;
    evidence: {
        ip: string | null; asn: string | null; country: string | null; capturedAt: string;
        registration: { registrar?: string | null; registeredAt?: string | null; nameservers?: string[]; abuse?: string[] } | null;
        hosting: { network?: string | null; holder?: string | null; abuse?: string[] } | null;
    } | null;
    targets: TakedownTarget[];
    dns: { checkedAt: string | null; aliveAt: string | null; deadAt: string | null };
    events: TicketEvent[];
}

export interface TicketDigest {
    date: string;
    opened: PhishTicket[];
    reopened: PhishTicket[];
    dropped: PhishTicket[];
    aging: PhishTicket[];
    byStatus: Record<string, number>;
    openCount: number;
}

export const fetchPhishTickets = (profileId: string, status?: string): Promise<{ tickets: PhishTicket[]; digest: TicketDigest }> => {
    const params = new URLSearchParams({ profileId });
    if (status) params.set('status', status);
    return orgJson(`/api/phishing-watch/tickets?${params}`);
};

export const fetchPhishTicket = (id: string): Promise<{ ticket: PhishTicket; takedown: { pt: string; en: string } }> =>
    orgJson(`/api/phishing-watch/tickets/${encodeURIComponent(id)}`);

export const setPhishTicketStatus = (id: string, status: TicketStatus, note = ''): Promise<{ ticket: PhishTicket }> =>
    orgJson(`/api/phishing-watch/tickets/${encodeURIComponent(id)}/status`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status, note }),
    });

export const runPhishWatch = (profileId: string): Promise<{ found: number; scanned: number; hits: PhishHit[]; run: PhishRun }> =>
    orgJson('/api/phishing-watch/run', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profileId }),
    });

/** Cota restante por base (faixa abaixo da barra de busca). Exige sessão. */
export interface VendorQuota {
    name: string;
    /** ok = tem número · pending = só depois da primeira busca · none = base sem cota */
    state: 'ok' | 'unconfigured' | 'none' | 'pending' | 'error';
    used?: number | null;
    limit?: number | null;
    remaining?: number | null;
    period?: 'day' | 'month';
    resetAt?: string | null;
    error?: string;
}

export const fetchVendorQuotas = (): Promise<{ quotas: VendorQuota[] }> => orgJson('/api/vendors/quotas');

// Bases que o enriquecimento consulta: são as quatro que rotulam família,
// campanha ou grupo. As outras dezessete respondem reputação, e reputação não
// atribui indicador a ninguém.
export interface NewsMention {
    storyId: string;
    title: string;
    source: string;
    link: string;
    pubDate: string;
    actors: string[];
    categories: string[];
}

// Quem já mencionou este indicador no acervo de notícias. Só a layer 3 (os
// laboratórios de pesquisa) tem IOC colhido do corpo, então é de lá que vem.
// Falha aqui não pode derrubar o enriquecimento: menção é acréscimo.
export const fetchNewsMentions = async (ioc: string): Promise<NewsMention[]> => {
    const response = await fetch(`/api/news/mentions?ioc=${encodeURIComponent(ioc)}`);
    if (!response.ok) return [];
    return (await response.json()).mentions || [];
};

export type CorrelationEvidenceType =
    | "cve" | "campaign" | "actor" | "malware" | "ioc-hash" | "ioc-domain" | "ioc-url" | "ioc-ip" | "ttp" | "rare-term";

export interface CorrelationEvidence {
    type: CorrelationEvidenceType;
    value: string;
    sourceLinks: string[];
}

export interface RelatedBySeller {
    storyId: string;
    title: string;
    link: string | null;
}

export interface StoryDetail {
    correlationEvidence: CorrelationEvidence[];
    // Outra história do mesmo vendedor de dark web (handle extraído da frase
    // "an actor using the handle 'X'") — relacionada, NUNCA fundida: vítimas
    // diferentes continuam sendo notícias diferentes (ver server/darkWebHandle.js).
    relatedBySeller: RelatedBySeller[];
}

// Por que o servidor agrupou estas fontes numa história só, e quais outras
// histórias compartilham o mesmo vendedor de dark web — calculado sob demanda
// (não no feed plano, que tem ~1200 itens por refresh) quando o usuário
// expande um card com mais de uma fonte. Falha aqui não pode escalar: o card
// já mostra a timeline de fontes sem isto, é só a explicação que falta.
export const fetchStoryDetail = async (storyId: string): Promise<StoryDetail> => {
    const empty: StoryDetail = { correlationEvidence: [], relatedBySeller: [] };
    const response = await fetch(`/api/news/stories/${encodeURIComponent(storyId)}`);
    if (!response.ok) return empty;
    const data = await response.json();
    return { correlationEvidence: data.correlationEvidence || [], relatedBySeller: data.relatedBySeller || [] };
};

export interface NewsArchiveRow {
    link: string;
    title: string;
    source: string;
    pubDate: string;
    categories: string[];
    primaryCategory: string | null;
    phishingTechniques: string[];
    archivedAt: string;
}

export interface PhishingEvidence {
    kind: string; label: string; field: 'title' | 'summary' | 'body'; term: string; snippet: string;
}
export interface PhishingTtp {
    id: string; name: string; tactics: string[]; basis: 'reported' | 'inferred'; reason: string;
}
export interface PhishingReport extends NewsArchiveRow {
    id: string; description: string; groupId: string;
    groupBasis: 'named-campaign' | 'correlated-story' | 'publication'; campaignName: string;
    primaryTechnique: string | null; vectors: string[]; sectors: string[]; regions: string[];
    brands: string[]; actorNames: string[]; software: string[]; nationState: 'reported' | 'unknown';
    ttps: PhishingTtp[]; evidence: PhishingEvidence[]; sourceType: string;
    profileMatches: { profileId: string; profileName: string; reasons: string[] }[];
}
export interface PhishingCampaign {
    id: string; name: string; basis: PhishingReport['groupBasis']; firstPublished: string;
    lastPublished: string; reportCount: number; description: string; techniques: string[];
    vectors: string[]; brands: string[]; sectors: string[]; regions: string[]; actors: string[];
    software: string[]; ttpIds: string[]; sources: string[]; links: string[]; reportIds: string[];
}
export interface PhishingFilters {
    search?: string; technique?: string; sector?: string; region?: string; brand?: string;
    profileId?: string; nationState?: string;
}
export interface PhishingDataset {
    reports: PhishingReport[]; campaigns: PhishingCampaign[]; total: number; truncated: boolean;
    range: { from?: string; to?: string }; filters: PhishingFilters;
    facets: { techniques: string[]; sectors: string[]; regions: string[]; brands: string[]; profiles: { id: string; name: string }[] };
    summary: {
        publications: number; groups: number; correlatedGroups: number; withTechnique: number;
        nationState: number; brazil: number; distinctTtps: number;
        months: { label: string; count: number }[]; techniques: { label: string; count: number }[];
        sectors: { label: string; count: number }[]; regions: { label: string; count: number }[];
        sources: { label: string; count: number }[];
    };
    ttps: { id: string; name: string; tactics: string[]; reports: number; groups: number; reported: number; inferred: number }[];
}
export const fetchPhishingReports = async (params: PhishingFilters & { from?: string; to?: string; limit?: number } = {}): Promise<PhishingDataset> => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) if (value) query.set(key, String(value));
    const response = await fetch(`/api/phishing/reports?${query}`);
    if (!response.ok) throw new Error(`Phishing reports API error: ${response.status}`);
    return response.json();
};

// Arquivo permanente do feed (nunca podado, ao contrário do /api/newsletter
// de 10 min e do /api/news/stories de 60 dias). Usado pelo dashboard de
// tendências de phishing e pela exportação em /phishing-analyzer.
export const fetchNewsArchive = async (
    params: { category?: string; source?: string; from?: string; to?: string; limit?: number } = {},
): Promise<{ total: number; rows: NewsArchiveRow[] }> => {
    const query = new URLSearchParams();
    if (params.category) query.set('category', params.category);
    if (params.source) query.set('source', params.source);
    if (params.from) query.set('from', params.from);
    if (params.to) query.set('to', params.to);
    if (params.limit) query.set('limit', String(params.limit));
    const response = await fetch(`/api/news/archive${query.toString() ? `?${query}` : ''}`);
    if (!response.ok) throw new Error(`News archive API error: ${response.status}`);
    return response.json();
};

export const ENRICHMENT_VENDORS = [
    "VirusTotal", "AlienVault OTX", "ThreatFox", "AbuseIPDB",
    // Para hash e URL, estas duas são quem nomeia a família — e família é a
    // ponte até o grupo no catálogo. Num IP elas são descartadas sozinhas pelo
    // resolveVendorsForQuery, então entrar aqui não custa chamada nenhuma.
    "MalwareBazaar", "URLhaus",
];

// Índice família de malware → grupos, do catálogo de atores. É estático e o
// server manda cache de 6h, então uma carga por sessão basta.
export interface ActorIndexes {
    /** família de malware normalizada → grupos que a usam */
    software: Record<string, { id: string; name: string }[]>;
    /** nome ou alias normalizado → nome canônico do ator */
    names: Record<string, string>;
}

export const fetchSoftwareIndex = async (): Promise<ActorIndexes> => {
    const response = await fetch('/api/actors/software-index');
    if (!response.ok) throw new Error('software index unavailable');
    const body = await response.json();
    return { software: body.index || {}, names: body.names || {} };
};
