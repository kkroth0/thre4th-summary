/// <reference types="vite/client" />
import { ThreatIntelligenceResult, VendorData, TimelineEvent } from "@/types/threat-intelligence";

// Helper to handle response
const handleResponse = async (response: Response, vendorName: string) => {
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${vendorName} API error: ${response.status} ${response.statusText} - ${errorText}`);
    }
    return response.json();
};

// Detect IOC type from query
export const detectIOCType = (query: string): 'ip' | 'domain' | 'hash' | 'url' => {
    if (query.startsWith('http://') || query.startsWith('https://')) return 'url';
    if (/^[a-fA-F0-9]{32}$/.test(query)) return 'hash'; // MD5
    if (/^[a-fA-F0-9]{40}$/.test(query)) return 'hash'; // SHA1
    if (/^[a-fA-F0-9]{64}$/.test(query)) return 'hash'; // SHA256
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query)) return 'ip';
    return 'domain';
};

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
    "Pulsedive": ['ip', 'domain', 'hash', 'url'],
    "Hybrid Analysis": ['hash'],
    "CIRCL hashlookup": ['hash'],
    "Criminal IP": ['ip', 'domain'],
    "MetaDefender": ['ip', 'hash', 'domain', 'url'],
    "PhishStats": ['url', 'domain'],
    "OpenPhish": ['url', 'domain'],
    "Team Cymru": ['ip', 'hash'],
    "Censys": ['ip'],
    // Intentionally excluded from per-IOC routing:
    //  - "Ransomware.live": recent-victims feed, ignores the query entirely.
    //  - "Google Safe Browsing": no backend endpoint implemented yet (would 404).
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
                    "First Seen": tf.first_seen || "Unknown",
                    "Last Seen": tf.last_seen || "Unknown",
                };
            }
            return { "Status": "No data" };
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
        case "Pulsedive": {
            if (data.error || (!data.risk && !data.iid)) return { "Status": "No data" };
            const pdRisk = (data.risk || "unknown").toLowerCase();
            const pdStatus = ["critical", "high"].includes(pdRisk) ? "Malicious"
                : pdRisk === "medium" ? "Suspicious"
                : pdRisk === "none" || pdRisk === "low" ? "Clean" : "Unknown";
            return {
                "Status": pdStatus,
                "Risk": data.risk || "Unknown",
                "Risk (recommended)": data.risk_recommended || "Unknown",
                "Type": data.type || "Unknown",
                "Threats": Array.isArray(data.threats) ? data.threats.slice(0, 5).map((t: any) => typeof t === 'string' ? t : t.name || t.type || 'Unknown').join(", ") : "None",
                "Feeds": data.feeds?.length || 0,
                "First Seen": data.stamp_added || "Unknown",
                "Last Seen": data.stamp_seen || data.stamp_updated || "Unknown",
            };
        }



        case "Hybrid Analysis":
            if (Array.isArray(data) && data.length > 0) {
                const ha = data[0];
                const haTags = Array.from(new Set(data.flatMap((d: any) => Array.isArray(d.classification_tags) ? d.classification_tags : [])));
                const mitre = Array.isArray(ha.mitre_attcks) ? ha.mitre_attcks.map((m: any) => m.technique || m.attck_id).filter(Boolean) : [];
                return {
                    "Status": ha.verdict === "malicious" ? "Malicious" : ha.verdict === "suspicious" ? "Suspicious" : (ha.verdict || "Unknown"),
                    "Verdict": ha.verdict || "Unknown",
                    "Malware Family": ha.vx_family || "N/A",
                    "Threat Score": ha.threat_score != null ? `${ha.threat_score}/100` : "N/A",
                    "Threat Level": ha.threat_level != null ? String(ha.threat_level) : "N/A",
                    "AV Detect": ha.av_detect != null ? `${ha.av_detect}%` : "N/A",
                    "File Type": ha.type_short || ha.type || "Unknown",
                    "Submission": ha.submit_name || "Unknown",
                    "Signatures": ha.total_signatures != null ? ha.total_signatures : "N/A",
                    "MITRE ATT&CK": mitre.slice(0, 6).join(", ") || "None",
                    "Classification": haTags.slice(0, 6).join(", ") || "None",
                    "Analyzed": ha.analysis_start_time || "Unknown",
                    "Reports": data.length,
                };
            }
            return { "Status": "No analysis found" };
        case "CIRCL hashlookup":
            return {
                "Status": "Found in database",
                "File Name": data.FileName || "Unknown",
                "File Size": data.FileSize || "Unknown",
            };
        case "Criminal IP": {
            // Criminal IP returns `issues` as an OBJECT of booleans (is_vpn, is_tor…),
            // not an array, and `score` as {inbound, outbound}. The card renderer
            // expects Score/Issues/Classification/VPN/Proxy/Tor/Cloud, so map to those.
            const ciIssues = (data.issues && typeof data.issues === "object") ? data.issues : {};
            const ciScoreRaw = typeof data.score === "object" ? (data.score?.inbound ?? data.score?.outbound ?? 0) : (data.score ?? 0);
            const ciScore = typeof ciScoreRaw === "number" ? ciScoreRaw : (parseInt(ciScoreRaw) || 0);
            const ciIssueCount = Object.values(ciIssues).filter(Boolean).length;
            const ciMalicious = data.is_malicious || ciIssues.is_malicious;
            return {
                "Score": ciScore,
                "Issues": ciIssueCount,
                "Classification": ciMalicious ? "Malicious" : ciIssueCount ? "Suspicious" : "Clean",
                "VPN": ciIssues.is_vpn ? "Yes" : "No",
                "Proxy": ciIssues.is_proxy ? "Yes" : "No",
                "Tor": ciIssues.is_tor ? "Yes" : "No",
                "Cloud": ciIssues.is_cloud ? "Yes" : "No",
                "Status": ciMalicious ? "Malicious" : "Clean",
            };
        }
        case "MetaDefender": {
            if (data.scan_results) {
                return {
                    "Detection Rate": `${data.scan_results?.total_detected_avs}/${data.scan_results?.total_avs}`,
                    "Status": data.scan_results?.total_detected_avs > 0 ? "Malicious" : "Clean",
                    "Threat": data.scan_results?.scan_all_result_a || "Unknown",
                };
            }
            const mdLr = data.lookup_results || {};
            const mdFlagged = Array.isArray(mdLr.sources)
                ? mdLr.sources.filter((s: any) => s.assessment && /mali|susp|phish|black|spam|botnet/i.test(s.assessment))
                : [];
            return {
                "Status": (mdLr.detected_by || 0) > 0 ? "Flagged" : "Clean",
                "Detected By": `${mdLr.detected_by || 0} source${(mdLr.detected_by || 0) === 1 ? "" : "s"}`,
                "Flagged By": mdFlagged.length ? mdFlagged.map((s: any) => s.provider).slice(0, 5).join(", ") : "None",
                "Geo Location": [data.geo_info?.city?.name, data.geo_info?.country?.name].filter(Boolean).join(", ") || "Unknown",
            };
        }
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

        case "Shodan": {
            // Domain queries hit /dns/domain — a different shape (subdomains + DNS records).
            if (data.subdomains || (Array.isArray(data.data) && data.data[0]?.subdomain !== undefined)) {
                const records = Array.isArray(data.data) ? data.data : [];
                const byType = (t: string) => records.filter((r: any) => r.type === t);
                return {
                    "Status": records.length > 0 ? "DNS Records Found" : "No DNS data",
                    "Subdomains": Array.isArray(data.subdomains) ? data.subdomains.length : 0,
                    "Subdomain List": Array.isArray(data.subdomains) ? data.subdomains.slice(0, 25) : [],
                    "A Records": byType("A").map((r: any) => `${r.subdomain || "@"} → ${r.value}`).slice(0, 10).join(", ") || "None",
                    "MX Records": byType("MX").map((r: any) => r.value).slice(0, 5).join(", ") || "None",
                    "NS Records": byType("NS").map((r: any) => r.value).slice(0, 5).join(", ") || "None",
                    "TXT Records": byType("TXT").length,
                    "Total Records": records.length,
                    "Tags": Array.isArray(data.tags) ? data.tags.join(", ") : "None",
                };
            }
            const banners = Array.isArray(data.data) ? data.data : [];
            // The actual CVE list, not just a count. Shodan keys data.vulns by CVE id.
            const hostVulns = data.vulns ? Object.keys(data.vulns) : [];
            // Per-service banner detail, mirroring the Censys "Services Detail" shape.
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
            const location = [data.city, data.region_code, data.country_name].filter(Boolean).join(", ");
            return {
                "Open Ports": data.ports?.slice(0, 12).join(", ") || "None",
                "Total Ports": data.ports?.length || 0,
                "Services": banners.slice(0, 5).map((d: any) => d.product || `${d.port}/${d.transport || 'tcp'}`).join(", ") || "Unknown",
                "Organization": data.org || "Unknown",
                "Hostnames": data.hostnames?.slice(0, 5).join(", ") || "None",
                "Domains": data.domains?.slice(0, 5).join(", ") || "None",
                "OS": data.os || "Unknown",
                "Location": location || "Unknown",
                "Last Update": data.last_update || "Unknown",
                "ASN": data.asn || "Unknown",
                "ISP": data.isp || "Unknown",
                "Vulnerabilities": `${hostVulns.length} CVEs`,
                "Vulnerability List": hostVulns,
                "Tags": data.tags?.slice(0, 8).join(", ") || "None",
                "Services Detail": servicesDetail,
            };
        }
        case "Censys": {
            const censysData = data.data || data;
            if (censysData.Status) return censysData;
            const services = censysData.services || [];
            const openPorts = services.map((s: any) => `${s.port}/${s.transport}`).join(", ") || "None";
            const softwareList = services
                .filter((s: any) => s.software)
                .map((s: any) => `${s.software}${s.software_version ? ' ' + s.software_version : ''} (${s.port}/${s.transport})`)
                .join(", ") || "None detected";
            const tlsServices = services.filter((s: any) => s.tls_version);
            const certServices = services.filter((s: any) => s.certificate_subject);
            const httpServices = services.filter((s: any) => s.http_status || s.http_title);

            // Aggregate CVEs reported across all services.
            const allVulns = Array.from(new Set(
                services.flatMap((s: any) => Array.isArray(s.vulnerabilities) ? s.vulnerabilities : [])
            ));

            const result: Record<string, any> = {
                "Open Ports": openPorts,
                "Service Count": censysData.service_count || services.length,
                "Software": softwareList,
            };

            if (Array.isArray(censysData.labels) && censysData.labels.length > 0) {
                result["Labels"] = censysData.labels.join(", ");
            }
            if (censysData.operating_system) result["Operating System"] = censysData.operating_system;
            if (allVulns.length > 0) {
                result["Vulnerabilities"] = `${allVulns.length} CVEs`;
                result["Vulnerability List"] = allVulns;
            }
            if (Array.isArray(censysData.dns_names) && censysData.dns_names.length > 0) {
                result["Reverse DNS"] = censysData.dns_names.slice(0, 5).join(", ");
            }
            if (censysData.last_updated) result["Last Scanned"] = censysData.last_updated;

            // HTTP fingerprint
            if (httpServices.length > 0) {
                const httpSvc = httpServices[0];
                result["HTTP Status"] = httpSvc.http_status ? String(httpSvc.http_status) : "N/A";
                result["HTML Title"] = httpSvc.http_title || "N/A";
                if (httpSvc.http_body_hash) result["Body Hash"] = httpSvc.http_body_hash;
            }

            // TLS fingerprint
            if (tlsServices.length > 0) {
                result["TLS Version"] = tlsServices.map((s: any) => `${s.tls_version} (${s.port})`).join(", ");
            }

            // Certificate fingerprint
            if (certServices.length > 0) {
                const cert = certServices[0];
                result["Certificate Subject"] = cert.certificate_subject || "N/A";
                result["Certificate Issuer"] = cert.certificate_issuer || "N/A";
                if (cert.certificate_fingerprint) result["Cert Fingerprint"] = cert.certificate_fingerprint;
                if (cert.certificate_names && cert.certificate_names.length > 0) {
                    result["Certificate Names"] = cert.certificate_names.slice(0, 8).join(", ") + (cert.certificate_names.length > 8 ? ` (+${cert.certificate_names.length - 8} more)` : "");
                }
                if (cert.certificate_trusted !== null) {
                    result["Browser Trust"] = cert.certificate_trusted ? "Trusted" : "Not Trusted";
                }
            }

            // ASN
            if (censysData.autonomous_system) {
                result["ASN"] = `AS${censysData.autonomous_system.asn} - ${censysData.autonomous_system.name}`;
                if (censysData.autonomous_system.bgp_prefix) result["BGP Prefix"] = censysData.autonomous_system.bgp_prefix;
            }

            // Location
            if (censysData.location) {
                result["Location"] = [censysData.location.city, censysData.location.province, censysData.location.country].filter(Boolean).join(", ");
            }

            // Services detail (for expanded vendor card)
            result["Services Detail"] = services.map((s: any) => ({
                port: s.port,
                protocol: s.protocol,
                transport: s.transport,
                software: s.software,
                version: s.software_version,
                os: s.os,
                labels: Array.isArray(s.labels) ? s.labels : [],
                http_status: s.http_status,
                http_title: s.http_title,
                http_server: s.http_server,
                vulns: Array.isArray(s.vulnerabilities) ? s.vulnerabilities : [],
            }));

            return result;
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
                    "Proxy/VPN": data.proxy ? "Yes ⚠️" : "No",
                    "Hosting": data.hosting ? "Yes" : "No",
                    "Mobile": data.mobile ? "Yes" : "No",
                    "Reverse Hostname": data.reverseHostname || "Unknown",
                    "Latitude": data.lat !== undefined ? String(data.lat) : "Unknown",
                    "Longitude": data.lon !== undefined ? String(data.lon) : "Unknown"
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
        case "Team Cymru": return `https://team-cymru.com/community-services/ip-asn-mapping/`;
        case "Censys": return `https://search.censys.io/hosts/${query}`;
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
            case "Censys": {
                const c = data.data || data;
                pushEvent(e, v, "Last scanned", c.last_updated, "analysis");
                break;
            }
            case "Pulsedive": {
                pushEvent(e, v, "First seen", data.stamp_added, "first_seen");
                pushEvent(e, v, "Last seen", data.stamp_seen, "last_seen");
                pushEvent(e, v, "Updated", data.stamp_updated, "other");
                break;
            }
            case "Hybrid Analysis": {
                (Array.isArray(data) ? data : []).slice(0, 5).forEach((d: any) => pushEvent(e, v, `Analyzed: ${d.vx_family || d.submit_name || "sample"}`, d.analysis_start_time, "analysis"));
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
export const fetchTeamCymruData = (query: string) => fetchFromBackend('teamcymru', query, "Team Cymru");
export const fetchCensysData = (query: string) => fetchFromBackend('censys', query, "Censys");

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

export const checkDNSBLBatch = async (ip: string, providers: string[]): Promise<Record<string, { listed: boolean; addresses?: string[]; status: string; error?: string }>> => {
    try {
        const response = await fetch('/api/dnsbl/batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: ip, providers })
        });
        if (!response.ok) throw new Error("API Error");
        return await response.json();
    } catch (error) {
        const fallback: Record<string, { listed: boolean; addresses?: string[]; status: string; error?: string }> = {};
        providers.forEach(p => {
            fallback[p] = { listed: false, status: "Error", error: (error as Error).message };
        });
        return fallback;
    }
};

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
    "Team Cymru": () => fetchTeamCymruData(query),
    "Censys": () => fetchCensysData(query),
});

// Resolve which vendors to actually query: the explicit selection (or all known
// vendors), narrowed to those that both exist in the map and support this IOC type.
const resolveVendorsToQuery = (
    vendorMap: Record<string, () => Promise<VendorData>>,
    selectedVendors: string[] | undefined,
    iocType: ReturnType<typeof detectIOCType>,
): string[] =>
    (selectedVendors || Object.keys(vendorMap))
        .filter(vendor => {
            const supportedTypes = VENDOR_IOC_SUPPORT[vendor];
            return supportedTypes && supportedTypes.includes(iocType);
        })
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
    const iocType = detectIOCType(query);
    const vendorsToQuery = resolveVendorsToQuery(vendorMap, selectedVendors, iocType);

    const results = await Promise.all(vendorsToQuery.map(vendor => vendorMap[vendor]()));
    return scoreThreatResults(query, results);
};

export const fetchThreatDataProgressive = async (
    query: string,
    selectedVendors: string[] | undefined,
    onProgress: (data: VendorData) => void
): Promise<ThreatIntelligenceResult> => {
    const vendorMap = buildVendorMap(query);
    const iocType = detectIOCType(query);
    const vendorsToQuery = resolveVendorsToQuery(vendorMap, selectedVendors, iocType);

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
export type DeckType = 'vuln' | 'campaign';

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
    generated_at?: string;
    tlp?: string;
    titulo?: string;
    sumario_executivo?: string;
    descricao?: string;
    impactos?: string[];
    cve_id?: string;
    tecnologias_afetadas?: {
        fabricante?: string; software?: string; versao?: string; cve?: string;
        cvss?: string; severidade?: string; cwe?: string; kev?: boolean;
    }[];
    superficie_de_ataque?: { categoria?: string; tecnologia?: string; utilizacao?: string }[];
    ator?: {
        threat_actor?: string; tipo?: string; motivation?: string;
        sectors?: string[]; diferencial?: string; onion?: string[];
    };
    recomendacoes?: { titulo?: string; itens?: string[] }[];
    iocs?: { categoria?: string; tipo?: string; valor?: string }[];
    mitre_ttps?: { id?: string; nome?: string; tatica?: string; descricao?: string; contexto?: string; url?: string }[];
    referencias_coletadas?: { titulo?: string; url?: string }[];
}

// 1 URL = 1 boletim: o front pede a geração de uma URL; o worker na VPS gera o
// JSON e devolve. O front faz poll do job até ficar pronto e baixa o JSON.
export interface BoletimJob {
    id: string;
    url: string;
    type: DeckType;
    title: string;
    status: 'pending' | 'done' | 'error';
    json: BoletimReport | null;
    error: string | null;
    createdAt: string;
    updatedAt: string;
    queuePosition?: number;   // quantos jobs pending estão à frente deste (0 = próximo)
}

export const generateBoletim = async (url: string, type: DeckType, title = ''): Promise<{ id: string; status: string }> => {
    const r = await fetch('/api/feed/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, type, title }),
    });
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || `Generate API error: ${r.status}`);
    }
    return r.json();
};

export const fetchJob = async (id: string): Promise<BoletimJob> => {
    const r = await fetch(`/api/feed/job?id=${encodeURIComponent(id)}`);
    if (!r.ok) throw new Error(`Job API error: ${r.status}`);
    return r.json();
};

export interface RansomwareVictim {
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

export interface LatamThreats {
    generatedAt: string;
    sources: string[];
    victims: RansomwareVictim[];
    groups: CountItem[];
    sectors: CountItem[];
    countries: CountItem[];
    threatFox: {
        count: number;
        malware: CountItem[];
        iocs: ThreatFoxRecentIoc[];
    };
}

export interface ThreatMapData {
    generatedAt: string;
    windowDays: number;
    source: string;
    victims: RansomwareVictim[];
    countries: CountItem[];
    groups: CountItem[];
    topCountry: CountItem | null;
    activeGroups: number;
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

export const fetchLatamThreats = async (): Promise<LatamThreats> => {
    const r = await fetch('/api/intel/latam-threats');
    if (!r.ok) return intelError(r);
    return r.json();
};

export const fetchThreatMap = async (days = 90): Promise<ThreatMapData> => {
    const r = await fetch(`/api/intel/threat-map?days=${days}`);
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
export interface FeedHealth { ok: boolean; count: number; error: string | null; at: string; }
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

// Attack Surface: Shodan-led external exposure search with optional Censys and TCP validation.
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
    activeValidation: boolean;
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
    source: { shodan: boolean; censys: boolean };
    observedAt: string | null;
    cves: string[];
    tags: string[];
    bannerSnippet: string | null;
    validation: {
        attempted: boolean;
        status: AttackSurfaceValidationStatus;
        detail: string | null;
    };
}

export interface AttackSurfaceSummary {
    totalAssets: number;
    totalServices: number;
    criticalHighFindings: number;
    activelyConfirmedOpen: number;
    byRisk: Record<AttackSurfaceRisk, number>;
    providers: { shodan: boolean; censys: boolean };
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
    throw new Error((body as { error?: string }).error || `Exposure Watchlist API error: ${response.status}`);
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

// ─── Publicações / Advisories (blog) ───────────────────────────────────────
export interface Post {
    id: string; slug: string; title: string; summary: string; body: string;
    tags: string[]; author: string; published: boolean;
    createdAt: string; updatedAt: string; publishedAt: string | null;
}
export type PostCard = Omit<Post, "body">;
export interface PostInput { title: string; summary?: string; body?: string; tags?: string[]; published?: boolean; slug?: string; }

const postError = async (r: Response): Promise<never> => {
    const e = await r.json().catch(() => ({}));
    throw new Error((e as { error?: string }).error || `Posts API error: ${r.status}`);
};

export const fetchPosts = async (): Promise<{ posts: PostCard[]; isAdmin: boolean }> => {
    const r = await fetch('/api/posts');
    if (!r.ok) return postError(r);
    return r.json();
};

export const fetchPost = async (slug: string): Promise<{ post: Post; isAdmin: boolean }> => {
    const r = await fetch(`/api/posts/${encodeURIComponent(slug)}`);
    if (!r.ok) return postError(r);
    return r.json();
};

export const createPost = async (input: PostInput): Promise<Post> => {
    const r = await fetch('/api/posts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!r.ok) return postError(r);
    return (await r.json()).post;
};

export const updatePost = async (id: string, input: Partial<PostInput>): Promise<Post> => {
    const r = await fetch(`/api/posts/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!r.ok) return postError(r);
    return (await r.json()).post;
};

export const deletePost = async (id: string): Promise<void> => {
    const r = await fetch(`/api/posts/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!r.ok) return postError(r);
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
    await fetch(`/api/user/keys/${encodeURIComponent(provider)}`, { method: 'DELETE' }).catch(() => {});
};
