import { ExternalLink, Shield, BookOpen } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { VENDOR_IOC_SUPPORT } from "@/services/threatApi";
import { Badge } from "@/components/ui/badge";
import { Header } from "@/components/Header";
import { useLanguage } from "@/contexts/LanguageContext";

const VENDOR_INFO: Record<string, { description: string; docLink: string }> = {
    "VirusTotal": {
        description: "Analyze suspicious files, domains, IPs and URLs to detect malware and other breaches.",
        docLink: "https://docs.virustotal.com/reference/overview"
    },
    "AbuseIPDB": {
        description: "A project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet.",
        docLink: "https://docs.abuseipdb.com/"
    },
    "AlienVault OTX": {
        description: "Open Threat Exchange is the world's first truly open threat intelligence community that enables collaborative defense with actionable, community-powered threat data.",
        docLink: "https://otx.alienvault.com/api"
    },
    "Shodan": {
        description: "Search engine for Internet-connected devices. Discover which of your devices are connected to the Internet, where they are located, and who is using them.",
        docLink: "https://developer.shodan.io/api"
    },
    "URLhaus": {
        description: "A project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
        docLink: "https://urlhaus-api.abuse.ch/"
    },
    "MalwareBazaar": {
        description: "A project from abuse.ch with the goal of sharing malware samples with the infosec community, AV vendors, and threat intelligence providers.",
        docLink: "https://bazaar.abuse.ch/api/"
    },
    "Google Safe Browsing": {
        description: "Google's Safe Browsing service provides lists of URLs for web resources that contain malware or phishing content.",
        docLink: "https://developers.google.com/safe-browsing/v4"
    },
    "PhishTank": {
        description: "PhishTank is a collaborative clearing house for data and information about phishing on the Internet.",
        docLink: "https://www.phishtank.com/developer_info.php"
    },
    "Pulsedive": {
        description: "Pulsedive is a free threat intelligence platform that allows you to search, scan, and enrich IPs, URLs, and domains.",
        docLink: "https://pulsedive.com/api/"
    },
    "Hybrid Analysis": {
        description: "Free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology.",
        docLink: "https://www.hybrid-analysis.com/docs/api/v2"
    },
    "CIRCL hashlookup": {
        description: "A public service to lookup hash values against known malicious files.",
        docLink: "https://hashlookup.circl.lu/"
    },
    "Criminal IP": {
        description: "Cyber Threat Intelligence (CTI) search engine that monitors open ports of IP addresses around the world.",
        docLink: "https://www.criminalip.io/developer/api-docs"
    },
    "MetaDefender": {
        description: "Advanced threat prevention and detection platform.",
        docLink: "https://docs.opswat.com/mdcloud/metadefender-cloud-api-v4"
    },
    "PhishStats": {
        description: "Phishing statistics and threat intelligence data.",
        docLink: "https://phishstats.info/"
    },
    "Ransomware.live": {
        description: "Tracking ransomware groups and their victims.",
        docLink: "https://www.ransomware.live/api"
    },
    "WHOIS": {
        description: "Query databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block or an autonomous system.",
        docLink: "https://en.wikipedia.org/wiki/WHOIS"
    },
    "IP Geolocation": {
        description: "Identification of the geographic location of a device, such as a computer, mobile phone, or router, using its IP address.",
        docLink: "https://ip-api.com/docs"
    }
};

const VendorDirectory = () => {
    const vendors = Object.entries(VENDOR_IOC_SUPPORT).sort((a, b) => a[0].localeCompare(b[0]));

    const { t } = useLanguage();

    return (
        <div className="min-h-screen bg-background flex flex-col">
            <Header showBackButton />
            <div className="flex-1 p-4 md:p-8">
                <div className="max-w-7xl mx-auto space-y-8">
                    <div>
                        <h1 className="text-3xl font-bold">Vendor Directory</h1>
                        <p className="text-muted-foreground mt-1">
                            Integrated threat intelligence sources and their capabilities
                        </p>
                    </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {vendors.map(([name, types]) => (
                        <div key={name} className="p-6 rounded-xl border bg-card shadow-sm hover:shadow-md transition-all flex flex-col h-full">
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <Shield className="h-5 w-5 text-primary" />
                                    <h3 className="font-semibold text-lg">{name}</h3>
                                </div>
                                {VENDOR_INFO[name]?.docLink && (
                                    <a
                                        href={VENDOR_INFO[name].docLink}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-muted-foreground hover:text-primary transition-colors"
                                        title="View Documentation"
                                    >
                                        <ExternalLink className="h-4 w-4" />
                                    </a>
                                )}
                            </div>

                            <div className="flex-1 space-y-4">
                                <p className="text-sm text-muted-foreground">
                                    {VENDOR_INFO[name]?.description || "No description available."}
                                </p>

                                <div>
                                    <p className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">Supported IOC Types</p>
                                    <div className="flex flex-wrap gap-2">
                                        {types.map(type => (
                                            <Badge key={type} variant="secondary" className="uppercase text-xs">
                                                {type}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    </div>
    );
};

export default VendorDirectory;
