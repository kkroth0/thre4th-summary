import { useState, useMemo, useEffect } from "react";
import { ExternalLink, Shield, Search, SlidersHorizontal, BookOpen, Globe } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { VENDOR_IOC_SUPPORT } from "@/services/threatApi";
import { Badge } from "@/components/ui/badge";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";

const VENDOR_INFO: Record<string, { description: string; docLink: string; domain: string }> = {
    "VirusTotal": {
        description: "Analyze suspicious files, domains, IPs and URLs to detect malware and other breaches.",
        docLink: "https://docs.virustotal.com/reference/overview",
        domain: "virustotal.com"
    },
    "AbuseIPDB": {
        description: "A project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet.",
        docLink: "https://docs.abuseipdb.com/",
        domain: "abuseipdb.com"
    },
    "AlienVault OTX": {
        description: "Open Threat Exchange is the world's first open threat intelligence community for collaborative defense.",
        docLink: "https://otx.alienvault.com/api",
        domain: "alienvault.com"
    },
    "Shodan": {
        description: "Search engine for Internet-connected devices. Discover device types, location, and active service banners.",
        docLink: "https://developer.shodan.io/api",
        domain: "shodan.io"
    },
    "URLhaus": {
        description: "A project from abuse.ch sharing malicious URLs that are actively used for malware distribution.",
        docLink: "https://urlhaus-api.abuse.ch/",
        domain: "abuse.ch"
    },
    "MalwareBazaar": {
        description: "A project from abuse.ch sharing verified malware samples with infosec teams and security products.",
        docLink: "https://bazaar.abuse.ch/api/",
        domain: "abuse.ch"
    },
    "PhishTank": {
        description: "PhishTank is a collaborative clearing house for sharing and verifying phishing data on the web.",
        docLink: "https://www.phishtank.com/developer_info.php",
        domain: "phishtank.com"
    },
    "Pulsedive": {
        description: "A community-driven threat intelligence platform allowing user search, scanning, and IOC enrichment.",
        docLink: "https://pulsedive.com/api/",
        domain: "pulsedive.com"
    },
    "Hybrid Analysis": {
        description: "Free malware analysis service that detects and analyzes threats using Hybrid Analysis sandboxing.",
        docLink: "https://www.hybrid-analysis.com/docs/api/v2",
        domain: "hybrid-analysis.com"
    },
    "CIRCL hashlookup": {
        description: "A public lookup database matching hash values against known benign and malicious software files.",
        docLink: "https://hashlookup.circl.lu/",
        domain: "circl.lu"
    },
    "MetaDefender": {
        description: "Advanced malware prevention cloud sandbox and multiscanning platform by OPSWAT.",
        docLink: "https://docs.opswat.com/mdcloud/metadefender-cloud-api-v4",
        domain: "opswat.com"
    },
    "PhishStats": {
        description: "Phishing statistics database and real-time public CTI feed provider.",
        docLink: "https://phishstats.info/",
        domain: "phishstats.info"
    },
    "WHOIS": {
        description: "Query databases storing registered assignees, creation dates, and network registrars for domain assets.",
        docLink: "https://en.wikipedia.org/wiki/WHOIS",
        domain: "who.is"
    },
    "IP Geolocation": {
        description: "Mapping of numeric IP networks to physical coordinates, ISP owners, regions, and timezone offsets.",
        docLink: "https://ip-api.com/docs",
        domain: "ip-api.com"
    },
    // Estas quatro são consultadas como as outras, mas não tinham verbete: o
    // cartão saía com "Sem descrição." e sem link de documentação.
    "ThreatFox": {
        description: "abuse.ch database of indicators of compromise shared by the community, with malware family attribution.",
        docLink: "https://threatfox.abuse.ch/api/",
        domain: "abuse.ch"
    },
    "OpenPhish": {
        description: "Feed of phishing URLs identified automatically, refreshed several times a day.",
        docLink: "https://openphish.com/faq.html",
        domain: "openphish.com"
    },
    "Team Cymru": {
        description: "IP to ASN mapping and malware hash registry, served over public DNS by Team Cymru.",
        docLink: "https://team-cymru.com/community-services/ip-asn-mapping/",
        domain: "team-cymru.com"
    },
    "Censys": {
        description: "Internet-wide scan data with open ports, certificates, and service banners per host.",
        docLink: "https://docs.censys.com/",
        domain: "censys.io"
    }
};

const VendorDirectory = () => {
    const { t, language } = useLanguage();
    const [searchQuery, setSearchQuery] = useState("");
    const [selectedType, setSelectedType] = useState<string>("ALL");
    const [apiStatuses, setApiStatuses] = useState<Record<string, boolean>>({});
    // EST-04: "verificando" precisa acabar. Sem prazo nem caminho de erro, uma
    // resposta que não chega deixava os 18 cartões pulsando para sempre.
    const [statusFailed, setStatusFailed] = useState(false);

    useEffect(() => {
        fetch("/api/vendors/status", { signal: AbortSignal.timeout(8000) })
            .then(res => res.json())
            .then(data => setApiStatuses(data))
            .catch(err => {
                console.error("Error fetching vendor API statuses:", err);
                setStatusFailed(true);
            });
    }, []);

    const vendorsList = useMemo(() => {
        return Object.entries(VENDOR_IOC_SUPPORT).sort((a, b) => a[0].localeCompare(b[0]));
    }, []);

    // Filter logic
    const filteredVendors = useMemo(() => {
        return vendorsList.filter(([name, types]) => {
            const matchesSearch = name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                (VENDOR_INFO[name]?.description || "").toLowerCase().includes(searchQuery.toLowerCase());
            
            const matchesType = selectedType === "ALL" || types.includes(selectedType as any);

            return matchesSearch && matchesType;
        });
    }, [vendorsList, searchQuery, selectedType]);

    // Unique IOC Types across all vendors
    const iocTypes = ["ALL", "IP", "DOMAIN", "HASH", "URL", "CVE"];
    // O rótulo é traduzido; o valor "ALL" continua sendo a chave do filtro.
    const typeLabel = (type: string) => (type === "ALL" ? (language === 'pt' ? "TODOS" : "ALL") : type);

    const activeCount = Object.values(apiStatuses).filter(Boolean).length;
    const totalCount = Object.keys(apiStatuses).length;

    return (
        <PageLayout width="max-w-6xl">
                <div className="space-y-6">
                    {/* Header bar and stats summary */}
                    <div className="page-head">
                        <div>
                            <h1 className="page-title">
                                {language === 'pt' ? 'Fontes de Dados' : 'Data Sources'}
                            </h1>
                            <p className="page-lede max-w-2xl">
                                {language === 'pt'
                                    ? `As ${vendorsList.length} fontes que alimentam as consultas, o que cada uma cobre e quais estão ativas.`
                                    : `The ${vendorsList.length} sources behind every lookup, what each one covers and which are active.`}
                            </p>
                        </div>
                        <div className="text-xs text-muted-foreground/80 md:text-right space-y-0.5">
                            {/* DEN-07: o único rótulo em inglês que sobrou na tela. DEN-03: o
                                denominador vem do mesmo mapa que pinta os cartões, então bate
                                com o "As N fontes" do subtítulo. */}
                            <div>{language === 'pt' ? "Conectores ativos: " : "Active connectors: "}<span className="text-emerald-500 font-semibold">{totalCount > 0 ? `${activeCount}/${totalCount}` : (language === 'pt' ? "verificando…" : "checking…")}</span></div>
                            <div>{language === 'pt' ? "Cache padrão: " : "Default cache TTL: "}<span className="font-mono">{language === 'pt' ? "30 minutos" : "30 minutes"}</span></div>
                        </div>
                    </div>

                    {/* Filter controls row */}
                    <div className="flex flex-col md:flex-row items-center gap-3 bg-muted/40 border border-border/50 p-3 rounded-lg">
                        <div className="relative w-full md:w-80">
                            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground/60" />
                            <Input
                                type="text"
                                placeholder={language === 'pt' ? "Filtrar fontes…" : "Search vendors…"}
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="pl-9 h-9 text-xs rounded-full bg-background border-border/50 focus-visible:ring-primary/30"
                            />
                        </div>

                        {/* Switcher pills */}
                        <div className="flex flex-wrap gap-1.5 overflow-x-auto w-full md:w-auto">
                            {iocTypes.map((type) => (
                                <Button
                                    key={type}
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => setSelectedType(type)}
                                    className={`rounded-full text-xs font-semibold py-1 px-3 h-7 transition-all ${
                                        selectedType === type
                                            ? "bg-primary text-primary-foreground shadow"
                                            : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
                                    }`}
                                >
                                    {typeLabel(type)}
                                </Button>
                            ))}
                        </div>
                    </div>

                    {/* High-density grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                        {filteredVendors.length > 0 ? (
                            filteredVendors.map(([name, types]) => {
                                const info = VENDOR_INFO[name];
                                const domain = info?.domain || "google.com";

                                return (
                                    <div
                                        key={name}
                                        className="p-4 rounded-lg border border-border/50 bg-muted/40 hover:bg-muted/40 transition-all hover:scale-[1.01] hover:border-border/50 flex flex-col justify-between h-[160px] relative shadow-sm hover:shadow-md"
                                    >
                                        <div className="space-y-2">
                                            <div className="flex items-center justify-between gap-2">
                                                <div className="flex items-center gap-2 min-w-0 flex-1">
                                                    <img
                                                        src={`https://www.google.com/s2/favicons?sz=32&domain=${domain}`}
                                                        alt=""
                                                        className="w-3.5 h-3.5 rounded-sm object-contain shrink-0"
                                                        onError={(e) => {
                                                            (e.target as HTMLElement).style.display = "none";
                                                        }}
                                                    />
                                                    <h3 className="font-bold text-sm text-foreground truncate">{name}</h3>
                                                </div>
                                                <div className="flex items-center gap-1.5 shrink-0 ml-auto">
                                                    {apiStatuses[name] !== undefined ? (
                                                        apiStatuses[name] ? (
                                                            <span className="inline-flex items-center gap-1.5 text-[9px] font-black tracking-wider px-2 py-0.5 rounded bg-emerald-500 text-neutral-950 shadow-sm shadow-emerald-500/20 shrink-0">
                                                                <span className="h-1.5 w-1.5 rounded-full bg-neutral-950 animate-pulse" />
                                                                {language === 'pt' ? "ATIVA" : "API ON"}
                                                            </span>
                                                        ) : (
                                                            <span className="inline-flex items-center gap-1.5 text-[9px] font-black tracking-wider px-2 py-0.5 rounded bg-red-500/10 text-red-500 border border-red-500/20 shrink-0">
                                                                <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                                                                API OFF
                                                            </span>
                                                        )
                                                    ) : (
                                                        <span className={`inline-flex items-center gap-1.5 text-[9px] font-black tracking-wider px-2 py-0.5 rounded bg-muted/40 text-muted-foreground border border-muted/50 shrink-0 ${statusFailed ? "" : "animate-pulse"}`}>
                                                            <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
                                                            {statusFailed
                                                                ? (language === 'pt' ? "SEM RESPOSTA" : "NO ANSWER")
                                                                : (language === 'pt' ? "VERIFICANDO" : "CHECKING")}
                                                        </span>
                                                    )}
                                                    {info?.docLink && (
                                                        <a
                                                            href={info.docLink}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="text-muted-foreground/60 hover:text-primary transition-colors p-1 rounded-full hover:bg-primary/10 shrink-0"
                                                            title="View Documentation"
                                                        >
                                                            <ExternalLink className="h-3 w-3" />
                                                        </a>
                                                    )}
                                                </div>
                                            </div>
                                            <p className="text-xs text-muted-foreground/90 line-clamp-2 leading-relaxed" title={info?.description}>
                                                {info?.description || (language === 'pt' ? "Sem descrição." : "No description available.")}
                                            </p>
                                        </div>

                                        <div className="flex flex-wrap gap-1 mt-2">
                                            {types.map((type) => (
                                                <Badge
                                                    key={type}
                                                    variant="secondary"
                                                    className="text-[9px] uppercase font-bold py-0 px-1.5 bg-primary/5 text-primary border border-border/50 scale-95 origin-left"
                                                >
                                                    {type}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                );
                            })
                        ) : (
                            <div className="col-span-full h-32 flex flex-col items-center justify-center text-muted-foreground bg-muted/40 rounded-lg border border-dashed border-border/50">
                                <Shield className="h-6 w-6 text-muted-foreground/40 mb-2" />
                                <p className="text-xs">No intelligence sources matching filters found.</p>
                            </div>
                        )}
                    </div>
                </div>
        </PageLayout>
    );
};

export default VendorDirectory;
