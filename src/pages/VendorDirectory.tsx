import { useState, useMemo, useEffect } from "react";
import { ExternalLink, RefreshCw, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { VENDOR_IOC_SUPPORT } from "@/services/threatApi";
import { Badge } from "@/components/ui/badge";
import { SourceIdentity } from "@/components/SourceIdentity";
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
        docLink: "https://www.phishtank.org/api_info.php",
        domain: "phishtank.com"
    },
    "PhishStats": {
        description: "Phishing statistics database and real-time public CTI feed provider.",
        docLink: "https://phishstats.info/api-docs",
        domain: "phishstats.info"
    },
    "WHOIS": {
        description: "Who.is domain registration snapshots: registrar, dates, statuses and nameservers.",
        docLink: "https://who.is/docs/api",
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
        description: "Community feed of phishing URLs, refreshed by OpenPhish every 12 hours.",
        docLink: "https://openphish.com/faq.html",
        domain: "openphish.com"
    },
};

type LookupActivity = { state: 'unchecked' | 'healthy' | 'failed'; lastChecked: string | null; httpStatus: number | null; requests: number; mode: 'on_demand'; keyConfigured?: boolean };
const PUBLIC_LOOKUPS = new Set(['IP Geolocation', 'AlienVault OTX', 'OpenPhish', 'PhishStats', 'PhishTank']);
const PHISHING_LOOKUPS = new Set(['OpenPhish', 'PhishStats', 'PhishTank']);

const VendorDirectory = () => {
    const { language } = useLanguage(); const pt = language === 'pt';
    const l = (a: string, b: string) => pt ? a : b;
    const [search, setSearch] = useState(''); const [type, setType] = useState('all');
    const [statuses, setStatuses] = useState<Record<string, boolean>>({});
    const [activity, setActivity] = useState<Record<string, LookupActivity>>({});
    const [state, setState] = useState<'loading' | 'ready' | 'failed'>('loading');
    const [refresh, setRefresh] = useState(0);
    useEffect(() => {
        const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
        setState('loading');
        const read = async (path: string) => { const response = await fetch(path, { signal: controller.signal }); if (!response.ok) throw new Error('Source status unavailable'); return response.json(); };
        void Promise.all([read('/api/vendors/status'), read('/api/vendors/activity')]).then(([configured, observed]) => { setStatuses(configured); setActivity(observed); setState('ready'); }).catch(() => { if (!controller.signal.aborted) setState('failed'); else setState('failed'); }).finally(() => clearTimeout(timer));
        return () => { controller.abort(); clearTimeout(timer); };
    }, [refresh]);
    const sources = useMemo(() => Object.entries(VENDOR_IOC_SUPPORT).sort(([a], [b]) => a.localeCompare(b)), []);
    const types = ['all', ...new Set(sources.flatMap(([, values]) => values))];
    const rows = sources.filter(([name, values]) => (type === 'all' || values.includes(type as never)) && (name + ' ' + VENDOR_INFO[name]?.description).toLowerCase().includes(search.toLowerCase().trim()));
    const available = sources.filter(([name]) => statuses[name] === true).length;
    return <PageLayout width="max-w-7xl"><div className="space-y-5">
        <div className="page-head"><div><h1 className="page-title">{l('Fontes de Dados', 'Data Sources')}</h1><p className="page-lede">{sources.length} {l('integrações para consultar IPs, domínios, URLs e hashes.', 'integrations for IP, domain, URL and hash lookups.')}</p></div><div className="flex items-center gap-3"><span className="text-xs text-muted-foreground">{l('Disponíveis pela configuração', 'Available by configuration')}: <strong className="font-mono text-foreground">{state === 'ready' ? available : '—'}/{sources.length}</strong></span><Button size="sm" variant="outline" disabled={state === 'loading'} onClick={() => setRefresh(value => value + 1)}><RefreshCw className="mr-2 h-3.5 w-3.5" />{l('Atualizar', 'Refresh')}</Button></div></div>
        <p className="max-w-4xl text-xs leading-relaxed text-muted-foreground">{l('As fontes são consultadas sob demanda no enriquecimento, conforme o tipo de indicador e sua seleção. Configurada ou pública indica acesso previsto; a última resposta registra a consulta realizada. Os dashboards de phishing usam as publicações coletadas, e o monitoramento de domínios usa o urlscan.io. O cache varia por fonte.', 'Sources are queried on demand during enrichment, according to indicator type and your selection. Configured or public indicates expected access; the last response records an executed lookup. Phishing dashboards use collected publications, while domain monitoring uses urlscan.io. Cache duration varies by source.')}</p>
        {state === 'failed' && <p role="alert" className="text-sm text-destructive">{l('Não foi possível consultar a configuração das fontes.', 'Could not load source configuration.')}</p>}
        <div className="flex flex-wrap items-center gap-3"><div className="relative w-full sm:w-80"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><Input value={search} onChange={event => setSearch(event.target.value)} placeholder={l('Filtrar fontes…', 'Filter sources…')} className="h-9 pl-9 text-sm" /></div><div className="flex flex-wrap gap-1">{types.map(value => <Button key={value} size="sm" variant={type === value ? 'secondary' : 'ghost'} className="h-8 px-3 text-xs" aria-pressed={type === value} onClick={() => setType(value)}>{value === 'all' ? l('TODOS', 'ALL') : value.toUpperCase()}</Button>)}</div></div>
        <div className="actor-surface overflow-hidden"><div className="overflow-x-auto"><table className="actor-table w-full min-w-[940px] text-left text-xs"><thead><tr>{[l('Fonte', 'Source'), l('Cobertura', 'Coverage'), l('Indicadores', 'Indicators'), l('Configuração', 'Configuration'), l('Última resposta', 'Last response'), l('Documentação', 'Documentation')].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{rows.map(([name, values]) => { const info = VENDOR_INFO[name]; const observed = activity[name]; return <tr key={name}><td className="font-medium"><SourceIdentity name={name} url={info ? 'https://' + info.domain : undefined} /></td><td className="max-w-80"><p className="text-muted-foreground">{info?.description || '—'}</p></td><td><div className="flex gap-1">{values.map(value => <Badge key={value} variant="outline" className="text-[10px] uppercase">{value}</Badge>)}</div></td><td><span className="text-muted-foreground">{state !== 'ready' ? '—' : PUBLIC_LOOKUPS.has(name) ? observed?.keyConfigured ? l('Chave configurada', 'Key configured') : l('Pública', 'Public') : statuses[name] ? l('Configurada', 'Configured') : l('Sem chave', 'No key')}</span></td><td>{observed?.lastChecked ? <div><span className={observed.state === 'failed' ? 'text-destructive' : 'text-muted-foreground'}>HTTP {observed.httpStatus}</span><p className="mt-1 text-[10px] text-muted-foreground">{new Date(observed.lastChecked).toLocaleString(pt ? 'pt-BR' : 'en-US')}</p></div> : <span className="text-muted-foreground">{PHISHING_LOOKUPS.has(name) ? l('Ainda não consultada', 'Not queried yet') : '—'}</span>}</td><td>{info && <a href={info.docLink} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-primary hover:underline" aria-label={l('Documentação de ', 'Documentation for ') + name}><ExternalLink className="h-3.5 w-3.5" />API</a>}</td></tr>; })}</tbody></table></div>{!rows.length && <p className="p-8 text-center text-sm text-muted-foreground">{l('Nenhuma fonte corresponde aos filtros.', 'No sources match your filters.')}</p>}</div>
        <Link to="/settings?section=api-keys" className="inline-block text-xs text-primary hover:underline">{l('Gerenciar chaves pessoais', 'Manage personal keys')}</Link>
    </div></PageLayout>;
};
export default VendorDirectory;
