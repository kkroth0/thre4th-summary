/**
 * ctiIntel.js — CTI relevance engine for the Advisory Feed collector.
 *
 * Ported from the soc-sentinela Telegram bot (cti/scorer.py + data/*.json).
 * Scores each advisory 0–100 by combining a keyword category taxonomy,
 * CVE/CVSS extraction, regional (BR/LATAM) weighting, source confidence
 * (weight_boost) and noise penalties. Concrete signals (monitored CVSS,
 * CVE IDs) outweigh fuzzy keyword matches.
 */

// ─── Category taxonomy (ported from data/cti_categories.json) ──────────────
export const CTI_CATEGORIES = {
    CAT1_CRITICAL_IMPACT: {
        score: 35, label: 'Active Exploitation',
        terms: ['zero-day', '0-day', 'actively exploited', 'exploited in the wild', 'in the wild',
            'exploitada ativamente', 'exploração ativa', 'under active attack', 'under attack',
            'supply chain attack', 'emergency patch', 'patch de emergência', 'out-of-band patch',
            'proof-of-concept exploit', 'poc exploit'],
    },
    CAT2_MALWARE_THREATS: {
        score: 30, label: 'Malware/Ransomware',
        terms: ['malware', 'ransomware', 'backdoor', 'wiper', 'trojan', 'keylogger', 'stealer',
            'infostealer', 'double extortion'],
    },
    CAT3_BREACH_COMPROMISE: {
        score: 25, label: 'Data Breach', exact_match: true,
        terms: ['data breach', 'vazamento de dados', 'compromised', 'breach', 'vazamento'],
    },
    CAT4_TTPS_CAMPAIGNS: {
        score: 20, label: 'TTPs/Campaign',
        terms: ['phishing', 'command and control', 'botnet', 'credential harvesting', 'credential theft',
            'c2', 'c&c', 'campanha', 'lateral movement', 'espionage', 'cyberespionage', 'cyber espionage',
            'cyber-espionage'],
    },
    CAT5_GROUPS: {
        score: 25, label: 'Threat Group',
        terms: ['lockbit', 'ransomhub', 'medusa', 'blackcat', 'alphv', 'cl0p', 'clop', 'scattered spider',
            'lazarus', 'volt typhoon', 'salt typhoon', 'sandworm', 'revil', 'fin7', 'ta505', 'storm-',
            'unc', 'advanced persistent threat', 'nation-state', 'nation state', 'state-sponsored',
            'state sponsored'],
    },
    CAT6_SCALE: {
        score: 20, label: 'Scale/Reach',
        terms: ['1000+', 'mass exploitation', 'milhares', 'global scale', 'mass attack'],
    },
    CAT7_CRITICAL_VENDORS: {
        score: 10, label: 'Critical Vendor', exact_match: true,
        terms: ['microsoft', 'aws', 'azure', 'google cloud', 'gcp', 'vmware', 'fortinet', 'cisco', 'palo alto'],
    },
    CAT8_SECTORS: {
        score: 20, label: 'Strategic Sector',
        terms: ['banco', 'financeiro', 'saúde', 'hospital', 'energia elétrica', 'infraestrutura crítica',
            'utilities', 'governo', 'órgão público', 'seguro', 'seguradora', 'fintech',
            'telecomunicações', 'operadora'],
    },
    CAT9_VULN_CLASS: {
        score: 20, label: 'Vuln Class', exact_match: true,
        terms: ['remote code execution', 'rce', 'arbitrary code execution', 'arbitrary code',
            'authentication bypass', 'auth bypass', 'unauthenticated', 'privilege escalation',
            'elevation of privilege', 'sql injection', 'command injection', 'code injection',
            'path traversal', 'directory traversal', 'insecure deserialization', 'deserialization',
            'use-after-free', 'buffer overflow', 'out-of-bounds write', 'out-of-bounds read',
            'server-side request forgery', 'ssrf', 'request smuggling', 'memory corruption', 'type confusion'],
    },
    REGIONAL: {
        score: 40, label: 'Regional Radar',
        exact_terms: ['br', 'pf', 'sus', 'stf', 'stj', 'tse', 'bcb', 'cvm'],
        substring_terms: ['brasil', 'brazil', 'latam', 'américa latina', 'america latina',
            'américa do sul', 'america do sul', 'são paulo', 'rio de janeiro', 'brasília',
            'distrito federal', '.com.br', '.gov.br', '.edu.br', '.jus.br'],
    },
    NOISE_PENALTY: {
        score: -100, label: 'Noise Detected', exact_match: true,
        terms: ['carreira', 'vaga', 'emprego', 'salário', 'demanda', 'profissão', 'mercado de trabalho',
            'startup', 'investimento', 'rodada', 'aporte', 'fundo', 'financiamento', 'curiosidade',
            'tutorial', 'como fazer', 'dica', 'webinar', 'palestra', 'curso'],
    },
    NOISE_VOLUME: {
        score: -50, label: 'Low Interest', exact_match: true,
        terms: ['linux kernel'],
    },
};

// ─── Structural scores (independent of the keyword taxonomy) ───────────────
const CVE_MENTION_SCORE = 10;
const CVSS_CRITICAL_SCORE = 30;
const CVSS_HIGH_SCORE = 20;
const WEIGHT_BOOST_CAP = 20;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const buildRe = (terms, exact) => {
    const body = terms.map(escapeRe).join('|');
    return exact ? new RegExp(`\\b(${body})\\b`, 'i') : new RegExp(body, 'i');
};

// Pre-compile category regexes once at module load
const COMPILED = [];
let REGIONAL_EXACT = null;
let REGIONAL_SUB = null;
let REGIONAL_SCORE = 40;
let REGIONAL_LABEL = 'Regional Radar';
for (const [id, data] of Object.entries(CTI_CATEGORIES)) {
    if (id === 'REGIONAL') {
        REGIONAL_SCORE = data.score;
        REGIONAL_LABEL = data.label;
        if (data.exact_terms?.length) REGIONAL_EXACT = buildRe(data.exact_terms, true);
        if (data.substring_terms?.length) REGIONAL_SUB = buildRe(data.substring_terms, false);
        continue;
    }
    if (data.terms?.length) {
        COMPILED.push({ id, label: data.label, score: data.score, re: buildRe(data.terms, !!data.exact_match) });
    }
}

// Consume the CVSS vector version (":3.1", "v4.0") before grabbing the 0-10 base
// score, otherwise "CVSS:3.1 ... 9.0" would capture 3.1 and misclassify a critical.
const CVSS_RE = /cvss\b[:\s]*(?:v?[234](?:\.\d)?\b[:/\s]*)?[a-z\s:()/_-]*?(10(?:\.\d+)?|[0-9](?:\.\d+)?)\b/gi;
const CVSS_FALLBACK_RE = /score[^\d]{0,15}(\d{1,2}\.\d+)/gi;
const CVE_RE = /\bcve-\d{4}-\d+\b/gi;

// ─── Deterministic enrichment maps (ported from soc-sentinela core/constants.py)
// Granular threat labels (keyword -> label)
const THREAT_KEYWORDS = {
    ransomware: 'Ransomware', trojan: 'Trojan', infostealer: 'Infostealer', stealer: 'Infostealer',
    wiper: 'Wiper', botnet: 'Botnet', spyware: 'Spyware', rootkit: 'Rootkit', backdoor: 'Backdoor',
    phishing: 'Phishing', 'zero-day': 'Zero-Day', '0-day': 'Zero-Day', exploit: 'Exploitation',
};

// Targeted/victim sectors (label -> keywords)
const TARGET_SECTORS = {
    Healthcare: ['healthcare', 'hospital', 'hospitals', 'health system', 'medical', 'saúde', 'hospitalar'],
    Financial: ['bank', 'banks', 'banking', 'financial', 'finance', 'fintech', 'banco', 'bancário', 'financeiro'],
    Government: ['government', 'governmental', 'ministry', 'public sector', 'governo', 'governamental', 'setor público'],
    Energy: ['energy', 'power grid', 'electric', 'oil and gas', 'utility', 'utilities', 'energia', 'elétrica', 'petróleo'],
    Education: ['education', 'university', 'universities', 'school', 'academic', 'educação', 'universidade', 'escola'],
    Manufacturing: ['manufacturing', 'industrial', 'factory', 'ics', 'ot security', 'indústria', 'fábrica', 'manufatura'],
    Retail: ['retail', 'e-commerce', 'ecommerce', 'varejo', 'comércio eletrônico'],
    Telecom: ['telecom', 'telecommunications', 'telco', 'telecomunicações', 'operadora'],
    Technology: ['technology sector', 'software vendor', 'saas', 'cloud provider', 'provedor de nuvem'],
    Transportation: ['transportation', 'aviation', 'airline', 'logistics', 'transporte', 'aviação', 'logística'],
    Defense: ['defense', 'defence', 'military', 'defesa', 'militar'],
    Developers: ['developer', 'developers', 'software developer', 'devops', 'open source', 'open-source', 'package repository', 'package registry', 'npm', 'pypi', 'desenvolvedor', 'desenvolvedores'],
    'Linux Users': ['linux user', 'linux users', 'arch linux', 'aur', 'debian', 'ubuntu', 'linux distribution', 'usuários de linux'],
};

// MITRE ATT&CK techniques ("Txxxx — Name" -> keywords)
const ATTACK_TTPS = {
    'T1566 — Phishing': ['phishing', 'phishing email', 'campanha de phishing'],
    'T1566.001 — Spearphishing Attachment': ['spearphishing', 'spear phishing', 'spear-phishing', 'malicious attachment', 'anexo malicioso'],
    'T1190 — Exploit Public-Facing Application': ['public-facing application', 'remote code execution', 'rce', 'execução remota de código', 'exploração de vulnerabilidade'],
    'T1204 — User Execution': ['malicious macro', 'macro-enabled', 'malicious document', 'macro maliciosa', 'documento malicioso'],
    'T1486 — Data Encrypted for Impact': ['ransomware', 'encrypts files', 'file-encrypting', 'criptografa arquivos'],
    'T1485 — Data Destruction': ['wiper', 'data wiping', 'destructive malware', 'malware destrutivo'],
    'T1003 — OS Credential Dumping': ['credential dumping', 'mimikatz', 'lsass', 'dump de credenciais'],
    'T1555 — Credentials from Password Stores': ['stolen credentials', 'credential theft', 'roubo de credenciais', 'credenciais roubadas'],
    'T1110 — Brute Force': ['brute force', 'brute-force', 'password spraying', 'credential stuffing', 'força bruta'],
    'T1059.001 — PowerShell': ['powershell'],
    'T1053 — Scheduled Task/Job': ['scheduled task', 'tarefa agendada'],
    'T1055 — Process Injection': ['process injection', 'dll injection', 'code injection', 'injeção de processo', 'injeção de código'],
    'T1068 — Exploitation for Privilege Escalation': ['privilege escalation', 'elevation of privilege', 'escalonamento de privilégio', 'elevação de privilégio'],
    'T1547 — Boot or Logon Autostart Execution': ['autostart', 'registry run key', 'chave de execução'],
    'T1021.001 — Remote Desktop Protocol': ['rdp', 'remote desktop', 'área de trabalho remota'],
    'T1021 — Remote Services': ['lateral movement', 'movimentação lateral', 'movimento lateral'],
    'T1071 — Application Layer Protocol (C2)': ['command and control', 'command-and-control', 'c2 server', 'c2 infrastructure', 'servidor c2'],
    'T1041 — Exfiltration Over C2 Channel': ['data exfiltration', 'exfiltrate', 'exfiltrated', 'exfiltração de dados'],
    'T1195 — Supply Chain Compromise': ['supply chain', 'supply-chain', 'cadeia de suprimentos'],
    'T1505.003 — Web Shell': ['web shell', 'webshell'],
    'T1078 — Valid Accounts': ['valid accounts', 'compromised account', 'conta comprometida', 'contas válidas'],
    'T1498 — Network Denial of Service': ['ddos', 'denial of service', 'dos attack', 'negação de serviço'],
    'T1496 — Resource Hijacking': ['cryptojacking', 'cryptomining', 'cryptocurrency miner', 'coinminer', 'criptomineração'],
    'T1027 — Obfuscated Files or Information': ['obfuscation', 'obfuscated', 'ofuscação', 'ofuscado'],
};

// Pre-compile each label -> single word-boundary regex over its keywords
const compileLabelMap = (map) =>
    Object.entries(map).map(([label, terms]) => ({ label, re: buildRe(terms, true) }));
const SECTOR_RULES = compileLabelMap(TARGET_SECTORS);
const TTP_RULES = compileLabelMap(ATTACK_TTPS);
const THREAT_RULES = Object.entries(
    // collapse duplicate labels (stealer/infostealer, zero-day/0-day) into one regex each
    Object.entries(THREAT_KEYWORDS).reduce((acc, [kw, label]) => {
        (acc[label] = acc[label] || []).push(kw);
        return acc;
    }, {})
).map(([label, terms]) => ({ label, re: buildRe(terms, true) }));

const matchLabels = (text, rules) => rules.filter((r) => r.re.exec(text)).map((r) => r.label);

// PT-BR labels for the deterministic threat/sector chips, mirroring the
// soc-sentinela bot output. Most threat names are technical terms kept in
// English (Trojan, Infostealer, Rootkit, Botnet…) — only a few translate.
// MITRE technique names and matched vendor assets are proper nouns: untouched.
const THREAT_LABELS_PT = {
    Exploitation: 'Exploração',
};
const SECTOR_LABELS_PT = {
    Healthcare: 'Saúde',
    Financial: 'Financeiro',
    Government: 'Governo',
    Energy: 'Energia',
    Education: 'Educação',
    Manufacturing: 'Indústria',
    Retail: 'Varejo',
    Telecom: 'Telecomunicações',
    Technology: 'Tecnologia',
    Transportation: 'Transporte',
    Defense: 'Defesa',
    Developers: 'Desenvolvedores',
    'Linux Users': 'Usuários de Linux',
};

/**
 * Localize the deterministic enrichment labels to the requested language.
 * Only threats/sectors carry translatable labels; ttps (MITRE) and assets
 * (vendor names) are proper nouns and pass through unchanged.
 */
export function localizeEnrichment(enriched, lang) {
    if (lang !== 'pt' || !enriched) return enriched;
    const map = (arr, dict) => (arr || []).map((l) => dict[l] || l);
    return {
        ...enriched,
        threats: map(enriched.threats, THREAT_LABELS_PT),
        sectors: map(enriched.sectors, SECTOR_LABELS_PT),
    };
}

const severityFromScore = (s) => (s >= 70 ? 'Critical' : s >= 50 ? 'High' : s >= 30 ? 'Medium' : 'Low');

/**
 * Score a single advisory.
 * @param {string} text  title + summary
 * @param {number} weightBoost  source confidence from the feed config
 * @returns {{score:number, severity:string, categories:string[], cves:string[], cvss:number|null, reasons:string[]}}
 */
export function scoreArticle(text, weightBoost = 0) {
    const lower = (text || '').toLowerCase().replace(/_/g, ' ');
    let raw = 0;
    const reasons = [];
    const categories = [];
    const assets = [];

    // Keyword categories (includes the negative NOISE_* buckets)
    for (const c of COMPILED) {
        const m = c.re.exec(lower);
        if (!m) continue;
        raw += c.score;
        categories.push(c.label);
        reasons.push(`${c.label} (${m[0]})`);
        // Surface the matched critical vendor as a "monitored asset"
        if (c.id === 'CAT7_CRITICAL_VENDORS') assets.push(m[0]);
    }

    // Regional relevance (BR/LATAM)
    const mExact = REGIONAL_EXACT ? REGIONAL_EXACT.exec(lower) : null;
    const mSub = REGIONAL_SUB ? REGIONAL_SUB.exec(lower) : null;
    if (mExact || mSub) {
        raw += REGIONAL_SCORE;
        categories.push(REGIONAL_LABEL);
        reasons.push(`${REGIONAL_LABEL} (${(mExact || mSub)[0].toUpperCase()})`);
    }

    // CVE identifiers
    const cves = [...new Set((text.match(CVE_RE) || []).map((s) => s.toUpperCase()))];
    if (cves.length) {
        raw += CVE_MENTION_SCORE;
        reasons.push('CVE Identified');
    }

    // Highest CVSS base score cited in the text
    let cvss = null;
    const primary = [...lower.matchAll(CVSS_RE)].map((m) => parseFloat(m[1]));
    const vals = primary.length ? primary : [...lower.matchAll(CVSS_FALLBACK_RE)].map((m) => parseFloat(m[1]));
    if (vals.length) {
        cvss = Math.max(...vals);
        if (cvss >= 9.0) {
            raw += CVSS_CRITICAL_SCORE;
            reasons.push(`CVSS Critical (${cvss})`);
        } else if (cvss >= 7.0) {
            raw += CVSS_HIGH_SCORE;
            reasons.push(`CVSS High (${cvss})`);
        }
    }

    // Source confidence — only counts when the item already has content signal,
    // so a priority feed can't approve noise on its own.
    const boost = Number(weightBoost) || 0;
    if (boost > 0 && raw > 0) {
        const applied = Math.min(boost, WEIGHT_BOOST_CAP);
        raw += applied;
        reasons.push(`Priority Source (+${applied})`);
    }

    const score = Math.max(0, Math.min(raw, 100));
    return {
        score,
        severity: severityFromScore(score),
        categories: [...new Set(categories)],
        cves,
        cvss,
        reasons,
        // Deterministic actionable enrichment
        threats: matchLabels(lower, THREAT_RULES),
        sectors: matchLabels(lower, SECTOR_RULES),
        ttps: matchLabels(lower, TTP_RULES),
        assets: [...new Set(assets)],
    };
}

// ─── Feed catalog (ported/merged from data/cti_feeds.json) ─────────────────
// Static-scrape feeds are omitted (the Node collector is plain HTTP). Feeds that
// sit behind a WAF simply yield nothing and are tolerated by Promise.allSettled.
export const CTI_FEEDS = [
    // Layer 1 — PSIRT, vendor advisories & vuln intel (highest confidence)
    { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', source: 'CISA Advisories', layer: 1, weight_boost: 20 },
    { url: 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml', source: 'CISA ICS (OT)', layer: 1, weight_boost: 20 },
    { url: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', source: 'Cisco PSIRT', layer: 1, weight_boost: 20 },
    { url: 'https://api.msrc.microsoft.com/update-guide/rss', source: 'Microsoft MSRC', layer: 1, weight_boost: 20 },
    { url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml', source: 'FortiGuard PSIRT', layer: 1, weight_boost: 20 },
    { url: 'https://filestore.fortinet.com/fortiguard/rss/outbreakalert.xml', source: 'FortiGuard Outbreak', layer: 1, weight_boost: 20 },
    { url: 'https://security.paloaltonetworks.com/rss.xml', source: 'Palo Alto PSIRT', layer: 1, weight_boost: 20 },
    { url: 'https://about.gitlab.com/security-releases.xml', source: 'GitLab Security', layer: 1, weight_boost: 20 },
    { url: 'https://www.jenkins.io/security/advisories/rss.xml', source: 'Jenkins PSIRT', layer: 1, weight_boost: 15 },
    { url: 'https://ubuntu.com/security/notices/rss.xml', source: 'Ubuntu Security Notices', layer: 1, weight_boost: 15 },
    { url: 'https://access.redhat.com/blogs/766093/feed', source: 'Red Hat Product Security', layer: 1, weight_boost: 15 },
    { url: 'https://feeds.feedburner.com/GoogleChromeReleases', source: 'Chrome Releases', layer: 1, weight_boost: 15 },
    { url: 'https://blog.cloudflare.com/tag/security/rss', source: 'Cloudflare Security', layer: 1, weight_boost: 15 },
    { url: 'https://googleprojectzero.blogspot.com/feeds/posts/default', source: 'Google Project Zero', layer: 1, weight_boost: 20 },
    { url: 'https://www.zerodayinitiative.com/rss/published/', source: 'Zero Day Initiative', layer: 1, weight_boost: 20 },
    { url: 'https://www.exploit-db.com/rss.xml', source: 'Exploit-DB', layer: 1, weight_boost: 15 },
    { url: 'https://www.tenable.com/blog/feed', source: 'Tenable', layer: 1, weight_boost: 15 },
    { url: 'https://blog.qualys.com/feed', source: 'Qualys', layer: 1, weight_boost: 15 },

    // Layer 2 — TI news & reporting
    { url: 'https://www.bleepingcomputer.com/feed/', source: 'BleepingComputer', layer: 2, weight_boost: 10 },
    { url: 'https://feeds.feedburner.com/TheHackersNews', source: 'The Hacker News', layer: 2, weight_boost: 10 },
    { url: 'https://feeds.feedburner.com/Securityweek', source: 'SecurityWeek', layer: 2, weight_boost: 10 },
    { url: 'https://krebsonsecurity.com/feed/', source: 'Krebs on Security', layer: 2, weight_boost: 10 },
    { url: 'https://therecord.media/feed/', source: 'The Record', layer: 2, weight_boost: 5 },
    { url: 'https://www.darkreading.com/rss.xml', source: 'Dark Reading', layer: 2, weight_boost: 10 },
    { url: 'https://www.helpnetsecurity.com/feed/', source: 'Help Net Security', layer: 2, weight_boost: 10 },

    // Layer 3 — Threat research labs
    { url: 'https://isc.sans.edu/rssfeed_full.xml', source: 'SANS ISC', layer: 3, weight_boost: 10 },
    { url: 'https://blog.talosintelligence.com/rss/', source: 'Cisco Talos', layer: 3, weight_boost: 15 },
    { url: 'https://unit42.paloaltonetworks.com/feed/', source: 'Palo Alto Unit 42', layer: 3, weight_boost: 15 },
    { url: 'https://research.checkpoint.com/feed/', source: 'Check Point Research', layer: 3, weight_boost: 10 },
    { url: 'https://securelist.com/feed/', source: 'Kaspersky Securelist', layer: 3, weight_boost: 12 },
    { url: 'https://www.volexity.com/feed/', source: 'Volexity', layer: 3, weight_boost: 12 },
    { url: 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v/', source: 'Mandiant', layer: 3, weight_boost: 15 },
    { url: 'https://www.elastic.co/security-labs/rss/feed.xml', source: 'Elastic Security', layer: 3, weight_boost: 5 },

    // Layer 4 — LATAM / BR regional
    { url: 'https://www.cisoadvisor.com.br/feed/', source: 'CISO Advisor BR', layer: 4, weight_boost: 15 },
    { url: 'https://thehack.com.br/rss/', source: 'The Hack', layer: 4, weight_boost: 10 },
];
