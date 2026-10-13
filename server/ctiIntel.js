/**
 * ctiIntel.js — CTI relevance engine for the Advisory Feed collector.
 *
 * Ported from the soc-sentinela Telegram bot (cti/scorer.py + data/*.json).
 * Scores each advisory 0–100 by combining a keyword category taxonomy,
 * CVE/CVSS extraction, regional (BR/LATAM) weighting, source confidence
 * (weight_boost) and noise penalties. Concrete signals (monitored CVSS,
 * CVE IDs) outweigh fuzzy keyword matches.
 */
import * as cheerio from 'cheerio';
import { VENDOR_TERMS } from './vendorCatalog.js';
import { matchVendors } from './vendorMatch.js';
import { analyzePhishing } from './phishingIntel.js';

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
        terms: VENDOR_TERMS,
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
            'tutorial', 'como fazer', 'dica', 'webinar', 'palestra', 'curso',
            // Dark Reading marca a agenda de evento com este prefixo no título
            // ("[Virtual Event] ..."); \b ainda casa nas bordas de "virtual"/
            // "event" mesmo com colchete colado, então não precisa do "[]" aqui.
            'virtual event'],
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

// Pre-compile category regexes once at module load. Only NOISE_PENALTY (pure
// marketing/career/tutorial content) is held back for the gate in scoreArticle
// below — it fires only when nothing else signals real threat-intel content.
// NOISE_VOLUME is a different kind of penalty: it targets content that IS real
// (has CVEs, has signal) but is so overrepresented in one feed that it drowns
// out everything else (Ubuntu's flood of per-flavor Linux kernel USNs is
// exactly this — each one cites real CVEs). Gating that one the same way would
// defeat its own purpose, so it stays unconditional in COMPILED.
const COMPILED = [];
const NOISE_COMPILED = [];
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
    // Vendor names have punctuation and per-supplier attribution. Their matcher
    // applies the same catalog to both score and all returned assets.
    if (!data.terms?.length || id === 'CAT7_CRITICAL_VENDORS') continue;
    const re = id === 'CAT5_GROUPS'
        ? new RegExp('\\b(?:' + data.terms.filter((term) => !['unc', 'storm-'].includes(term)).map(escapeRe).join('|') + ')\\b|\\b(?:unc\\d{2,6}|storm-\\d{2,6})\\b', 'i')
        : buildRe(data.terms, !!data.exact_match);
    const entry = { id, label: data.label, score: data.score, re };
    (id === 'NOISE_PENALTY' ? NOISE_COMPILED : COMPILED).push(entry);
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
export const compileLabelMap = (map) =>
    Object.entries(map).map(([label, terms]) => ({ label, re: buildRe(terms, true) }));
export const SECTOR_RULES = compileLabelMap(TARGET_SECTORS);
const TTP_RULES = compileLabelMap(ATTACK_TTPS);

// scoreArticle's ttps are display labels ("T1566 — Phishing"), always built
// from this file's own ATTACK_TTPS keys — so the id is reliably the prefix
// before " — ". Used by newsStories.js to compare technique ids across
// articles without re-deriving them from keywords on every merge comparison.
const TTP_ID_RE = /^(T\d{4}(?:\.\d{3})?)/;
export const ttpIdsFrom = (labels) =>
    [...new Set((labels || []).map((label) => TTP_ID_RE.exec(label)?.[1]).filter(Boolean))];
const THREAT_RULES = Object.entries(
    // collapse duplicate labels (stealer/infostealer, zero-day/0-day) into one regex each
    Object.entries(THREAT_KEYWORDS).reduce((acc, [kw, label]) => {
        (acc[label] = acc[label] || []).push(kw);
        return acc;
    }, {})
).map(([label, terms]) => ({ label, re: buildRe(terms, true) }));

export const matchLabels = (text, rules) => rules.filter((r) => r.re.exec(text)).map((r) => r.label);

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

export const severityFromScore = (s) => (s >= 70 ? 'Critical' : s >= 50 ? 'High' : s >= 30 ? 'Medium' : 'Low');

// ─── Deterministic IOC extraction ──────────────────────────────────────────
// High-precision indicators from advisory text. Hashes are always IOCs. Network
// indicators are accepted when DEFANGED in the source (evil[.]com, 1.2.3[.]4,
// hxxp://) — analysts defang on purpose, so this stays low-noise — plus plain
// public IPv4. Returns canonical arrays consumed by the IOC panel / export.
const RE_HASHES = [/\b[a-f0-9]{64}\b/gi, /\b[a-f0-9]{40}\b/gi, /\b[a-f0-9]{32}\b/gi];
const RE_PRIVATE_IP = /^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|22[4-9]\.|2[3-5]\d\.)/;

const refang = (s) => String(s)
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[@\]|\[at\]/gi, '@')
    .replace(/\bhxx(ps?)\b/gi, 'htt$1')
    .replace(/\bhxx(ps?):/gi, 'htt$1:');

// An address' domain is not an IOC: evil@gmail[.]com would otherwise publish
// gmail.com as a malicious domain. The schema has no e-mail field, so the whole
// token goes.
const RE_EMAIL = /[a-z0-9._%+-]+(?:@|\[@\]|\[at\])[a-z0-9.\[\](){}_-]+\.?[a-z]{2,}/gi;

// Shared hosting/CDN suffixes: the bare apex is legit infrastructure (nobody
// blocks github.io), so alone it's noise — e.g. a "<referrer>.github.io" template
// in a CSV that refangs to a bare "github.io". The attacker SUBdomain
// (evil.github.io) is a real indicator and is kept. Curated, not the full Public
// Suffix List. ponytail: hand-list, add the PSL only if noise proves broader.
const SHARED_PLATFORM_DOMAINS = new Set([
    'github.io', 'workers.dev', 'pages.dev', 'web.app', 'firebaseapp.com',
    'netlify.app', 'vercel.app', 'azurewebsites.net', 'herokuapp.com',
    'cloudfront.net', 'amazonaws.com', 'blogspot.com', 'wordpress.com',
    'r2.dev', 'b-cdn.net', 'glitch.me',
]);

// Serviço legítimo e famoso nunca é o indicador. O artigo de laboratório
// defanga o que ESTÁ SENDO ABUSADO, não só o que é do atacante: um post sobre
// abuso de canal confiável escreve `slack[.]com`, e sem este guarda a planilha
// sairia com "slack.com atribuído à APT29".
//
// Mesma semântica do SHARED_PLATFORM_DOMAINS: só o apex sai. `evil.sharepoint.com`
// e `payload.pastebin.com` continuam passando, porque aí o atacante é dono do
// nome. O custo assumido é que a menção "o grupo usou o Slack" some do índice —
// o que é certo, porque hunting por slack.com não acha adversário nenhum.
//
// Lista curada, não exaustiva: é para os famosos. Domínio novo entra aqui
// quando aparecer como ruído em colheita real, não por precaução.
const BENIGN_APEX_DOMAINS = new Set([
    // Comunicação e colaboração — o balde que mais aparece defangado
    'slack.com', 'discord.com', 'discordapp.com', 'telegram.org', 't.me',
    'zoom.us', 'whatsapp.com', 'teams.microsoft.com', 'skype.com',
    // Armazenamento e documentos
    'dropbox.com', 'box.com', 'mega.nz', 'mediafire.com', 'wetransfer.com',
    'drive.google.com', 'docs.google.com', 'onedrive.live.com', 'sharepoint.com',
    // Plataformas grandes
    'google.com', 'gmail.com', 'microsoft.com', 'office.com', 'live.com',
    'outlook.com', 'apple.com', 'icloud.com', 'amazon.com', 'cloudflare.com',
    'akamai.com', 'fastly.com', 'adobe.com', 'oracle.com', 'ibm.com',
    // Redes sociais
    'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 'x.com',
    'youtube.com', 'reddit.com', 'tiktok.com', 'telegram.me',
    // Desenvolvimento e pacotes
    'npmjs.com', 'pypi.org', 'docker.com', 'stackoverflow.com', 'pastebin.com',
    // Fornecedores de segurança: o artigo cita o próprio domínio o tempo todo
    'virustotal.com', 'paloaltonetworks.com', 'mandiant.com', 'kaspersky.com',
    'securelist.com', 'talosintelligence.com', 'sans.edu', 'sans.org',
    'crowdstrike.com', 'trendmicro.com', 'sophos.com', 'fortinet.com',
    'checkpoint.com', 'welivesecurity.com', 'eset.com', 'abuse.ch',
    'alienvault.com', 'recordedfuture.com', 'proofpoint.com', 'volexity.com',
    'mitre.org', 'cisa.gov', 'nist.gov', 'first.org',
]);

// Resolvedor público famoso. Malware usa 1.1.1.1 para DoH e o relatório cita —
// mas caçar por 1.1.1.1 não acha adversário nenhum, acha a internet.
const BENIGN_IPS = new Set([
    '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220', '4.2.2.2', '4.2.2.1', '64.6.64.6',
    '76.76.2.0', '94.140.14.14', '185.228.168.9', '76.76.19.19',
]);

// A bare filename (malware.exe) matches the domain shape but is not a domain.
const RE_FILE_EXT = /\.(exe|dll|sys|bin|dat|dmp|zip|rar|tar|gz|7z|png|jpe?g|gif|svg|css|js|html?|txt|log|json|xml|pdf|docx?|xlsx?|pptx?|csv|ya?ml|md|ps1|sh|py)$/i;

// Code hosting is never the indicator. An appendix that LIVES in a repo cites its
// own repo, the raw file host and neighbouring projects on every other line, and
// each one came back as a "malicious domain/URL". Unlike SHARED_PLATFORM_DOMAINS
// (bare apex only, attacker subdomain kept), here the whole host tree goes: there
// is no evil.github.com. The repo link still shows up in `iocSources`, which is
// where it belongs. github.io stays out of this — it serves attacker pages.
const CODE_HOST_SUFFIXES = [
    'github.com', 'githubusercontent.com', 'githubassets.com',
    'gitlab.com', 'gitlab-static.net', 'bitbucket.org',
];
const isCodeHost = (host) => CODE_HOST_SUFFIXES.some(
    (s) => host === s || host.endsWith(`.${s}`),
);

const addDomain = (set, raw) => {
    const d = String(raw).toLowerCase();
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return;
    if (SHARED_PLATFORM_DOMAINS.has(d) || BENIGN_APEX_DOMAINS.has(d)) return;
    if (RE_FILE_EXT.test(d) || isCodeHost(d)) return;
    set.add(d);
};

const addUrl = (set, raw) => {
    const url = String(raw).replace(/[.,;:]+$/, '');
    let host = '';
    // Inparseável fica: antes entrava sem checagem, e só o code host sai daqui.
    try { host = new URL(url).hostname.toLowerCase(); } catch { /* keep */ }
    if (isCodeHost(host)) return;
    set.add(url);
};

// plaintext=false (default): article prose. Only DEFANGED network indicators are
// kept, so benign links/domains in the body aren't harvested — low noise.
// plaintext=true: a dedicated indicator appendix (CSV/txt/gist), where every
// listed domain/URL IS an indicator and is usually NOT defanged. Hashes and
// public IPv4 are always taken (unambiguous in either source).
// ponytail: plaintext mode over a prose-y .md appendix can pull a few benign
// domains; bounded by the 40KB fetch cap. Restrict by file type only if it bites.
// O que anuncia versão logo antes do número: a palavra, a notação da CISA
// (`vers:intdot/`) e os comparadores que aparecem em "prior to <4.3.4.1".
const RE_VERSION_BEFORE = /(?:vers(?:ion|ao|ão)?|vers:intdot\/|firmware|release|build|update|patch|prior to|earlier than|before|through)\s*[<>=]*\s*$|(?:<|>|&lt;|&gt;|≤|≥)\s*$/i;

export function extractIOCs(text, { plaintext = false } = {}) {
    const t = String(text || '');
    const hashes = new Set();
    for (const re of RE_HASHES) for (const m of t.matchAll(re)) hashes.add(m[0].toLowerCase());

    const urls = new Set();
    // A comma ends the URL: it delimits the next column in a CSV appendix, and the
    // next clause in prose.
    for (const m of t.matchAll(/\b(?:hxxps?|https?)(?::|\[:\])\/\/[^\s<>"'),]+/gi)) {
        if (plaintext || /\[\.\]|\(\.\)|\{\.\}|\[:\]|hxx/i.test(m[0])) addUrl(urls, refang(m[0]));
    }

    const domains = new Set();
    const domainSrc = t.replace(RE_EMAIL, ' ');
    // Defanged domains (any mode): a token carrying [.] / (.) / {.}
    for (const m of domainSrc.matchAll(/\b((?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)|\{\.\}))+[a-z]{2,})\b/gi)) {
        if (/\[\.\]|\(\.\)|\{\.\}/.test(m[1])) addDomain(domains, refang(m[1]));
    }
    // Plaintext appendix: also accept plain domains (evil.com, sub.evil.com), after
    // stripping URLs so a URL's host isn't double-counted through a different path.
    if (plaintext) {
        const noUrls = refang(domainSrc).replace(/\bhttps?:\/\/\S+/gi, ' ');
        for (const m of noUrls.matchAll(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/gi)) addDomain(domains, m[1]);
    }

    const ips = new Set();
    const refanged = refang(t);
    for (const m of refanged.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
        const ip = m[0];
        if (ip.split('.').some((o) => Number(o) > 255)) continue;
        if (RE_PRIVATE_IP.test(ip)) continue;
        if (BENIGN_IPS.has(ip)) continue;
        // Versão de produto tem a mesma cara de um IPv4 — "version 3.3.1.0",
        // "vers:intdot/&lt;4.3.4.1" — e advisory de OT é feito disso. Sem os dois
        // guardas abaixo, um boletim da CISA sobre a Siemens saía com quatro
        // "IOCs" que são número de firmware.
        if (ip.split('.').some((o) => o.length > 1 && o.startsWith('0'))) continue;
        if (RE_VERSION_BEFORE.test(refanged.slice(Math.max(0, m.index - 28), m.index))) continue;
        ips.add(ip);
    }

    return { ips: [...ips], domains: [...domains], hashes: [...hashes], urls: [...urls] };
}

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
    const vendors = matchVendors(text);
    const assets = vendors.map((vendor) => vendor.name);

    // Keyword categories
    for (const c of COMPILED) {
        const m = c.re.exec(lower);
        if (!m) continue;
        raw += c.score;
        categories.push(c.label);
        reasons.push(`${c.label} (${m[0]})`);
    }

    if (vendors.length) {
        const { score, label } = CTI_CATEGORIES.CAT7_CRITICAL_VENDORS;
        raw += score;
        categories.push(label);
        reasons.push(`${label} (${assets.join(', ')})`);
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

    // Noise penalty (career/marketing/tutorial content) only fires when
    // nothing above found a concrete threat-intel signal — a genuine advisory
    // that happens to mention "webinar" or "curso" in passing shouldn't be
    // tanked by the same rule meant to filter a pure career/marketing post.
    const hasConcreteSignal = categories.some((category) => !['Regional Radar', 'Critical Vendor', 'Low Interest'].includes(category)) || cves.length > 0 || (cvss !== null && cvss >= 7.0);
    if (!hasConcreteSignal) {
        for (const c of NOISE_COMPILED) {
            const m = c.re.exec(lower);
            if (!m) continue;
            raw += c.score;
            categories.push(c.label);
            reasons.push(`${c.label} (${m[0]})`);
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
        phishingTechniques: analyzePhishing({ description: text }).techniques,
        assets: [...new Set(assets)],
        vendors,
    };
}

// Item cujo NOISE_PENALTY disparou (agenda de evento, vaga, "webinar") não é
// baixa prioridade — é lixo que não deveria ocupar vaga no feed. Antes só
// afundava a 0 no score e continuava aparecendo em qualquer ordenação que não
// fosse "por relevância" (o padrão da tela é por data). O feed usa isto pra
// dropar o item de vez antes de servir a /api/newsletter, em vez de só
// rebaixar. Note: o gate em scoreArticle já garante que isto só dispara
// quando nenhuma categoria/CVE/CVSS real também bateu no mesmo texto.
export const NOISE_LABEL = CTI_CATEGORIES.NOISE_PENALTY.label;
export function isPureNoise(categories) {
    return Array.isArray(categories) && categories.includes(NOISE_LABEL);
}

// ─── Transient vs. permanent feed-fetch failures ───────────────────────────
// A retry only pays off against a failure that might not repeat: a 5xx, a
// dropped connection, a rate limit. A 404, a DNS failure, or a WAF that stalls
// the TLS handshake for a non-browser client (measured against Sophos'
// feed URLs, 2026-09-15: 10s of TLS renegotiation, zero bytes, every time)
// looks exactly the same on the next attempt — retrying those three times
// just adds ~20s of dead weight to every refresh cycle for a feed that was
// never coming back up this run.
export function isTransientFeedError(err) {
    const status = err?.response?.status;
    if (status) return status >= 500 || status === 429;
    // No HTTP response at all: a network/timeout-level failure. ENOTFOUND/
    // EAI_AGAIN (DNS) are deliberately excluded — a hostname that doesn't
    // resolve now won't resolve differently a second later.
    const code = err?.code;
    return code === 'ECONNABORTED' || code === 'ETIMEDOUT' || code === 'ECONNRESET' || code === 'ECONNREFUSED';
}

// ─── Ubuntu kernel notice collapsing ────────────────────────────────────────
// USN republica a mesma rodada de CVE de kernel uma vez por flavor (linux,
// linux-aws, linux-gcp, linux-oem-6.8, linux-raspi...), quase sempre no mesmo
// dia — o leitor via cinco cards quase idênticos de "... vulnerabilities" para
// um único evento real. Colapsar em um só card mantém todo CVE e todo link
// original (na description); só para de inundar o feed com N cópias.
const UBUNTU_SOURCE = 'Ubuntu Security Notices';
const KERNEL_TITLE_RE = /^linux\b.*vulnerabilit/i;
const KERNEL_PACKAGE_RE = /^([\w.-]+)/;

export function collapseKernelNotices(items) {
    const byDay = new Map();
    const passthrough = [];
    for (const item of items) {
        if (item.source === UBUNTU_SOURCE && KERNEL_TITLE_RE.test(item.title || '')) {
            const day = String(item.pubDate || '').slice(0, 10);
            if (!byDay.has(day)) byDay.set(day, []);
            byDay.get(day).push(item);
        } else {
            passthrough.push(item);
        }
    }

    const collapsed = [];
    for (const group of byDay.values()) {
        if (group.length === 1) { collapsed.push(group[0]); continue; }
        // O mais severo vira a base do card: nenhum CVE crítico fica escondido
        // atrás de um flavor mais brando publicado no mesmo lote.
        const sorted = [...group].sort((a, b) => (b.score || 0) - (a.score || 0) || a.title.localeCompare(b.title));
        const primary = sorted[0];
        const flavors = [...new Set(group.map((g) => (g.title.match(KERNEL_PACKAGE_RE) || ['', ''])[1]))].filter(Boolean).sort();
        const flavorList = flavors.length > 6 ? `${flavors.slice(0, 6).join(', ')}, +${flavors.length - 6}` : flavors.join(', ');
        collapsed.push({
            ...primary,
            title: `Linux kernel vulnerabilities — ${group.length} Ubuntu flavors patched (${flavorList})`,
            description: group.map((g) => `${g.title}: ${g.link}`).join(' · '),
            cves: [...new Set(group.flatMap((g) => g.cves || []))],
        });
    }

    return [...passthrough, ...collapsed];
}

// ─── Feed catalog (ported/merged from data/cti_feeds.json) ─────────────────
// Static-scrape feeds are omitted (the Node collector is plain HTTP). Feeds that
// sit behind a WAF simply yield nothing and are tolerated by Promise.allSettled.
export const CTI_FEEDS = [
    // Layer 1 — PSIRT, vendor advisories & vuln intel (highest confidence)
    { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', source: 'CISA Advisories', layer: 1, weight_boost: 20 },
    { url: 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml', source: 'CISA ICS (OT)', layer: 1, weight_boost: 20, categories: ['OT/ICS'] },
    { url: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', source: 'Cisco PSIRT', layer: 1, weight_boost: 20 },
    { url: 'https://api.msrc.microsoft.com/update-guide/rss', source: 'Microsoft MSRC', layer: 1, weight_boost: 20 },
    { url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml', source: 'FortiGuard PSIRT', layer: 1, weight_boost: 20 },
    { url: 'https://filestore.fortinet.com/fortiguard/rss/outbreakalert.xml', source: 'FortiGuard Outbreak', layer: 1, weight_boost: 20 },
    { url: 'https://feeds.feedblitz.com/fortinet/blog/psirt', source: 'Fortinet PSIRT Blog', layer: 1, weight_boost: 15 },
    { url: 'https://security.paloaltonetworks.com/rss.xml', source: 'Palo Alto PSIRT', layer: 1, weight_boost: 20 },
    { url: 'https://security.nozominetworks.com/rss.xml', source: 'Nozomi Networks PSIRT', layer: 1, weight_boost: 20 },
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
    { url: 'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml', source: 'Oracle Security Alerts', layer: 1, weight_boost: 20 },
    { url: 'https://filestore.fortinet.com/fortiguard/rss/threatsignal.xml', source: 'FortiGuard Threat Signal', layer: 1, weight_boost: 15 },
    { url: 'https://www.microsoft.com/en-us/security/blog/feed/', source: 'Microsoft Security Blog', layer: 1, weight_boost: 15 },
    { url: 'https://www.crowdstrike.com/en-us/blog/feed', source: 'CrowdStrike Blog', layer: 1, weight_boost: 15 },
    { url: 'https://www.sentinelone.com/labs/feed/', source: 'SentinelOne Labs', layer: 1, weight_boost: 15 },
    { url: 'https://www.welivesecurity.com/en/rss/feed/', source: 'ESET WeLiveSecurity', layer: 1, weight_boost: 15 },
    { url: 'https://thedfirreport.com/feed/', source: 'The DFIR Report', layer: 1, weight_boost: 15 },

    // Gov CSIRTs / national advisory feeds (adicionados a pedido, lote CTIFLOW).
    { url: 'https://www.cisa.gov/rss.xml', source: 'CISA Alerts', layer: 1, weight_boost: 15 },
    { url: 'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en', source: 'Canada CCCS', layer: 1, weight_boost: 15 },
    { url: 'https://www.cert.ssi.gouv.fr/avis/feed/', source: 'CERT-FR Avis (ANSSI)', layer: 1, weight_boost: 15 },
    { url: 'https://www.cert.ssi.gouv.fr/alerte/feed/', source: 'CERT-FR Alertes (ANSSI)', layer: 1, weight_boost: 15 },
    { url: 'https://www.jpcert.or.jp/rss/jpcert.rdf', source: 'JPCERT/CC (JP)', layer: 1, weight_boost: 12 },
    { url: 'https://jvn.jp/rss/jvn.rdf', source: 'JVN (JP)', layer: 1, weight_boost: 10 },
    { url: 'https://advisories.ncsc.nl/rss/advisories', source: 'NCSC-NL Advisories', layer: 1, weight_boost: 15 },
    { url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', source: 'NCSC UK', layer: 1, weight_boost: 15 },
    { url: 'https://www.incibe.es/en/incibe-cert/alerta-temprana/avisos/feed', source: 'INCIBE-CERT (ES)', layer: 1, weight_boost: 12 },
    { url: 'https://cert.pl/en/rss.xml', source: 'CERT.PL', layer: 1, weight_boost: 12 },
    { url: 'https://ccb.belgium.be/advisories.xml', source: 'CERT-BE (BE)', layer: 1, weight_boost: 12 },
    { url: 'https://www.kb.cert.org/vuls/atomfeed/', source: 'CERT/CC Vulnerability Notes', layer: 1, weight_boost: 15 },
    { url: 'https://www.cert.se/feed.rss', source: 'CERT-SE (SE)', layer: 1, weight_boost: 10 },
    { url: 'https://cert.europa.eu/publications/security-advisories-rss', source: 'CERT-EU Advisories', layer: 1, weight_boost: 15 },
    // TAG não publica RSS próprio; sai pelo Google Security Blog, que carrega os
    // relatórios do Threat Analysis Group.
    { url: 'https://feeds.feedburner.com/GoogleOnlineSecurityBlog', source: 'Google TAG Blog', layer: 1, weight_boost: 15 },

    // Layer 2 — TI news & reporting
    { url: 'https://www.bleepingcomputer.com/feed/', source: 'BleepingComputer', layer: 2, weight_boost: 10 },
    { url: 'https://feeds.feedburner.com/TheHackersNews', source: 'The Hacker News', layer: 2, weight_boost: 10 },
    { url: 'https://feeds.feedburner.com/Securityweek', source: 'SecurityWeek', layer: 2, weight_boost: 10 },
    { url: 'https://krebsonsecurity.com/feed/', source: 'Krebs on Security', layer: 2, weight_boost: 10 },
    { url: 'https://therecord.media/feed/', source: 'The Record', layer: 2, weight_boost: 5 },
    { url: 'https://www.darkreading.com/rss.xml', source: 'Dark Reading', layer: 2, weight_boost: 10 },
    { url: 'https://www.helpnetsecurity.com/feed/', source: 'Help Net Security', layer: 2, weight_boost: 10 },
    { url: 'https://www.recordedfuture.com/feed', source: 'Recorded Future', layer: 2, weight_boost: 10 },
    { url: 'https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest', source: 'Malpedia', layer: 2, weight_boost: 8 },
    { url: 'https://www.proofpoint.com/us/threat-insight-blog.xml', source: 'Proofpoint TI', layer: 2, weight_boost: 12 },
    { url: 'https://www.infosecurity-magazine.com/rss/news/', source: 'Infosecurity Magazine', layer: 2, weight_boost: 10 },
    { url: 'https://www.theregister.com/security/headlines.atom', source: 'The Register Security', layer: 2, weight_boost: 10 },
    { url: 'https://www.wired.com/feed/category/security/latest/rss', source: 'Wired Security', layer: 2, weight_boost: 8 },
    { url: 'https://darkwebinformer.com/rss/', source: 'Dark Web Informer', layer: 2, weight_boost: 8 },
    { url: 'https://www.hipaajournal.com/feed/', source: 'HIPAA Journal', layer: 2, weight_boost: 6 },
    { url: 'https://arstechnica.com/security/feed/', source: 'Ars Technica Security', layer: 2, weight_boost: 8 },

    // Layer 3 — Threat research labs
    { url: 'https://isc.sans.edu/rssfeed_full.xml', source: 'SANS ISC', layer: 3, weight_boost: 10 },
    { url: 'https://blog.talosintelligence.com/rss/', source: 'Cisco Talos', layer: 3, weight_boost: 15 },
    { url: 'https://unit42.paloaltonetworks.com/feed/', source: 'Palo Alto Unit 42', layer: 3, weight_boost: 15 },
    { url: 'https://research.checkpoint.com/feed/', source: 'Check Point Research', layer: 3, weight_boost: 10 },
    { url: 'https://securelist.com/feed/', source: 'Kaspersky Securelist', layer: 3, weight_boost: 12 },
    { url: 'https://www.volexity.com/feed/', source: 'Volexity', layer: 3, weight_boost: 12 },
    { url: 'https://www.group-ib.com/blog/rss.xml', source: 'Group-IB', layer: 3, weight_boost: 12 },
    // O host feeds.fortinet.com serve com certificado de *.feedblitz.com — o
    // hostname não bate e o TLS é recusado por qualquer cliente que valide.
    // O host canônico do FeedBlitz entrega o mesmo feed, com cert válido.
    { url: 'https://feeds.feedblitz.com/fortinet/blog/threat-research', source: 'FortiGuard Labs', layer: 3, weight_boost: 15 },
    { url: 'https://unit42.paloaltonetworks.com/category/top-cyberthreats/feed/', source: 'Unit 42 Top Cyberthreats', layer: 3, weight_boost: 15 },
    { url: 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v/', source: 'Mandiant', layer: 3, weight_boost: 15 },
    { url: 'https://www.elastic.co/security-labs/rss/feed.xml', source: 'Elastic Security', layer: 3, weight_boost: 5 },
    { url: 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/', source: 'Google Cloud Threat Intelligence', layer: 3, weight_boost: 15 },
    { url: 'https://www.reversinglabs.com/blog/rss.xml', source: 'ReversingLabs', layer: 3, weight_boost: 10 },
    { url: 'https://www.sekoia.com/blog/rss.xml', source: 'Sekoia', layer: 3, weight_boost: 12 },
    { url: 'https://securitylabs.datadoghq.com/rss/feed.xml', source: 'Datadog Security Labs', layer: 3, weight_boost: 10 },
    { url: 'https://www.wiz.io/feed/rss.xml', source: 'Wiz Blog', layer: 3, weight_boost: 10 },
    { url: 'https://www.malwarebytes.com/blog/feed/', source: 'Malwarebytes TI', layer: 3, weight_boost: 10 },
    { url: 'https://cyble.com/blog/feed/', source: 'Cyble', layer: 3, weight_boost: 10 },
    { url: 'https://any.run/cybersecurity-blog/rss/', source: 'ANY.RUN Blog', layer: 3, weight_boost: 8 },
    { url: 'https://blog.aquasec.com/rss.xml', source: 'Aqua Security', layer: 3, weight_boost: 8 },
    { url: 'https://trustedsec.com/feed.rss', source: 'TrustedSec', layer: 3, weight_boost: 10 },
    { url: 'https://industrialcyber.co/feed/', source: 'Industrial Cyber', layer: 3, weight_boost: 10, categories: ['OT/ICS'] },
    { url: 'https://www.securityweek.com/category/ics-ot/feed/', source: 'SecurityWeek ICS/OT', layer: 2, weight_boost: 10, categories: ['OT/ICS'] },
    { url: 'https://br.claroty.com/team82/disclosure-dashboard/feed', source: 'Claroty Team82 Disclosures', layer: 1, weight_boost: 20, categories: ['OT/ICS'] },
    { url: 'https://productcert.siemens.com/productcert/rss/advisories.atom', source: 'Siemens ProductCERT Advisories', layer: 1, weight_boost: 20, categories: ['OT/ICS'] },
    { url: 'https://productcert.siemens.com/productcert/rss/alerts.atom', source: 'Siemens ProductCERT Alerts', layer: 1, weight_boost: 15, categories: ['OT/ICS'] },
    { url: 'https://objective-see.org/rss.xml', source: 'Objective-See', layer: 3, weight_boost: 8 },
    // Sophos removida: as duas URLs travam a renegociação TLS e nunca respondem
    // pra um cliente sem navegador (bot mitigation), confirmado em 2026-09-15
    // com curl puro contra ambas — não é falha transitória que um retry resolve,
    // é bloqueio permanente. Mantida como URL, não linha em branco, pra quem for
    // reativar não perder o porquê de ter saído.
    // { url: 'https://www.sophos.com/en-us/category/security-operations/feed', source: 'Sophos Security Operations', layer: 3, weight_boost: 8 },
    // { url: 'https://www.sophos.com/en-us/category/threat-research/feed', source: 'Sophos Threat Research', layer: 3, weight_boost: 10 },
    { url: 'https://www.cybereason.com/blog/rss.xml', source: 'Cybereason', layer: 3, weight_boost: 8 },
    { url: 'https://www.huntress.com/blog/rss.xml', source: 'Huntress Blog', layer: 3, weight_boost: 12 },
    { url: 'https://www.kelacyber.com/blog/feed/', source: 'KELA Cyber Blog', layer: 3, weight_boost: 10 },
    { url: 'https://www.rapid7.com/blog/rss/', source: 'Rapid7 Blog', layer: 3, weight_boost: 10 },
    { url: 'https://intel471.com/blog/feed', source: 'Intel 471 Blog', layer: 3, weight_boost: 12 },
    { url: 'https://feeds.feedburner.com/TrendMicroResearch', source: 'Trend Micro Research', layer: 3, weight_boost: 12 },
    // Sophos X-Ops: news.sophos.com redireciona pro mesmo www.sophos.com que já
    // tínhamos descartado por bloqueio de TLS/bot mitigation permanente (ver nota
    // acima). Não adicionada — não existe outro domínio publicando o mesmo feed.

    // Layer 4 — LATAM / BR regional
    { url: 'https://www.cisoadvisor.com.br/feed/', source: 'CISO Advisor BR', layer: 4, weight_boost: 15 },
    { url: 'https://thehack.com.br/rss/', source: 'The Hack', layer: 4, weight_boost: 10 },
    { url: 'https://www.cert.br/rss/certbr-rss.xml', source: 'CERT.br', layer: 4, weight_boost: 12 },
    // Health-ISAC e CTIR Gov (gov.br) não têm feed RSS público — Health-ISAC é
    // conteúdo fechado a membros, e CTIR Gov não expõe /RSS em nenhum caminho
    // testado (confirmado 2026-10-08).
];

// ─── Article body + IOC artifacts ──────────────────────────────────────────
// Two ways a report hides its indicators from a <p>-only scraper:
//   1. an inline IOC *table* (or code block / bullet list) — no <p> in sight;
//   2. no list at all, just a link to an appendix elsewhere (Arctic Wolf ships
//      its IOCs in a GitHub repo, linked as "our official public GitHub
//      repository" — the word IOC appears nowhere in the anchor text).
// So: read the tables too, and match candidate artifacts on the HREF.
const ARTICLE_BOILERPLATE = /^(advertisement|scroll to continue|related\s*:|written by|subscribe|sign up|sponsored|©|cookie|share this|read more|tags:|follow us|newsletter|sign up to)/i;
const ARTICLE_CHROME = 'script,style,noscript,nav,aside,footer,header,form,iframe,figure,figcaption,.ad,.ads,.advertisement,.related,.newsletter,.share,.social,[class*="related-article"],[class*="promo"],[class*="sidebar"]';

const contentRoot = ($) => {
    for (const sel of ['article', 'main']) {
        const el = $(sel).first();
        if (el.length) return el;
    }
    return $('body');
};

export function extractReadableText(html) {
    try {
        const $ = cheerio.load(html);
        // A raiz sai ANTES da limpeza, e a limpeza roda DENTRO dela. Quando o
        // remove() era global ele podia apagar o documento inteiro: o WordPress
        // marca com `no-sidebar` a página que NÃO tem sidebar, o seletor
        // [class*="sidebar"] casava com essa classe no <body>, e o artigo sumia.
        // Medido em 2026-08-27: 67% dos artigos de uma amostra de 18 (todos os
        // do Unit 42) voltavam vazios daqui — e isso também deixava o boletim
        // gerado a partir dessas URLs sem texto nenhum.
        const page = contentRoot($);
        // Publisher templates often put related headlines and sidebar feeds
        // INSIDE <article>. Prefer the actual body before extracting entities.
        const body = page.find('[itemprop="articleBody"], .articleBody, .zox-post-body, .entry-content, .article-content, .post-content').first();
        const root = body.length ? body : page;
        root.find(ARTICLE_CHROME).remove();
        const blocks = new Set();
        // Document order, so the narrative reaches the model in one piece. A <p>
        // still needs to look like prose (45+ chars); a table cell holding
        // "evil[.]com" or a hash does not.
        root.find('p, li, td, th, pre, code').each((_, el) => {
            const node = $(el);
            if (el.tagName === 'code' && node.parents('pre').length) return;
            const t = node.text().replace(/\s+/g, ' ').trim();
            const min = el.tagName === 'p' ? 45 : 3;
            if (t.length < min || t.length > 2000) return;
            if (ARTICLE_BOILERPLATE.test(t)) return;
            if (/\(@\w+\)\s+is\s+(a|the|senior|managing)/i.test(t)) return;
            blocks.add(t);
        });
        return [...blocks].join('\n\n');
    } catch {
        return '';
    }
}

// Hosts we are willing to follow one hop into. Anything else (including a .csv
// on a random host) is left alone: an article-controlled URL is an SSRF and
// prompt-injection vector, and these four cover where vendors actually park
// their indicator files.
const ARTIFACT_HOSTS = /^(?:www\.)?(?:github\.com|gist\.github\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com)$/i;
const ARTIFACT_FILE = /\.(?:csv|txt|json|ioc|iocs|yara|yar|stix|misp)$/i;
export const ARTIFACT_TEXT_FILE = /\.(?:csv|txt|json|md|ioc|iocs|yara|yar|stix|misp|ya?ml)$/i;

/** Links in the article that plausibly carry its indicator list. */
export function collectArtifactLinks(html, baseUrl, max = 3) {
    const links = [];
    try {
        const $ = cheerio.load(html);
        $(ARTICLE_CHROME).remove();
        contentRoot($).find('a[href]').each((_, el) => {
            if (links.length >= max) return false;
            let u;
            try { u = new URL($(el).attr('href'), baseUrl); } catch { return; }
            if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
            if (!ARTIFACT_HOSTS.test(u.hostname)) return;
            const segments = u.pathname.split('/').filter(Boolean);
            // github.com/<org> alone is a profile link, not an appendix.
            if (segments.length < 2 && !ARTIFACT_FILE.test(u.pathname)) return;
            u.hash = '';
            const href = u.toString();
            if (!links.includes(href)) links.push(href);
        });
    } catch { /* unparseable page: no links, no crash */ }
    return links;
}

/**
 * Map a GitHub UI URL onto something fetchable as text.
 *   blob/<ref>/<path>  → the raw file
 *   tree/<ref>/<path>  → a directory listing (contents API), one call, no recursion
 *   <org>/<repo>       → the repo root listing
 * Returns null for non-GitHub URLs — fetch those as-is.
 */
export function githubArtifact(url) {
    let u;
    try { u = new URL(url); } catch { return null; }
    if (!/^(?:www\.)?github\.com$/i.test(u.hostname)) return null;

    const [owner, repo, kind, ref, ...rest] = u.pathname.split('/').filter(Boolean);
    if (!owner || !repo) return null;
    const path = rest.join('/');

    if (kind === 'blob' && ref) {
        return { kind: 'raw', url: `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}` };
    }
    if (kind === 'tree' && ref) {
        return { kind: 'dir', url: `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}` };
    }
    if (!kind) {
        return { kind: 'dir', url: `https://api.github.com/repos/${owner}/${repo}/contents/` };
    }
    return null;
}

// ─── Proteção de terminologia na tradução ──────────────────────────────────
//
// O caminho sem LLM traduz o artigo pelo Google Translate, que não sabe que
// "Buffer Overflow" é nome de classe de vulnerabilidade e devolve "estouro de
// buffer" — termo que não casa com nada que o analista vá pesquisar depois. A
// saída é mascarar os termos antes de traduzir e repô-los na volta.
//
// Nomes próprios (malware, atores, produtos) ficam de fora da lista de
// propósito: são milhares e mudam toda semana, e o tradutor já costuma
// preservá-los por não reconhecê-los. Aqui entram só os termos que ELE conhece
// e por isso traduz.
const PROTECTED_TERMS = [
    'buffer overflow', 'stack overflow', 'heap overflow', 'integer overflow',
    'sql injection', 'command injection', 'code injection', 'prompt injection',
    'cross-site scripting', 'cross-site request forgery', 'server-side request forgery',
    'use-after-free', 'double free', 'out-of-bounds read', 'out-of-bounds write',
    'path traversal', 'directory traversal', 'race condition', 'type confusion',
    'remote code execution', 'arbitrary code execution', 'privilege escalation',
    'denial of service', 'man-in-the-middle', 'supply chain attack',
    'deserialization', 'memory corruption', 'zero-day', 'proof of concept',
    'threat actor', 'threat hunting', 'kill chain', 'lateral movement',
    'brute force', 'credential stuffing', 'living off the land',
];

// Mais longo primeiro: senão "code injection" seria comido por "injection" se
// algum dia um termo curto entrar na lista e virar prefixo de outro.
const PROTECTED_RE = new RegExp(
    `\\b(?:${[...PROTECTED_TERMS].sort((a, b) => b.length - a.length).map(escapeRe).join('|')})\\b`,
    'gi',
);

// Marcador alfanumérico sem espaço: o tradutor não reconhece como palavra e
// costuma repassar intacto.
// ponytail: se ele mexer no marcador além do que restoreTerms tolera, o termo
// não volta — por isso o chamador confere e cai no texto original.
const MARKER = 'TSQ';

/** Troca cada termo técnico por um marcador. Devolve o texto e os termos na ordem. */
export function protectTerms(text) {
    const terms = [];
    const masked = String(text ?? '').replace(PROTECTED_RE, (match) => {
        terms.push(match);
        return `${MARKER}${terms.length - 1}`;
    });
    return { masked, terms };
}

/**
 * Repõe os termos, aceitando que o tradutor tenha mudado a caixa do marcador ou
 * metido um espaço no meio. O `\b` no fim impede que o marcador 1 case dentro
 * do 10.
 */
export function restoreTerms(text, terms) {
    let out = String(text ?? '');
    (terms || []).forEach((term, index) => {
        out = out.replace(new RegExp(`${MARKER}\\s*${index}\\b`, 'gi'), term);
    });
    return out;
}
