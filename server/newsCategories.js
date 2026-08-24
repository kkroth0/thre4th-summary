// Navigation buckets for the news feed. CTI_CATEGORIES in ctiIntel.js is a
// *scoring* taxonomy — nine overlapping labels that add up to a relevance
// number. These seven are what a reader clicks, so they are separate on purpose.
//
// A story lands in every bucket that matches; `primary` is the first one in this
// order, which is what the card shows. Order is precedence, not importance.
//
// Os dois últimos são baldes de *setor*, não de ameaça: ficam no fim para nunca
// roubarem a categoria principal de "ransomware em hospital" ou "APT em banco".
export const NEWS_CATEGORIES = [
    'Ransomware', 'APTs', 'Data Leaks', 'OT/ICS', 'Vulnerabilities', 'Malware', 'Microsoft',
    'Finance/Banking', 'Health/Pharma',
];

const RANSOMWARE = /\b(?:ransomware|double extortion|dupla extors[aã]o|leak site|data leak site|ransom note)\b/i;
const NATION_STATE = /\b(?:nation[- ]state|state[- ]sponsored|state sponsored|advanced persistent threat|cyber ?espionage|espionagem)\b/i;
const DATA_LEAK = /\b(?:data breach|data leak|breached|vazamento de dados|vazamento|exposed \d[\d.,]* (?:records|customers|users))\b/i;
// Fornecedores e protocolos OT: only unambiguous terms. BMS (Bristol-Myers ticker),
// Emerson (conglomerate + sobrenome), Honeywell (aeroespacial/EPI/doméstica),
// Copeland (sobrenome) são excluídos — mesmo princípio de MICROSOFT acima.
const OT_ICS = /\b(?:ot\/ics|ics\/ot|\bics\b|scada|\bplc\b|\bhmi\b|modbus|opc ua|profinet|dnp3|purdue|safety instrumented|siemens s7|simatic|rockwell|allen[- ]bradley|schneider electric|codesys|phoenix contact|danfoss|enocean|lontalk|yokogawa|mitsubishi electric|omron|wago|beckhoff|moxa|advantech|iec ?6(?:1850|0870)|ethernet\/ip|bacnet|building management system)\b/i;
const VULN_CLASS = /\b(?:remote code execution|\brce\b|arbitrary code|authentication bypass|auth bypass|privilege escalation|deserialization|path traversal|sql injection|zero[- ]day|0-day|actively exploited|exploited in the wild|proof[- ]of[- ]concept)\b/i;
// exchange/teams/outlook/defender are ordinary CTI-headline words on their own
// ("crypto exchange", "red teams", "threat outlook", "a defender perspective"),
// so only the qualified forms count — same treatment as the other alternatives
// here, which are already unambiguous.
const MICROSOFT = /\b(?:microsoft|windows|exchange server|exchange online|sharepoint|azure|entra id|active directory|office 365|microsoft 365|microsoft teams|microsoft defender|windows defender|microsoft outlook|outlook\.com|hyper-v)\b/i;

// Setor financeiro em PT/ES/EN. Termos genéricos ("financial impact", "credit
// card data") ficam de fora: aparecem em manchete de qualquer setor. SWIFT e PIX
// só nas formas qualificadas — "swift" é palavra comum e linguagem da Apple.
const FINANCE = /\b(?:bank|banks|banking|banco|bancos|banc[aá]ri[ao]s?|banca|fintechs?|credit union|cooperativa de cr[eé]dito|financial (?:institutions?|services|sector|regulator)|institui[cç][aã]o financeira|institui[cç][oõ]es financeiras|servi[cç]os financeiros|setor financeiro|sector (?:financiero|bancario)|instituci[oó]n(?:es)? financieras?|servicios financieros|payment (?:processor|gateway)|processadora de pagamentos|pasarela de pagos|swift network|rede swift|sistema pix|pagamentos? pix|\batms?\b|caixas? eletr[oô]nicos?|cajeros? autom[aá]ticos?|brokerage|corretoras?|bolsa de valores|stock exchange|crypto(?:currency)? exchange|bolsa de criptomoedas)\b/i;

// Saúde e farmacêutica em PT/ES/EN. "saúde"/"salud" sozinhos são vagos demais
// (saúde financeira, salud del mercado), então só as formas compostas contam.
const HEALTH = /\b(?:hospitals?|hospitais|hospitalar(?:es)?|health ?care|health (?:system|network|provider|insurer)|medical (?:center|centre|records?|devices?)|clinics?|cl[ií]nicas?|patient (?:data|records?)|dados de pacientes|datos de pacientes|prontu[aá]rios?|historia cl[ií]nica|registros m[eé]dicos|dispositivos? m[eé]dicos?|equipamentos? m[eé]dicos?|pharma(?:ceutical)?s?|farmac[eê]uticas?|farmac[ée]uticas?|farm[aá]cias?|drugmakers?|laborat[oó]rio farmac[eê]utico|hipaa|\bhl7\b|dicom|\behr\b|electronic health records?|(?:setor|rede|sistema|plano|operadora|unidade|secretaria)s? de sa[uú]de|(?:sector|sistema|centro)s? de salud)\b/i;

// Malware families that are not ransomware — ransomware has its own bucket.
const MALWARE_THREATS = new Set(['Trojan', 'Infostealer', 'Wiper', 'Backdoor', 'Botnet', 'Spyware', 'Rootkit']);

export function categorize(item) {
    if (!item || typeof item !== 'object') return { categories: [], primary: null };

    const title = `${item.title || ''}`;
    const text = `${title} ${item.description || ''}`;
    const threats = Array.isArray(item.threats) ? item.threats : [];
    const cves = Array.isArray(item.cves) ? item.cves : [];
    const actors = Array.isArray(item.actors) ? item.actors : [];

    const hits = {
        Ransomware: threats.includes('Ransomware') || RANSOMWARE.test(text),
        // A codename-grade attribution is the strongest APT signal there is.
        APTs: actors.some((a) => a && (a.via === 'codename' || a.via === 'multiword')) || NATION_STATE.test(text),
        'Data Leaks': DATA_LEAK.test(text),
        'OT/ICS': OT_ICS.test(text),
        Vulnerabilities: cves.length > 0 || VULN_CLASS.test(text),
        Malware: threats.some((t) => MALWARE_THREATS.has(t)),
        Microsoft: MICROSOFT.test(text),
        // Setor sai só do título: é quem *foi atacado*, e a manchete sempre diz.
        // O corpo cita setor de passagem ("from healthcare and finance to
        // manufacturing…") em qualquer post de marketing, e isso carimbava o
        // balde errado. Menos recall, muito menos ruído.
        // ponytail: título só. Se faltar notícia cujo alvo aparece só no corpo,
        // o passo é um segundo regex, com os termos inequívocos (hospital,
        // banco, prontuário, ATM), rodando também na descrição.
        'Finance/Banking': FINANCE.test(title),
        'Health/Pharma': HEALTH.test(title),
    };

    const categories = NEWS_CATEGORIES.filter((name) => hits[name]);
    return { categories, primary: categories[0] || null };
}
