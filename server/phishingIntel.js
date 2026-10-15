// Phishing evidence is scoped to the publication, not inherited from a vendor,
// a campaign catalogue or the recommendations at the end of an advisory.
export const PHISHING_VERSION = 'phishing-v2';
const normalize = value => String(value || '').normalize('NFD').replace(/\p{Mn}/gu, '').replace(/[‐‑–—]/g, '-');
const rule = (label, pattern, options = {}) => ({ label, re: new RegExp(pattern, 'i'), ...options });

export const PHISHING_RULES = [
    rule('ClickFix', '\\b(?:click[- ]?fix|fake captchas?|captchas? fals[oa]s?|fake cloudflare (?:check|verification)|verificacao falsa (?:do )?cloudflare)\\b'),
    rule('AiTM / Adversary-in-the-Middle', '\\b(?:aitm|adversary[- ]in[- ]the[- ]middle|browser[- ]in[- ]the[- ]middle|bitm)\\b'),
    rule('Device Code Phishing', '\\b(?:device[- ]code (?:phishing|attack|lure)|phishing (?:de|por|com) (?:codigo de dispositivo|device code))\\b'),
    rule('Device Code Phishing', '\\bdevice[- ]code (?:login|authentication|flow)\\b', { context: /\b(?:phish\w*|attack\w*|atacante\w*|malicious|malicios\w*)\b/i }),
    rule('Browser-in-the-Browser', '\\b(?:bitb|browser[- ]in[- ]the[- ]browser)\\b'),
    rule('Vishing', '\\b(?:vishing|voice phishing|spearphishing voice|phishing (?:por|de) voz|golpes? por telefone|fraudadores por telefone|falsa central|fake help[- ]?desk)\\b'),
    rule('Smishing', '\\b(?:smishing|sms phishing|(?:phishing|golpes?) (?:por|via) sms|malicious text messages|mensagens? sms (?:falsas?|maliciosas?))\\b'),
    rule('Quishing', '\\b(?:quishing|qr[- ]?code phishing|(?:phishing|golpes?) (?:por|via|com|de) qr[- ]?code|malicious qr[- ]?codes?|qr[- ]?codes? (?:falsos?|maliciosos?))\\b'),
    rule('OAuth Consent Phishing', '\\b(?:oauth consent phishing|consent phishing|phishing de consentimento|malicious oauth (?:apps?|applications?)|aplicativos? oauth maliciosos?)\\b'),
    rule('Phishing-as-a-Service', '\\b(?:phaas|phishing[- ]as[- ]a[- ]service|phish[- ]?kits?|phishing kits?|kits? de phishing)\\b'),
    rule('Business Email Compromise', '\\b(?:business e[- ]?mail compromise|bec|payment (?:diversion|fraud)|invoice fraud|fraude de (?:pagamento|fatura)|desvio de pagamentos?)\\b', { context: /\b(?:business email|e-?mail|payment|invoice|fraud|pagamento|fatura|engenharia social|social engineering)\b/i }),
    rule('Brand Impersonation', '\\b(?:brand impersonation|impersonat(?:e[sd]?|ing|ion)|spoofs?|spoofed|spoofing|posing as|masquerad(?:e[sd]?|ing)|se pass(?:am|ava|ando|aram|ar)? por|impostores?|imita(?:m|ndo)?|fals[oa]s? (?:chatgpt|gemini|claude)|fake (?:chatgpt|gemini|claude))\\b', { context: /\b(?:phish\w*|fake|fals[oa]s?|steal|rouba\w*|credential\w*|credencia\w*|scam|golpes?|malicious|malicios\w*|fraud\w*|login|victims?|vitimas?|campaign|campanha|attackers?|atacantes?|instala\w*|screenconnect|anydesk|e-mails?)\b/i }),
    rule('Credential Harvesting', '\\b(?:credential (?:harvesting|phishing)|harvest(?:s|ed|ing)? (?:\w+ ){0,3}(?:credentials|passwords)|(?:capture|steal|collect)(?:s|d|ing)? (?:\w+ ){0,4}(?:credentials|passwords|mfa codes)|(?:captura|coleta|roubo|rouba)(?:m|r|ndo)? (?:de )?(?:credenciais|senhas)|fake login (?:pages?|portals?)|paginas? falsas? de login)\\b'),
    rule('Tech Support Scam', '\\b(?:tech(?:nical)? support scams?|golpes? de suporte (?:tecnico|falso)|scareware)\\b'),
    rule('Pig Butchering', '\\b(?:pig[- ]butchering|romance[- ]investment scam|golpe (?:de|do) investimento (?:cripto|falso))\\b'),
    rule('Callback Phishing', '\\b(?:call[- ]?back phishing|callback scam|phishing de retorno de chamada)\\b'),
    rule('Typosquatting', '\\b(?:typosquatting|typo[- ]squatting|lookalike domains?|dominios? (?:parecidos|imitados))\\b', { context: /\b(?:phish\w*|malicious|malicios\w*|fake|fals\w*|scam|golpe|credential\w*|roubo|attack\w*|attacker\w*|campanha|campaign)\b/i }),
    rule('Fake Recruiter / Job Lure', '\\b(?:fake recruiters?|job lures?|fake job interviews?|entrevistas? (?:de emprego )?falsas?|iscas? de emprego|vagas? falsas?|golpes? de emprego|falsos? recrutadores?)\\b'),
    rule('Spearphishing Attachment', '\\b(?:spear[- ]?phishing attachments?|malicious (?:email )?attachments?|anexos? maliciosos?|phishing com (?:pdf|lnk|anexo))\\b'),
    rule('Spearphishing Link', '\\b(?:spear[- ]?phishing links?|phishing (?:emails? |e-mails? )?(?:with|containing) (?:malicious )?links?|phishing (?:por|via|com) links?)\\b'),
    rule('Malvertising', '\\b(?:malvertising|malicious ads?|anuncios? maliciosos?)\\b', { adjunct: true }),
    rule('SEO Poisoning', '\\b(?:seo poisoning|search poisoning|envenenamento (?:de buscas|de seo))\\b', { adjunct: true }),
    rule('RMM Abuse', '\\b(?:rmm abuse|abuso de rmm|screenconnect|anydesk|atera|net ?support|remote monitoring and management)\\b', { adjunct: true }),
    rule('SaaS Abuse', '\\b(?:power bi|google (?:docs|forms|apps script)|microsoft forms|direct send|sharepoint|onedrive)\\b', { adjunct: true }),
    rule('Calendar Phishing', '\\b(?:calendar phishing|malicious calendar invites?|convites? (?:de calendario )?(?:falsos?|maliciosos?))\\b', { adjunct: true }),
    rule('Messaging App Lure', '\\b(?:whatsapp|telegram|slack|microsoft teams|discord|messaging app lures?)\\b', { adjunct: true }),
    rule('Fake Sponsorship', '\\b(?:fake sponsorships?|patrocinios? falsos?|fals[oa]s? propostas? de patrocinio)\\b'),
    rule('Fake Download / Update', '\\b(?:fake (?:downloads?|installers?|updates?)|fals[oa]s? (?:downloads?|instaladores?|atualizacoes)|downloads? falsos?|instaladores? falsos?|atualizac(?:ao|oes) falsas?)\\b'),
    rule('Social Engineering Lure', '\\b(?:iscas?(?: falsas?)?|(?:sites?|lojas?|apps?|aplicativos?|repositorios?|convites?|documentos?|faturas?|cartas?|mensagens?|portais)(?: \\w+){0,3} fals[oa]s?|fals[oa]s? (?:solicitacoes|auditorias?|suporte|verificadores?))\\b', { context: /\b(?:campanh\w*|golpes?|atacantes?|malicios\w*|malware|backdoor|infostealer|rouba\w*|fraud\w*|engan\w*|drain\w*|credencia\w*|senha\w*|acesso|instala\w*|phish\w*|alvos?|mira\w*|e-mails?)\b/i }),
    rule('Email Prompt Injection', '\\b(?:prompt injections?|injecoes? de prompt|injecao de prompt)\\b', { adjunct: true, context: /\b(?:e-?mail|message|mensagem)\b/i }),
];

const PHISH = /\b(?:phishing|spear[- ]?phishing|phishkits?|engenharia social|social engineering|malicious emails?|fraudulent emails?|e-mails? (?:falsos?|maliciosos?)|iscas? (?:de|via)|fake (?:pages?|websites?|portals?)|paginas? falsas?)\b/i;
const INCIDENT = /\b(?:campaigns?|campanhas?|attackers?|atacantes?|criminals?|criminosos?|victims?|vitimas?|targets?|targeted|targeting|atinge\w*|alvos?|golpes?|scams?|abuses?|abused|abusing|abusa\w*|delivers?|delivering|distributes?|spreads?|entrega\w*|distribui\w*|rouba\w*|steals?|stealing|captura\w*|impersonat\w*|impostores?|fake|fals[oa]s?|uncovered|discovered|identificou|identified)\b/i;
const GUIDANCE = /\b(?:recommend\w*|recomend\w*|best practices|boas praticas|awareness training|training|treinamento|simulat\w*|phishing[- ]resistant|anti[- ]phishing|how to (?:prevent|avoid|protect)|como (?:evitar|prevenir)|protect against|defend against|could (?:lead|be used)|may be used|pode(?:m)? (?:levar|ser usado))\b/i;
const FOOTER = /^(?:\d+[.)]\s*)?(?:mitigations?|recommendations?|recomendacoes|related (?:articles|posts|stories)|read more|references|referencias|subscribe|newsletter|general security recommendations|recommended security measures)\b/i;
const NEGATION = /(?:no evidence of|not (?:using |a )?|does not (?:use |involve )?|did not (?:use |involve )?|sem evidencias? de|nao (?:usa |houve |envolve |e ))\s*$/i;
const unique = values => [...new Set(values)];

// Capitalization before "kit" is not evidence of a family name (e.g.
// "AI-powered phishing kit" or "AiTM kit"). Retain recognized families,
// explicit naming/quotation, or the more specific coined "Name Phishkit".
const KNOWN_KITS = new Set(['evilginx', 'evilginx2', 'evilproxy', 'tycoon2fa', 'mamba2fa', 'rockstar2fa', 'greatness', 'flowerstorm', 'darcula', 'lucid', '16shop', 'onnx', 'strox', 'modlishka', 'gophish', 'wazza']);
const KIT_DESCRIPTOR = /^(?:new|the|this|phishing|microsoft|ai[-_]?powered|aitm|bitm|advanced|sophisticated|custom|open[-_]?source|free|commercial|credential)$/i;
function namedKits(context) {
    const result = [];
    for (const match of context.matchAll(/\b([A-Z0-9][A-Za-z0-9_-]{2,35})\s+([Pp]hishkit|[Pp]hishing kit|[Kk]it|\(PhaaS\))/g)) {
        if (!KIT_DESCRIPTOR.test(match[1]) && (KNOWN_KITS.has(match[1].toLowerCase()) || /^phishkit$/i.test(match[2]))) result.push(match[1]);
    }
    for (const match of context.matchAll(/\b(?:phishing kit|phishkit|kit de phishing)\s+(?:named|called|dubbed|conhecido como|chamado|denominado)\s+["'“‘]?([A-Z0-9][A-Za-z0-9_-]{2,35})\b|["“‘]([A-Z0-9][A-Za-z0-9_-]{2,35})["”’]\s+(?:phishing kit|phishkit)\b/g)) {
        const name = match[1] || match[2];
        if (!KIT_DESCRIPTOR.test(name)) result.push(name);
    }
    return unique(result);
}

export function phishingTextBlocks({ title, description, text, bodyText } = {}) {
    const blocks = [];
    for (const [field, value] of [['title', title], ['summary', description || text], ['body', bodyText]]) {
        for (const raw of String(value || '').slice(0, 32000).split(/\n+|(?<=[.!?;])\s+/)) {
            const snippet = raw.replace(/<[^>]+>/g, ' ').replace(/https?:\/\/\S+/g, ' ').replace(/\s+/g, ' ').trim();
            if (field === 'body' && FOOTER.test(normalize(snippet))) break;
            if (snippet) blocks.push({ field, snippet, normalized: normalize(snippet) });
        }
    }
    return blocks;
}

const actionable = (block, match) => {
    const local = block.normalized.slice(Math.max(0, match.index - 160), match.index + match[0].length + 180);
    if (NEGATION.test(block.normalized.slice(Math.max(0, match.index - 60), match.index))) return false;
    if (GUIDANCE.test(local)) return false;
    return block.field !== 'body' || INCIDENT.test(local);
};

// Matching terms are retained as evidence. No score/confidence number is
// presented as a measured probability, and a generic phishing report is not
// assigned a more specific technique merely to fill an empty cell.
export function analyzePhishing(input = {}) {
    const blocks = phishingTextBlocks(input);
    const evidence = [];
    for (const block of blocks) {
        const match = PHISH.exec(block.normalized);
        if (match && actionable(block, match) && !evidence.some(e => e.kind === 'classification' && e.field === block.field)) evidence.push({ kind: 'classification', label: 'Phishing', field: block.field, term: match[0], snippet: block.snippet.slice(0, 420) });
        for (const r of PHISHING_RULES.filter(r => !r.adjunct)) {
            const match = r.re.exec(block.normalized);
            if (!match || !actionable(block, match) || (r.context && !r.context.test(block.normalized.slice(Math.max(0, match.index - 160), match.index + 240)))) continue;
            if (!evidence.some(e => e.kind === 'technique' && e.label === r.label)) evidence.push({ kind: 'technique', label: r.label, field: block.field, term: match[0], snippet: block.snippet.slice(0, 420) });
        }
    }
    const detected = evidence.length > 0;
    if (detected) for (const r of PHISHING_RULES.filter(r => r.adjunct)) {
        for (const block of blocks) {
            const match = r.re.exec(block.normalized);
            if (!match || !actionable(block, match) || (r.context && !r.context.test(block.normalized))) continue;
            // A legitimate service in a publisher footer is not an attack vector.
            if (!INCIDENT.test(block.normalized) && !PHISH.test(block.normalized)) continue;
            evidence.push({ kind: 'technique', label: r.label, field: block.field, term: match[0], snippet: block.snippet.slice(0, 420) });
            break;
        }
    }
    const techniques = unique(evidence.filter(e => e.kind === 'technique').map(e => e.label));
    const relevant = blocks.filter(b => !GUIDANCE.test(b.normalized));
    const context = relevant.map(b => b.normalized).join('\n');
    const details = [];
    const add = (kind, label, block, term) => {
        if (!details.some(e => e.kind === kind && e.label === label)) details.push({ kind, label, field: block.field, term, snippet: block.snippet.slice(0, 420) });
    };
    if (detected) for (const block of relevant) {
        // Victim geography follows the targeting cue. An actor's nationality
        // before that cue does not become the victim's region.
        const target = /\b(?:target(?:s|ed|ing)?|victims?|against|alvos?|atinge\w*|atingiu|miram?|contra|vitimas?)\b/i.exec(block.normalized);
        const targetText = target ? block.normalized.slice(target.index).split(/\b(?:attributed to|linked to|based in|backed by|operated by|originating from|atribuido a|ligado ao|sediado em)\b/i)[0] : '';
        for (const [label, re] of SECTORS) if (re.test(targetText)) add('sector', label, block, re.exec(targetText)[0]);
        for (const [label, re] of REGIONS) if (re.test(targetText)) add('region', label, block, re.exec(targetText)[0]);
        for (const [label, re] of [['United States', /\bUS\b/], ['Europe', /\b(?:EU|UE)\b/], ['Australia', /\bAU\b/]]) if (re.test(targetText)) add('region', label, block, re.exec(targetText)[0]);
        const deception = /\b(?:impersonat\w*|spoof\w*|posing as|masquerad\w*|fake|fals[oa]s?|imita\w*|se passam? por|themed|tema)\b/i.exec(block.normalized);
        if (deception) {
            const brandText = block.normalized.slice(Math.max(0, deception.index - 50), deception.index + 170);
            for (const [label, re] of BRANDS) if (re.test(brandText)) add('brand', label, block, re.exec(brandText)[0]);
        }
        if (!INCIDENT.test(block.normalized) && !evidence.some(e => e.snippet === block.snippet.slice(0, 420))) continue;
        for (const [label, re] of VECTORS) if (re.test(block.normalized)) add('vector', label, block, re.exec(block.normalized)[0]);
    }
    const inferred = [];
    const mitre = (id, reason) => { if (!inferred.some(e => e.id === id)) inferred.push({ id, basis: 'inferred', reason }); };
    if (detected) {
        if (PHISH.test(context)) mitre('T1566', 'Phishing descrito na publicação');
        const pairs = [['Spearphishing Attachment', 'T1566.001'], ['Spearphishing Link', 'T1566.002'], ['Vishing', 'T1566.004'], ['AiTM / Adversary-in-the-Middle', 'T1557'], ['Device Code Phishing', 'T1528'], ['RMM Abuse', 'T1219']];
        for (const [technique, id] of pairs) if (techniques.includes(technique)) mitre(id, technique);
        if (techniques.includes('Credential Harvesting') && /\b(?:login|portals?|pages?|paginas?|sites?|websites?)\b/i.test(context)) mitre('T1056.003', 'Captura de credenciais em portal web');
        if (techniques.includes('Messaging App Lure') && /\b(?:via|through|using|por|pelo|pela|abuses?)\s+(?:whatsapp|telegram|slack|microsoft teams|discord)\b/i.test(context)) mitre('T1566.003', 'Isca em serviço de mensagens');
        if (techniques.includes('ClickFix') && /\b(?:click[- ]?fix|copy.{0,30}paste|copiar.{0,30}colar)\b/i.test(context)) mitre('T1204.004', 'ClickFix / execução por copiar e colar');
    }
    const reportedIds = detected ? unique(context.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []) : [];
    const ttps = [...reportedIds.map(id => ({ id, basis: 'reported', reason: 'ID citado na publicação' })), ...inferred.filter(e => !reportedIds.includes(e.id))];
    const kits = detected ? namedKits(context) : [];
    const stateEvidence = detected && relevant.find(block => {
        const match = /\b(?:nation[- ]state|state[- ]sponsored|government[- ]backed|estado[- ]nacao|patrocinad[oa]s? (?:pelo|por) (?:estado|governo)|ligad[oa]s? ao governo)\b/i.exec(block.normalized);
        return match && actionable(block, match);
    });
    if (stateEvidence) add('attribution', 'Nation-state citado', stateEvidence, 'nation-state');
    const nationState = stateEvidence ? 'reported' : 'unknown';
    return {
        version: PHISHING_VERSION, detected, techniques, primaryTechnique: techniques[0] || null,
        vectors: details.filter(e => e.kind === 'vector').map(e => e.label),
        brands: details.filter(e => e.kind === 'brand').map(e => e.label),
        sectors: details.filter(e => e.kind === 'sector').map(e => e.label),
        regions: details.filter(e => e.kind === 'region').map(e => e.label),
        kits, nationState, ttps, evidence: [...evidence, ...details],
    };
}

const specs = list => list.map(([label, pattern]) => [label, new RegExp(pattern, 'i')]);
const SECTORS = specs([
    ['Financial', '\\b(?:banks?|banking|bancos?|bancari\\w*|financial (?:sector|institutions?|organizations?)|setor financeiro|instituicoes financeiras|fintech|credit unions?)\\b'],
    ['Government', '\\b(?:governments?|governo|governamental|ministerios?|public sector|setor publico)\\b'],
    ['Manufacturing', '\\b(?:manufactur\\w*|manufatura|industrial|industria|factories|fabricas?)\\b'],
    ['Energy', '\\b(?:energy|energia|power grid|oil and gas|utilities|petroleo)\\b'],
    ['Healthcare', '\\b(?:healthcare|hospitals?|hospitais|saude|pharma\\w*|farmaceut\\w*)\\b'],
    ['Education', '\\b(?:universit\\w*|universidades?|schools?|escolas?|academia|education|educacao)\\b'],
    ['Transportation', '\\b(?:airports?|aeroportos?|airlines?|logistics|logistica|transporte)\\b'],
    ['Retail', '\\b(?:retail|varejo|e-commerce|ecommerce|lojas?)\\b'],
    ['Technology', '\\b(?:technology companies|empresas de tecnologia|software vendors|saas providers)\\b'],
    ['Defense', '\\b(?:defen[cs]e|military|militar\\w*|defesa)\\b'],
    ['Developers', '\\b(?:developers?|desenvolvedores?|devops)\\b'],
    ['Content Creators', '\\b(?:youtubers?|content creators?|criadores? de conteudo)\\b'],
    ['Cryptocurrency', '\\b(?:crypto users|cryptocurrency users|usuarios de cripto|carteiras cripto)\\b'],
]);
const REGIONS = specs([
    ['Brazil', '\\b(?:brazil(?:ian)?|brasil|brasileir[oa]s?)\\b'], ['Latin America', '\\b(?:latam|latin america|america latina)\\b'],
    ['United States', '\\b(?:united states|u\\.s\\.|usa|eua|estados unidos|american)\\b'],
    ['Europe', '\\b(?:europe|european|europa|europeus?)\\b'], ['Australia', '\\b(?:australia|australian|australianos?)\\b'],
    ['Ukraine', '\\b(?:ukraine|ukrainian|ucrania|ucranianos?)\\b'], ['United Kingdom', '\\b(?:united kingdom|uk|british|reino unido)\\b'],
    ['Japan', '\\b(?:japan|japanese|japao|japones\\w*)\\b'], ['Taiwan', '\\btaiwan(?:ese)?\\b'],
    ['Poland', '\\b(?:poland|polish|polonia)\\b'], ['India', '\\bindia(?:n)?\\b'],
    ['China', '\\b(?:china|chinese|chines\\w*)\\b'], ['Russia', '\\b(?:russia|russian|russos?)\\b'],
    ['Mexico', '\\b(?:mexico|mexican|mexican[oa]s?)\\b'], ['Argentina', '\\bargentin[ao](?:s|n)?\\b'],
    ['Chile', '\\b(?:chile|chilean|chilen[oa]s?)\\b'], ['Colombia', '\\bcolombia(?:n|nos?)?\\b'], ['Peru', '\\b(?:peru|peruvian|peruan[oa]s?)\\b'],
    ['Global', '\\b(?:globally|worldwide|global|multiple countries|varios paises|mundo todo)\\b'],
]);
const BRANDS = specs([
    ['Microsoft', '\\bmicrosoft\\b'], ['Microsoft 365', '\\b(?:microsoft 365|office 365|m365)\\b'],
    ['Adobe', '\\badobe\\b'], ['Google', '\\bgoogle\\b'], ['YouTube', '\\byoutube\\b'],
    ['Cloudflare', '\\bcloudflare\\b'], ['ChatGPT', '\\bchatgpt\\b'], ['Gemini', '\\bgemini\\b'], ['Claude', '\\bclaude\\b'],
    ['DocuSign', '\\bdocusign\\b'], ['PayPal', '\\bpaypal\\b'], ['Apple', '\\bapple\\b'],
    ['Amazon', '\\bamazon\\b'], ['WhatsApp', '\\bwhatsapp\\b'], ['Facebook', '\\bfacebook\\b'],
    ['Instagram', '\\binstagram\\b'], ['LinkedIn', '\\blinkedin\\b'], ['Correios', '\\bcorreios\\b'],
    ['Receita Federal', '\\breceita federal\\b'], ['Rabby', '\\brabby\\b'], ['OKX', '\\bokx\\b'],
]);
const VECTORS = specs([
    ['E-mail', '\\b(?:emails?|e-mails?|correio eletronico|malspam)\\b'], ['SMS', '\\b(?:sms|text messages?|smishing)\\b'],
    ['Voice', '\\b(?:vishing|voice phishing|phone calls?|ligacoes?|chamadas? telefonicas?|falsa central)\\b'],
    ['QR Code', '\\b(?:qr[- ]?codes?|quishing)\\b'], ['WhatsApp', '\\bwhatsapp\\b'], ['Telegram', '\\btelegram\\b'],
    ['Microsoft Teams', '\\bmicrosoft teams\\b'], ['Slack', '\\bslack\\b'], ['Discord', '\\bdiscord\\b'],
    ['Web', '\\b(?:websites?|web pages?|portals?|paginas?|sites?|login pages?)\\b'],
    ['Advertising', '\\b(?:malvertising|malicious ads|anuncios maliciosos|ad portals)\\b'],
]);
