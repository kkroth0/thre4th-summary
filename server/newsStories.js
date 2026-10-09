import crypto from 'node:crypto';
import { NEWS_CATEGORIES } from './newsCategories.js';

// The same story reaches us from Reuters, BleepingComputer and CISA within
// hours, worded three different ways. De-duplicating by URL — which is all the
// feed did before — keeps all three. Grouping them is what lets a reader follow
// one story instead of re-reading it.
//
// Every rule here is deterministic: the same input has to group the same way
// today and next month, so nothing depends on the current feed's word
// frequencies, on the wall clock, or on iteration order of a Map built elsewhere.

export const STORY_RETENTION_DAYS = 60;
export const STORY_ACTIVE_DAYS = 14;

const DAY = 86400000;
const MIN_RARE_FOR_JACCARD = 2;
// 0.34 = um terço dos termos raros da união. Medido contra o feed real: em 0.5
// duas coberturas da mesma notícia em veículos diferentes quase nunca batem
// ("SilkParasite Espionage Campaign Targets Central Asian Governments" x
// "SilkParasite Threatens Central Asian Orgs With Flurry of RATs"), porque cada
// redação escolhe as próprias palavras. Baixar só foi seguro depois de tirar o
// vocabulário de classe de falha do COMMON_CTI abaixo.
const JACCARD_THRESHOLD = 0.34;

// Acima disto o artigo é um apanhado, não uma matéria sobre uma falha: "CISA
// Adds Four Known Exploited Vulnerabilities to Catalog" cita quatro CVEs sem
// tratar de nenhum. Os CVEs dele continuam indexados e visíveis; o que ele
// perde é o poder de dizer que duas matérias são a mesma.
//
// Sem isso o apanhado vira um eixo: toda matéria sobre qualquer um dos CVEs
// dele casa pela regra 1 e, como o absorve recomputa os sinais a cada rodada, o
// merge é transitivo — MLflow entra pelo apanhado de 20/08, que já tinha
// entrado pelo de 19/08, que puxou o Windows IKE. A semana inteira num card.
const MAX_TOPIC_CVES = 3;

// Same reasoning, same risk, for named campaigns: a "top campaigns of the
// year" retrospective naming several unrelated operations would otherwise
// become a transitive merge hub exactly like the CVE-catalog case above —
// campaigns are treated as sufficient evidence alone (see isSameStory), so
// they need the same guard CVEs get, not the lighter one-source-mention
// tolerance that corroboration-gated signals (actor/malware/TTP) can rely on.
const MAX_TOPIC_CAMPAIGNS = 3;

// O apanhado se anuncia na manchete. O cap acima só pega quem lista muitos
// CVEs; isto pega quem lista poucos e mesmo assim é catálogo — "CISA Adds Three
// Known Exploited Vulnerabilities to Catalog" tem exatamente três e virava eixo
// de um card com seis matérias sem relação: Cisco ASA, Patch Tuesday da
// Microsoft, Lazarus e KEV, todas de assunto diferente.
const ROUNDUP = /\b(?:adds?\b[^.]{0,40}\bto\b[^.]{0,12}\bcatalog|known exploited vulnerabilit|patch tuesday|security update guide|weekly (?:recap|roundup)|roundup|resumo da semana|vulnerability summary|advance notification|security holes|(?:fixes|fixed|patches|patched|plugs|corrige|corrigem)\s+(?:nearly\s+|almost\s+|more than\s+|over\s+|mais de\s+|quase\s+)?\d+\s+(?:security\s+)?(?:flaws|bugs|vulnerabilit|holes|issues|falhas|vulnerabilidades|brechas))/i;

// Static, not derived from the day's feed: a frequency-based stoplist would make
// the same pair of headlines group differently tomorrow.
const STOPWORDS = new Set([
    'about', 'after', 'against', 'amid', 'from', 'into', 'over', 'that', 'this', 'their', 'them', 'these', 'those',
    'with', 'without', 'have', 'been', 'were', 'will', 'more', 'most', 'than', 'then', 'they', 'what', 'when', 'which',
    'para', 'pelo', 'pela', 'como', 'mais', 'menos', 'sobre', 'entre', 'apos', 'contra', 'seus', 'suas', 'este', 'esta',
    'isso', 'pode', 'podem', 'sera', 'estao', 'foram',
    // Contagem não é assunto. Sem isto "CISA Adds Four ..." lê como série
    // diferente de "CISA Adds Two ...", que é a mesma publicação recorrente.
    'zero', 'three', 'four', 'five', 'seven', 'eight', 'nine', 'dez', 'ten',
    'eleven', 'twelve', 'dois', 'duas', 'tres', 'quatro', 'cinco', 'seis',
    'sete', 'oito', 'nove', 'onze', 'doze',
]);

const COMMON_CTI = new Set([
    'security', 'seguranca', 'vulnerability', 'vulnerabilities', 'vulnerabilidade', 'vulnerabilidades',
    'attack', 'attacks', 'ataque', 'ataques', 'attacker', 'attackers', 'atacante', 'atacantes',
    'flaw', 'flaws', 'falha', 'falhas', 'patch', 'patches', 'patched', 'update', 'updates', 'atualizacao',
    'report', 'reports', 'relatorio', 'research', 'researchers', 'pesquisadores', 'hacker', 'hackers',
    'threat', 'threats', 'ameaca', 'ameacas', 'cyber', 'cyberattack', 'malicious', 'malicioso',
    'exploit', 'exploits', 'exploited', 'exploitation', 'exploracao', 'critical', 'critico', 'critica',
    'warns', 'warning', 'alerta', 'alertam', 'says', 'said', 'novo', 'nova', 'released', 'reveals',
    'bug', 'bugs', 'issue', 'issues', 'code', 'codigo', 'data', 'dados', 'users', 'usuarios',
    // Sit in a large share of CTI headlines, so they carry no grouping signal.
    'ransomware', 'zero-day', '0-day', 'abuse', 'abused', 'abusing', 'targeting', 'targeted',
    // Órgão que ASSINA o aviso, não o assunto dele. "CISA" encabeça uma fatia
    // enorme das manchetes; deixá-lo contar fazia MLflow e Windows IKE
    // dividirem dois dos três termos e baterem o limiar do jaccard.
    'cisa', 'nist', 'enisa', 'cert',
    // Metade de "exploração ativa" / "active exploitation" — o resto do par já
    // está aqui, e sozinho ele só soma ruído.
    'ativa', 'ativo', 'active', 'actively', 'ativamente',
    // Classe da falha, não assunto. Sem isto "OriginLab Origin Viewer OPJ File
    // Parsing Out-Of-Bounds Write" e "BlackBerry QNX File Parsing Out-Of-Bounds
    // Write" dividem quatro termos e viram a mesma história.
    'parsing', 'file', 'files', 'arquivo', 'arquivos', 'memory', 'memoria', 'corruption', 'corrupcao',
    'overflow', 'underflow', 'buffer', 'heap', 'stack', 'bounds', 'write', 'read', 'free', 'use-after-free',
    'injection', 'injecao', 'command', 'comando', 'comandos', 'execution', 'execucao', 'remote', 'remoto', 'remota',
    'disclosure', 'divulgacao', 'information', 'informacao', 'denial', 'service', 'servico',
    'authentication', 'autenticacao', 'bypass', 'privilege', 'privileges', 'privilegio', 'privilegios',
    'escalation', 'escalonamento', 'traversal', 'deserialization', 'desserializacao', 'arbitrary', 'arbitrario',
    'improper', 'unauthenticated', 'authenticated', 'handling', 'multiple', 'multiplas', 'multiplos',
    // Vocabulário de release: separa canal e plataforma, não assunto.
    'beta', 'stable', 'desktop', 'channel', 'release', 'releases', 'version', 'versao', 'build', 'builds',
    // Manchete de PSIRT que é só o nome da classe ("Server-Side Request
    // Forgery (SSRF)") fica sem termo raro nenhum, e o mínimo de dois termos
    // já a impede de casar com qualquer coisa.
    'server-side', 'client-side', 'cross-site', 'scripting', 'request', 'forgery', 'ssrf', 'csrf', 'xss',
    'race', 'condition', 'dereference', 'pointer', 'uninitialized', 'integer', 'path', 'null',
    'out-of-bounds', 'use-after', 'after-free', 'hardcoded', 'insecure', 'weak', 'missing', 'exposure',
]);

const normalize = (value) =>
    String(value || '').toLowerCase().normalize('NFD').replace(/\p{Mn}/gu, '');

export function rareTerms(title) {
    const seen = new Set();
    for (const token of normalize(title).split(/[^a-z0-9-]+/)) {
        if (token.length < 4) continue;
        if (STOPWORDS.has(token) || COMMON_CTI.has(token)) continue;
        seen.add(token);
    }
    return [...seen].sort();
}

const jaccard = (a, b) => {
    if (a.size < MIN_RARE_FOR_JACCARD || b.size < MIN_RARE_FOR_JACCARD) return 0;
    let shared = 0;
    for (const term of a) if (b.has(term)) shared += 1;
    return shared / (a.size + b.size - shared);
};

const overlaps = (a, b) => [...a].some((value) => b.has(value));

const storyId = (link) => crypto.createHash('sha1').update(String(link || '')).digest('hex').slice(0, 12);

/**
 * Identidade de série: veículo + o esqueleto da manchete.
 *
 * "CISA Adds One Known Exploited Vulnerability to Catalog" sai quase todo dia,
 * variando só a contagem. Duas edições são assuntos diferentes com a mesma
 * manchete — para o jaccard a similaridade é 1.0, e sem isto a série inteira
 * desaba num card só.
 *
 * A chave usa os termos raros, não o título literal: é o que faz "Adds One" e
 * "Adds Two" caírem na mesma série. E é estreita o bastante para não colar
 * matérias de verdade do mesmo veículo — "…no MLflow" e "…no Windows IKE"
 * guardam `mlflow` e `windows`, então são séries diferentes.
 */
const seriesKey = (source) => `${source.source}\u0000${rareTerms(source.title).join(' ')}`;

const dayOf = (value) => String(value || '').slice(0, 10);

// Hash/domain/URL IOCs already passed extractIOCs's false-positive filters
// (benign resolvers, shared platforms, code hosts) before ever reaching here —
// what remains is high-precision attacker infrastructure, the same tier of
// evidence as a shared CVE. A bare IP is weaker: bulletproof/VPS hosting
// recycles the same address across unrelated campaigns, and cloud ranges get
// reassigned between tenants, so it needs the same corroboration as an actor
// or malware match, never sufficient alone.
const normIoc = (value) => String(value || '').trim().toLowerCase();
const iocsOf = (source) => {
    // A ROUNDUP-titled source ("this week's indicators") is exactly the kind of
    // digest that would otherwise become a false merge axis across unrelated
    // campaigns — same guard already applied to CVEs above. No count cap is
    // applied beyond that: a single layer-3 deep dive can legitimately list
    // 20-50 real IOCs about ONE campaign, and capping by count would penalize
    // exactly the deep single-subject research this signal is meant to catch.
    if (!source.iocs || ROUNDUP.test(source.title)) return { strong: [], weak: [] };
    const { ips = [], domains = [], hashes = [], urls = [] } = source.iocs;
    return {
        strong: [...hashes, ...domains, ...urls].map(normIoc).filter(Boolean),
        weak: ips.map(normIoc).filter(Boolean),
    };
};

const signals = (story) => {
    const rare = new Set(story.sources.flatMap((source) => rareTerms(source.title)));
    // The actor's/malware's/campaign's own name is in both headlines by
    // definition — two unrelated Cl0p stories both say "Cl0p", and that is not
    // evidence they are one story. The corroboration-gated rules below need
    // evidence from somewhere else in the title.
    const actorTokens = new Set(story.actors.flatMap((actor) => rareTerms(`${actor.name} ${actor.matched || ''}`)));
    const malwareTokens = new Set(story.malware.flatMap((m) => rareTerms(`${m.name} ${m.matched || ''}`)));
    const campaignTokens = new Set(story.campaigns.flatMap((c) => rareTerms(`${c.name} ${c.matched || ''}`)));
    // Só os CVEs de fontes que tratam de um assunto entram na regra 1. Story
    // gravada antes de as fontes carregarem `cves` cai no conjunto da story —
    // volta ao comportamento antigo em vez de perder o sinal.
    const scoped = story.sources.filter((source) => Array.isArray(source.cves));
    const mergeCves = scoped.length
        ? new Set(scoped.flatMap((source) => (
            source.cves.length <= MAX_TOPIC_CVES && !ROUNDUP.test(source.title) ? source.cves : []
        )))
        : new Set(story.cves);

    // Same scoping as CVEs, same cap, same reason: campaigns are sufficient
    // evidence alone (see isSameStory), so a "top campaigns" retrospective
    // needs the same guard a CVE catalog digest does.
    const scopedCampaigns = story.sources.filter((source) => Array.isArray(source.campaigns));
    const mergeCampaigns = scopedCampaigns.length
        ? new Set(scopedCampaigns.flatMap((source) => (
            source.campaigns.length <= MAX_TOPIC_CAMPAIGNS && !ROUNDUP.test(source.title) ? source.campaigns : []
        )))
        : new Set(story.campaigns.map((c) => c.id));

    return {
        cves: mergeCves,
        campaigns: mergeCampaigns,
        actors: new Set(story.actors.map((actor) => actor.id)),
        malware: new Set(story.malware.map((m) => m.id)),
        // TTPs are corroboration-gated (see isSameStory), the same light tier
        // as a bare IP — so only the ROUNDUP title guard applies, no count cap:
        // one deep-dive article legitimately touching several techniques of
        // ONE campaign isn't a digest the way citing many CVEs/campaigns is.
        ttps: new Set(story.sources.flatMap((source) => (
            !ROUNDUP.test(source.title) ? (source.ttps || []) : []
        ))),
        strongIocs: new Set(story.sources.flatMap((source) => iocsOf(source).strong)),
        weakIocs: new Set(story.sources.flatMap((source) => iocsOf(source).weak)),
        rare,
        // Excludes actor-, malware- AND campaign-name tokens: without this,
        // two unrelated "LummaC2" stories would have the entity's own name
        // survive as a shared rare term, satisfying their own corroboration
        // requirement with nothing but the entity's name — the exact hole
        // rareBeyondActors already closed for actors, extended to every
        // entity type that needs corroboration.
        rareBeyondEntities: new Set([...rare].filter((term) =>
            !actorTokens.has(term) && !malwareTokens.has(term) && !campaignTokens.has(term))),
        series: new Set(story.sources.map(seriesKey)),
        outlets: new Set(story.sources.map((source) => source.source)),
        days: new Set(story.sources.map((source) => dayOf(source.pubDate))),
    };
};

// Dentro de um veículo, manchete parecida em outro dia é a próxima edição, não
// a mesma notícia: "Chrome Beta for Android Update" de terça não é a de quinta.
// O veto de série acima exige o mesmo esqueleto de manchete; este cobre a
// variação — sem ele, onze releases do Chrome viravam um card só.
const sameOutletOtherDay = (a, b) => overlaps(a.outlets, b.outlets) && !overlaps(a.days, b.days);

const isSameStory = (a, b) => {
    // Mesma manchete do mesmo veículo em outro dia: é a próxima edição de uma
    // série, não a mesma notícia. Veta antes das três regras — um merge errado
    // custa mais que um agrupamento perdido, e o boletim do dia seguinte
    // apareceria enterrado dentro do card do dia anterior.
    if (overlaps(a.series, b.series) && !overlaps(a.days, b.days)) return false;

    if (overlaps(a.cves, b.cves)) return true;
    // A named campaign ("Operation Dream Job") identifies one specific bounded
    // operation, unlike an actor or malware family — those are persistent
    // brands that recur across many unrelated incidents, which is exactly why
    // they need corroboration below. Two articles naming the same campaign are
    // near-certainly covering the same thing, so this is sufficient alone —
    // scoped against roundup digests the same way CVEs are (see MAX_TOPIC_CAMPAIGNS).
    if (overlaps(a.campaigns, b.campaigns)) return true;
    // Hash/domain/URL: sufficient alone, same tier as CVE (see iocsOf above).
    if (overlaps(a.strongIocs, b.strongIocs)) return true;
    // Malware never sufficient alone, even for a nonce-word family name: a
    // popular commodity family (LummaC2/AsyncRAT/RedLine) gets an unrelated
    // headline most weeks (new technique, takedown, new victim) — treating
    // "same family" as proof of "same story" would be a worse false-merge axis
    // than the "Cl0p twice, different victims" case the actor rule already
    // guards against below.
    if (overlaps(a.malware, b.malware) && overlaps(a.rareBeyondEntities, b.rareBeyondEntities)) return true;
    if (overlaps(a.actors, b.actors) && overlaps(a.rareBeyondEntities, b.rareBeyondEntities)) return true;
    // Bare IP: same corroboration requirement as actor/malware, never alone.
    if (overlaps(a.weakIocs, b.weakIocs) && overlaps(a.rareBeyondEntities, b.rareBeyondEntities)) return true;
    // Weakest tier: a single shared MITRE technique (T1566 phishing, T1486
    // ransomware encryption...) is common to a huge share of unrelated
    // articles, so it only ever corroborates, exactly like a bare IP.
    if (overlaps(a.ttps, b.ttps) && overlaps(a.rareBeyondEntities, b.rareBeyondEntities)) return true;
    if (sameOutletOtherDay(a, b)) return false;
    return jaccard(a.rare, b.rare) >= JACCARD_THRESHOLD;
};

const newStory = (item) => ({
    id: storyId(item.link),
    title: item.title,
    firstSeen: item.pubDate,
    lastSeen: item.pubDate,
    cves: [...(item.cves || [])],
    actors: [...(item.actors || [])],
    malware: [...(item.malware || [])],
    campaigns: [...(item.campaigns || [])],
    // item.newsCategories is the navigation bucket list from categorize();
    // item.categories is scoreArticle's unrelated CTI scoring labels — do not
    // read that one here.
    categories: [...(item.newsCategories || [])],
    primaryCategory: item.primaryCategory || null,
    score: item.score || 0,
    sources: [{
        source: item.source, link: item.link, title: item.title,
        pubDate: item.pubDate, score: item.score || 0, severity: item.severity || null,
        // Por fonte, não só somados na story: é o que permite separar a matéria
        // sobre uma falha do apanhado que lista dez. Campanha segue o mesmo
        // motivo (ids só, como os CVEs — os objetos completos ficam na union
        // no nível da story, abaixo).
        cves: [...(item.cves || [])],
        campaigns: (item.campaigns || []).map((c) => c.id),
        // TTPs (ids T####) também por fonte: é o que faz um artigo-resumo de
        // uma técnica só não contar como corroboração de outro sobre uma
        // técnica totalmente diferente.
        ttps: [...(item.ttpIds || [])],
        // Guardado SÓ por fonte, ao contrário dos cves. A pergunta que isso
        // responde é "qual artigo mencionou este IP" — a união na story não
        // responde nada que a varredura das fontes não responda, e seria um
        // segundo lugar para dessincronizar.
        iocs: item.iocs || null,
    }],
});

// Absorbs `extra` into `target`, keeping the older identity: a link already
// shared with a colleague has to keep working.
const absorb = (target, extra) => {
    const older = target.firstSeen <= extra.firstSeen ? target : extra;
    const merged = {
        ...target,
        id: older.id,
        firstSeen: older.firstSeen,
        lastSeen: target.lastSeen >= extra.lastSeen ? target.lastSeen : extra.lastSeen,
        cves: [...new Set([...target.cves, ...extra.cves])],
        categories: [...new Set([...target.categories, ...extra.categories])],
        score: Math.max(target.score, extra.score),
        sources: [...target.sources],
    };
    const byId = new Map(target.actors.map((actor) => [actor.id, actor]));
    for (const actor of extra.actors) if (!byId.has(actor.id)) byId.set(actor.id, actor);
    merged.actors = [...byId.values()];

    const malwareById = new Map(target.malware.map((m) => [m.id, m]));
    for (const m of extra.malware) if (!malwareById.has(m.id)) malwareById.set(m.id, m);
    merged.malware = [...malwareById.values()];

    const campaignById = new Map(target.campaigns.map((c) => [c.id, c]));
    for (const c of extra.campaigns) if (!campaignById.has(c.id)) campaignById.set(c.id, c);
    merged.campaigns = [...campaignById.values()];

    const links = new Set(target.sources.map((source) => source.link));
    for (const source of extra.sources) if (!links.has(source.link)) merged.sources.push(source);

    // Title follows the loudest source, which is the one a reader recognises:
    // a CISA directive outranks a two-paragraph writeup. Primary category
    // follows precedence order (the first in NEWS_CATEGORIES that matches).
    const loudest = merged.sources.reduce((best, source) => (source.score > best.score ? source : best), merged.sources[0]);
    merged.title = loudest.title;
    const orderedCategories = NEWS_CATEGORIES.filter((cat) => merged.categories.includes(cat));
    merged.primaryCategory = orderedCategories[0] || null;
    merged.categories = orderedCategories;
    return merged;
};

export function mergeIntoStories(stories, items, now) {
    const cutoff = now.getTime() - STORY_RETENTION_DAYS * DAY;
    const activeSince = now.getTime() - STORY_ACTIVE_DAYS * DAY;
    let result = (Array.isArray(stories) ? stories : []).filter((story) => new Date(story.lastSeen).getTime() >= cutoff);

    const known = new Set(result.flatMap((story) => story.sources.map((source) => source.link)));

    // Sorted by date so the merge order — and therefore the surviving id — does
    // not depend on the order the feeds happened to answer in.
    const incoming = (Array.isArray(items) ? items : [])
        .filter((item) => item && item.link && !known.has(item.link))
        .sort((a, b) => String(a.pubDate).localeCompare(String(b.pubDate)) || String(a.link).localeCompare(String(b.link)));

    for (const item of incoming) {
        if (known.has(item.link)) continue;
        known.add(item.link);

        let candidate = newStory(item);
        const rest = [];
        for (const story of result) {
            const active = new Date(story.lastSeen).getTime() >= activeSince;
            // Recomputed each round: absorbing one story hands the candidate a CVE
            // or an actor that can make the next story match too.
            if (active && isSameStory(signals(story), signals(candidate))) {
                candidate = absorb(story, candidate);
            } else {
                rest.push(story);
            }
        }
        rest.push(candidate);
        result = rest;
    }

    return result.sort((a, b) => String(b.lastSeen).localeCompare(String(a.lastSeen)) || a.id.localeCompare(b.id));
}
