import crypto from 'node:crypto';
import { setImmediate as yieldLoop } from 'node:timers/promises';
import { canonicalArticleUrl } from './feedCollector.js';
import { NEWS_CATEGORIES } from './newsCategories.js';
import { sanitizeStoredMalware } from './malwareMatch.js';

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
export const CORRELATION_VERSION = 3;

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
const ROUNDUP = /\b(?:adds?\b[^.]{0,40}\bto\b[^.]{0,12}\bcatalog|known exploited vulnerabilit|patch tuesday|security update guide|weekly (?:recap|roundup)|roundup|resumo da semana|vulnerability summary|advance notification|security holes|security hardening|(?:fixes|fixed|patches|patched|plugs|corrige|corrigem)\s+(?:a\s+)?(?:nearly\s+|almost\s+|more than\s+|over\s+|mais de\s+|quase\s+)?(?:\d+|dozen|two|three|four|five|six|seven|eight|nine|ten|twelve|duas|tres|quatro|cinco|doze)\s+(?:critical\s+|security\s+|criticas\s+)?(?:flaws|bugs|vulnerabilit|holes|issues|falhas|vulnerabilidades|brechas))/i;

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
    // Method, generic outcome and editorial verbs are relations, not events.
    'phishing', 'breach', 'breaches', 'incident', 'incidents', 'access', 'enables', 'enable',
    'deliver', 'delivers', 'delivery', 'targets', 'target', 'alleged', 'health', 'healthcare',
    'hardening', 'advisory', 'advisories', 'october', 'september', 'august',
    'malware', 'botnet', 'trojan', 'stealer', 'infostealer', 'campaign', 'campaigns',
    'emergency', 'immediate', 'immediately', 'urgent', 'urgently', 'urges', 'patching', 'admins', 'could', 'lets',
]);

const normalize = (value) =>
    String(value || '').toLowerCase().normalize('NFD').replace(/\p{Mn}/gu, '');

export function rareTerms(title) {
    const seen = new Set();
    for (const token of normalize(title).split(/[^a-z0-9-]+/)) {
        if (token.length < 4) continue;
        if (/^\d+$/.test(token)) continue;
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
    const vendorTokens = new Set(story.sources.flatMap((source) => (source.vendors || []).flatMap((vendor) => rareTerms(`${vendor.name} ${vendor.matched || ''}`))));
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
    const topicCves = (source) => source.topicCves || source.cves;
    const mergeCves = scoped.length
        ? new Set(scoped.flatMap((source) => (
            topicCves(source).length <= MAX_TOPIC_CVES && !ROUNDUP.test(source.title) ? topicCves(source) : []
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
        observedCves: new Set(story.sources.flatMap((source) => topicCves(source) || [])),
        roundup: story.sources.some((source) => ROUNDUP.test(source.title) || (source.campaigns || []).length > MAX_TOPIC_CAMPAIGNS),
        campaigns: mergeCampaigns,
        actors: new Set(story.actors.map((actor) => actor.id)),
        malware: new Set(story.malware.map((m) => m.id)),
        headlineActors: new Set(story.actors.filter((entity) => rareTerms(`${entity.name} ${entity.matched || ''}`).some((term) => rare.has(term))).map((entity) => entity.id)),
        headlineMalware: new Set(story.malware.filter((entity) => rareTerms(`${entity.name} ${entity.matched || ''}`).some((term) => rare.has(term))).map((entity) => entity.id)),
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
        headlineContext: new Set([...rare].filter((term) => !vendorTokens.has(term))),
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
        titles: new Set(story.sources.map((source) => normalize(source.title).trim())),
        recurring: story.sources.some((source) => ROUNDUP.test(source.title) || /\b(?:stable|beta|canary|dev)\b.*\b(?:channel|update)\b/i.test(source.title)),
    };
};

// Dentro de um veículo, manchete parecida em outro dia é a próxima edição, não
// a mesma notícia: "Chrome Beta for Android Update" de terça não é a de quinta.
// O veto de série acima exige o mesmo esqueleto de manchete; este cobre a
// variação — sem ele, onze releases do Chrome viravam um card só.
const sameOutletOtherDay = (a, b) => overlaps(a.outlets, b.outlets) && !overlaps(a.days, b.days);

const shared = (a, b) => [...a].filter((value) => b.has(value));
const decision = (a, b) => {
    const reject = (rule) => ({ sameEvent: false, rule, evidence: [] });
    const accept = (rule, evidence) => ({ sameEvent: true, rule, evidence });
    // Mesma manchete do mesmo veículo em outro dia: é a próxima edição de uma
    // série, não a mesma notícia. Veta antes das três regras — um merge errado
    // custa mais que um agrupamento perdido, e o boletim do dia seguinte
    // apareceria enterrado dentro do card do dia anterior.
    if ((a.recurring || b.recurring) && overlaps(a.series, b.series) && !overlaps(a.days, b.days)) return reject('recurring-edition');
    // Digests retain their extracted facts for research, but cannot join events
    // through ANY signal, including a malware mention or a similar headline.
    if (a.roundup || b.roundup) {
        if (overlaps(a.outlets, b.outlets) && overlaps(a.days, b.days) && overlaps(a.titles, b.titles)
            && a.observedCves.size === b.observedCves.size && shared(a.observedCves, b.observedCves).length === a.observedCves.size) {
            return accept('same-edition', [...a.titles]);
        }
        return reject('multi-topic');
    }
    if (overlaps(a.cves, b.cves)) return accept('shared-cve', shared(a.cves, b.cves));
    // A named campaign ("Operation Dream Job") identifies one specific bounded
    // operation, unlike an actor or malware family — those are persistent
    // brands that recur across many unrelated incidents, which is exactly why
    // they need corroboration below. Two articles naming the same campaign are
    // near-certainly covering the same thing, so this is sufficient alone —
    // scoped against roundup digests the same way CVEs are (see MAX_TOPIC_CAMPAIGNS).
    if (overlaps(a.campaigns, b.campaigns)) return accept('shared-campaign', shared(a.campaigns, b.campaigns));
    // Hash/domain/URL: sufficient alone, same tier as CVE (see iocsOf above).
    if (overlaps(a.strongIocs, b.strongIocs)) return accept('shared-ioc', shared(a.strongIocs, b.strongIocs));
    // Two scoped articles identifying different vulnerabilities need stronger
    // evidence than a similar product headline, actor or technique. A campaign
    // or attacker infrastructure can still prove a shared multi-CVE incident.
    if (a.observedCves.size && b.observedCves.size) return reject('different-cves');
    if ((a.recurring || b.recurring) && overlaps(a.outlets, b.outlets) && !overlaps(a.titles, b.titles)) return reject('different-release-channel');
    if ((a.recurring || b.recurring) && sameOutletOtherDay(a, b)) return reject('recurring-edition');
    if (a.headlineActors.size && b.headlineActors.size && !overlaps(a.headlineActors, b.headlineActors)) return reject('different-headline-actors');
    if (a.headlineMalware.size && b.headlineMalware.size && !overlaps(a.headlineMalware, b.headlineMalware)) return reject('different-headline-malware');
    // Malware never sufficient alone, even for a nonce-word family name: a
    // popular commodity family (LummaC2/AsyncRAT/RedLine) gets an unrelated
    // headline most weeks (new technique, takedown, new victim) — treating
    // "same family" as proof of "same story" would be a worse false-merge axis
    // than the "Cl0p twice, different victims" case the actor rule already
    // guards against below.
    const context = shared(a.rareBeyondEntities, b.rareBeyondEntities);
    const focused = (field, headline) => shared(a[field], b[field]).filter((id) => a[headline].has(id) || b[headline].has(id));
    const malware = focused('malware', 'headlineMalware');
    const actors = focused('actors', 'headlineActors');
    if (context.length && malware.length) return accept('malware-and-context', [...malware, ...context]);
    if (context.length && actors.length) return accept('actor-and-context', [...actors, ...context]);
    // Bare IP: same corroboration requirement as actor/malware, never alone.
    if (overlaps(a.weakIocs, b.weakIocs) && context.length >= 2) return accept('ip-and-context', [...shared(a.weakIocs, b.weakIocs), ...context]);
    // TTPs describe behavior shared by thousands of incidents. They never
    // lower the title threshold or independently establish event identity.
    if (sameOutletOtherDay(a, b)) return reject('different-edition-without-identifier');
    if (shared(a.headlineContext, b.headlineContext).length >= 2 && jaccard(a.rare, b.rare) >= JACCARD_THRESHOLD) return accept('headline-context', shared(a.rare, b.rare));
    return reject('insufficient-evidence');
};

/** Auditable pair decision using only evidence attributed to each publication. */
export function compareNewsSources(left, right, campaigns = []) {
    const asSignals = (source) => signals({ sources: [source], cves: source.cves || [],
        actors: source.actors || [], malware: source.malware || [],
        campaigns: campaigns.filter((campaign) => (source.campaigns || []).includes(campaign.id)),
    });
    const gap = Math.abs(Date.parse(left.pubDate) - Date.parse(right.pubDate));
    if (!Number.isFinite(gap) || gap > STORY_ACTIVE_DAYS * DAY) return { sameEvent: false, rule: 'outside-window', evidence: [] };
    return decision(asSignals(left), asSignals(right));
}

const newStory = (item) => ({
    id: storyId(canonicalArticleUrl(item.link) || item.link),
    aliases: [],
    correlationVersion: CORRELATION_VERSION,
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
        pubDate: item.pubDate, dateInferred: item.dateInferred === true,
        publicationTimeKnown: item.publicationTimeKnown, publicationDateBasis: item.publicationDateBasis, firstCollectedAt: item.firstCollectedAt,
        repository: item.repository, score: item.score || 0, severity: item.severity || null,
        actors: [...(item.actors || [])], malware: [...(item.malware || [])],
        newsCategories: [...(item.newsCategories || [])],
        vendors: [...(item.vendors || [])], assets: [...(item.assets || [])],
        contentHash: item.contentHash || null, extractionVersion: item.extractionVersion || null,
        // Por fonte, não só somados na story: é o que permite separar a matéria
        // sobre uma falha do apanhado que lista dez. Campanha segue o mesmo
        // motivo (ids só, como os CVEs — os objetos completos ficam na union
        // no nível da story, abaixo).
        cves: [...(item.cves || [])],
        topicCves: [...(item.topicCves || item.cves || [])],
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
        // Handle de vendedor de dark web (ver darkWebHandle.js) — por fonte,
        // igual iocs, e pelo mesmo motivo deliberadamente NUNCA entra em
        // signals()/isSameStory(): mesmo vendedor, vítima diferente, é
        // notícia diferente (mesma regra que já vale pra ator). O que isto
        // habilita é "mostrar relacionado" via findRelatedBySeller, não merge.
        sellerHandle: item.sellerHandle || null,
    }],
});

// Absorbs `extra` into `target`, keeping the older identity: a link already
// shared with a colleague has to keep working.
const absorb = (target, extra) => {
    const older = target.firstSeen <= extra.firstSeen ? target : extra;
    const merged = {
        ...target,
        id: older.id,
        aliases: [...new Set([...(target.aliases || []), ...(extra.aliases || []), target.id, extra.id])].filter((id) => id !== older.id),
        correlationVersion: CORRELATION_VERSION,
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

function* mergeStorySteps(stories, items, now) {
    const cutoff = now.getTime() - STORY_RETENTION_DAYS * DAY;
    let result = (Array.isArray(stories) ? stories : []).filter((story) => new Date(story.lastSeen).getTime() >= cutoff);
    if (result.some((story) => story.correlationVersion !== CORRELATION_VERSION)) {
        return yield* rebuildStorySteps(result, items, now);
    }
    const knownSources = new Map(result.flatMap((story) => story.sources.map((source) => [canonicalArticleUrl(source.link) || source.link, source])));
    const sourceOwners = new Map(result.flatMap((story) => story.sources.map((source) => [canonicalArticleUrl(source.link) || source.link, story])));
    const publicationMetadata = new Set(['dateInferred', 'publicationTimeKnown', 'publicationDateBasis', 'firstCollectedAt', 'repository']);
    const signalCache = new WeakMap();
    const sourceSignals = (story, source) => {
        if (signalCache.has(source)) return signalCache.get(source);
        const value = signals({
            ...story, sources: [source], cves: source.cves || [],
            actors: source.actors || [], malware: source.malware || [],
            campaigns: (story.campaigns || []).filter((campaign) => (source.campaigns || []).includes(campaign.id)),
        });
        signalCache.set(source, value);
        return value;
    };
    const directMatch = (story, candidate) => story.sources.some((source) => {
        const article = candidate.sources[0];
        const gap = Math.abs(new Date(source.pubDate).getTime() - new Date(article.pubDate).getTime());
        return gap <= STORY_ACTIVE_DAYS * DAY && decision(sourceSignals(story, source), sourceSignals(candidate, article)).sameEvent;
    });
    const summarize = (story) => {
        const sources = story.sources;
        const byId = (field) => [...new Map(sources.flatMap((source) => source[field] || []).map((entity) => [entity.id, entity])).values()];
        const categories = [...new Set(sources.flatMap((source) => source.newsCategories || []))];
        const ordered = NEWS_CATEGORIES.filter((category) => categories.includes(category));
        const loudest = sources.reduce((best, source) => source.score > best.score ? source : best, sources[0]);
        return { ...story, correlationVersion: CORRELATION_VERSION, title: loudest.title,
            firstSeen: sources.map((source) => source.pubDate).sort()[0],
            lastSeen: sources.map((source) => source.pubDate).sort().at(-1),
            score: Math.max(...sources.map((source) => source.score || 0)),
            cves: [...new Set(sources.flatMap((source) => source.cves || []))],
            actors: sources.every((source) => Array.isArray(source.actors)) ? byId("actors") : story.actors,
            malware: sources.every((source) => Array.isArray(source.malware)) ? byId("malware") : story.malware,
            campaigns: (story.campaigns || []).filter((campaign) => sources.some((source) => (source.campaigns || []).includes(campaign.id))),
            categories: sources.every((source) => Array.isArray(source.newsCategories)) ? ordered : story.categories,
            primaryCategory: sources.every((source) => Array.isArray(source.newsCategories)) ? ordered[0] || null : story.primaryCategory,
        };
    };
    const incoming = (Array.isArray(items) ? items : []).filter((item) => item?.link && new Date(item.pubDate).getTime() >= cutoff)
        .sort((a, b) => String(a.pubDate).localeCompare(String(b.pubDate)) || String(a.link).localeCompare(String(b.link)));
    for (const item of incoming) {
        const unchanged = knownSources.get(canonicalArticleUrl(item.link) || item.link);
        if (item.contentHash && unchanged?.contentHash === item.contentHash && unchanged.extractionVersion === item.extractionVersion) {
            const next = newStory(item).sources[0];
            if (Object.keys(next).every(key => JSON.stringify(next[key] ?? null) === JSON.stringify(unchanged[key] ?? null))) { yield; continue; }
            if (Object.keys(next).filter(key=>!publicationMetadata.has(key)).every(key=>JSON.stringify(next[key]??null)===JSON.stringify(unchanged[key]??null))) {
                const link=canonicalArticleUrl(item.link)||item.link,owner=sourceOwners.get(link),index=result.indexOf(owner);
                if(index>=0){
                    const source={...unchanged,...Object.fromEntries([...publicationMetadata].filter(key=>next[key]!==undefined).map(key=>[key,next[key]]))};
                    const updated={...owner,sources:owner.sources.map(row=>row===unchanged?source:row)};
                    result[index]=updated;
                    for(const row of updated.sources){const key=canonicalArticleUrl(row.link)||row.link;sourceOwners.set(key,updated);knownSources.set(key,row);}
                    yield;continue;
                }
            }
        }
        yield;
        const link = canonicalArticleUrl(item.link) || item.link;
        const direct = newStory({ ...item, link });
        if (JSON.stringify(knownSources.get(link)) === JSON.stringify(direct.sources[0])) continue;
        const ownerIndex = result.findIndex((story) => story.sources.some((source) => (canonicalArticleUrl(source.link) || source.link) === link));
        let candidate = direct;
        if (ownerIndex >= 0) {
            const owner = result[ownerIndex];
            result = result.filter((_, index) => index !== ownerIndex);
            const remaining = owner.sources.filter((source) => (canonicalArticleUrl(source.link) || source.link) !== link);
            if (remaining.length) {
                const anchor = remaining.find((source) => storyId(canonicalArticleUrl(source.link) || source.link) === owner.id);
                const id = anchor ? owner.id : storyId(remaining[0].link);
                const memberIds = new Set(remaining.map((source) => storyId(canonicalArticleUrl(source.link) || source.link)));
                const residual = summarize({ ...owner, id,
                    aliases: (owner.aliases || []).filter((alias) => alias !== direct.id && alias !== id && (owner.id !== direct.id || memberIds.has(alias))), sources: remaining });
                // Removing an updated bridge may disconnect the publications
                // it formerly joined. Re-evaluate the residual group too.
                result.push(...(remaining.length > 1 ? yield* rebuildStorySteps([residual], [], now) : [residual]));
                if (owner.id === direct.id) {
                    candidate.aliases = (owner.aliases || []).filter((alias) => !memberIds.has(alias));
                }
            }
            else candidate = { ...direct, id: owner.id, aliases: owner.aliases || [] };
        }
        // Every match must be supported by the incoming article itself.
        // Signals inherited from one merge cannot manufacture the next merge.
        const potential = [];
        let checked = 0;
        for (const story of result) {
            if (directMatch(story, direct)) potential.push(story);
            if (++checked % 32 === 0) yield;
        }
        let matches = potential.sort((a, b) => a.firstSeen.localeCompare(b.firstSeen) || a.id.localeCompare(b.id));
        // A CVE-less headline may resemble two different advisories. Preserve
        // it independently until stronger evidence arrives instead of using
        // it as a bridge between incompatible CVE clusters.
        const incompatible = (left, right) => {
            const a = signals(left), b = signals(right);
            return a.observedCves.size && b.observedCves.size && !overlaps(a.observedCves, b.observedCves)
                && !overlaps(a.campaigns, b.campaigns) && !overlaps(a.strongIocs, b.strongIocs);
        };
        if (!signals(direct).observedCves.size && matches.some((left, index) => matches.slice(index + 1).some((right) => incompatible(left, right)))) matches = [];
        matches = matches.filter((story) => !incompatible(story, candidate));
        const ids = new Set(matches.map((story) => story.id));
        for (const story of matches) candidate = absorb(story, candidate);
        result = [...result.filter((story) => !ids.has(story.id)), candidate];
        for (const source of candidate.sources) knownSources.set(canonicalArticleUrl(source.link) || source.link, source);
    }
    return result.sort((a, b) => String(b.lastSeen).localeCompare(String(a.lastSeen)) || a.id.localeCompare(b.id));
}

/** Re-evaluate retained publications after a rule change, without copying a
 * story's union onto its individual sources. Incoming extraction overrides
 * stored evidence. Split stories keep old links pointing to their anchor;
 * aliases of the former aggregate are never assigned to multiple stories. */
function* rebuildStorySteps(stories, items = [], now = new Date()) {
    const byLink = new Map();
    for (const story of stories) for (const source of story.sources || []) {
        const link = canonicalArticleUrl(source.link) || source.link;
        if (!link) continue;
        byLink.set(link, { ...source, link,
            cves: source.cves || [], actors: source.actors || [],
            malware: sanitizeStoredMalware(source.malware, source.title),
            campaigns: (story.campaigns || []).filter((campaign) => (source.campaigns || []).includes(campaign.id)),
            ttpIds: source.ttps || [], newsCategories: source.newsCategories || [],
            primaryCategory: NEWS_CATEGORIES.find((category) => (source.newsCategories || []).includes(category)) || null,
        });
    }
    for (const item of items) if (item?.link) byLink.set(canonicalArticleUrl(item.link) || item.link, item);
    const rebuilt = yield* mergeStorySteps([], [...byLink.values()], now);
    const targets = new Map(rebuilt.flatMap((story) => story.sources.map((source) => [canonicalArticleUrl(source.link) || source.link, story])));
    const addAliases = (target, aliases) => {
        target.aliases = [...new Set([...(target.aliases || []), ...aliases])].filter((id) => id && id !== target.id);
    };
    for (const old of stories) {
        const members = (old.sources || []).map((source) => targets.get(canonicalArticleUrl(source.link) || source.link)).filter(Boolean);
        if (!members.length) continue;
        const anchor = (old.sources || []).find((source) => storyId(canonicalArticleUrl(source.link) || source.link) === old.id);
        const target = anchor ? targets.get(canonicalArticleUrl(anchor.link) || anchor.link) : members[0];
        if (target) addAliases(target, [old.id, ...(old.aliases || [])]);
        // Legacy aggregate metadata is safe to retain only when ALL of its
        // publications still belong to one event. Never spread it across a
        // split, and never let it stand in for source-attributed merge evidence.
        if (target && new Set(members).size === 1 && members.length === (old.sources || []).length) {
            target.categories = NEWS_CATEGORIES.filter((category) => [...target.categories, ...(old.categories || [])].includes(category));
            target.primaryCategory = target.categories[0] || null;
            for (const field of ['actors', 'malware', 'campaigns']) {
                const legacy = field === 'malware' ? sanitizeStoredMalware(old[field], old.title) : old[field] || [];
                target[field] = [...new Map([...target[field], ...legacy].map((entity) => [entity.id, entity])).values()];
            }
        }
    }
    // Each URL hash belongs to the new cluster containing that publication.
    // Remove stale aggregate aliases from other clusters after a split.
    const owners = new Map(rebuilt.map((story) => [story.id, story]));
    for (const story of rebuilt) for (const source of story.sources) owners.set(storyId(canonicalArticleUrl(source.link) || source.link), story);
    for (const story of rebuilt) story.aliases = story.aliases.filter((id) => !owners.has(id) || owners.get(id) === story);
    return rebuilt;
}

const complete = steps => {
    let result = steps.next();
    while (!result.done) result = steps.next();
    return result.value;
};

export function mergeIntoStories(stories, items, now) {
    return complete(mergeStorySteps(stories, items, now));
}

export function rebuildStoryCorrelations(stories, items = [], now = new Date()) {
    return complete(rebuildStorySteps(stories, items, now));
}

// The production collector can compare thousands of retained publications.
// Yield between comparisons so worker polls/results and user requests stay live.
export async function mergeIntoStoriesAsync(stories, items, now) {
    const steps = mergeStorySteps(stories, items, now);
    let result = steps.next(), lastYield = performance.now();
    while (!result.done) {
        if (performance.now() - lastYield >= 8) { await yieldLoop(); lastYield = performance.now(); }
        result = steps.next();
    }
    return result.value;
}
