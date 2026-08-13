import crypto from 'node:crypto';

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
const JACCARD_THRESHOLD = 0.5;

// Static, not derived from the day's feed: a frequency-based stoplist would make
// the same pair of headlines group differently tomorrow.
const STOPWORDS = new Set([
    'about', 'after', 'against', 'amid', 'from', 'into', 'over', 'that', 'this', 'their', 'them', 'these', 'those',
    'with', 'without', 'have', 'been', 'were', 'will', 'more', 'most', 'than', 'then', 'they', 'what', 'when', 'which',
    'para', 'pelo', 'pela', 'como', 'mais', 'menos', 'sobre', 'entre', 'apos', 'contra', 'seus', 'suas', 'este', 'esta',
    'isso', 'pode', 'podem', 'sera', 'estao', 'foram',
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
]);

const normalize = (value) =>
    String(value || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');

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

const signals = (story) => {
    const rare = new Set(story.sources.flatMap((source) => rareTerms(source.title)));
    // The actor's own name is in both headlines by definition — two unrelated
    // Cl0p stories both say "Cl0p", and that is not evidence they are one story.
    // Rule 2 needs corroboration from somewhere else in the title.
    const actorTokens = new Set(story.actors.flatMap((actor) => rareTerms(`${actor.name} ${actor.matched || ''}`)));
    return {
        cves: new Set(story.cves),
        actors: new Set(story.actors.map((actor) => actor.id)),
        rare,
        rareBeyondActors: new Set([...rare].filter((term) => !actorTokens.has(term))),
    };
};

const isSameStory = (a, b) => {
    if (overlaps(a.cves, b.cves)) return true;
    if (overlaps(a.actors, b.actors) && overlaps(a.rareBeyondActors, b.rareBeyondActors)) return true;
    return jaccard(a.rare, b.rare) >= JACCARD_THRESHOLD;
};

const newStory = (item) => ({
    id: storyId(item.link),
    title: item.title,
    firstSeen: item.pubDate,
    lastSeen: item.pubDate,
    cves: [...(item.cves || [])],
    actors: [...(item.actors || [])],
    categories: [...(item.categories || [])],
    primaryCategory: item.primaryCategory || null,
    score: item.score || 0,
    sources: [{
        source: item.source, link: item.link, title: item.title,
        pubDate: item.pubDate, score: item.score || 0, severity: item.severity || null,
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

    const links = new Set(target.sources.map((source) => source.link));
    for (const source of extra.sources) if (!links.has(source.link)) merged.sources.push(source);

    // Title and primary category follow the loudest source, which is the one a
    // reader recognises: a CISA directive outranks a two-paragraph writeup.
    const loudest = merged.sources.reduce((best, source) => (source.score > best.score ? source : best), merged.sources[0]);
    merged.title = loudest.title;
    merged.primaryCategory = merged.categories[0] || null;
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
