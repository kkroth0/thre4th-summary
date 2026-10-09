// A read-only derived view over an already-built Story: not a merge decision
// (that stays in newsStories.js), just an explanation of what two or more of
// its sources actually have in common. Kept as its own module rather than
// folded into newsStories.js for the same reason actorMatch.js/newsIocs.js
// are their own files — one small module, one job.
import { rareTerms } from './newsStories.js';

const normIoc = (value) => String(value || '').trim().toLowerCase();

// A value only one source mentions is a fact about that one article, not
// evidence two articles are related — only keep values >=2 distinct links share.
function sharedValues(pairs) {
    const byValue = new Map();
    for (const { value, link } of pairs) {
        if (!value || !link) continue;
        if (!byValue.has(value)) byValue.set(value, new Set());
        byValue.get(value).add(link);
    }
    const out = [];
    for (const [value, links] of byValue) {
        if (links.size >= 2) out.push({ value, sourceLinks: [...links] });
    }
    return out;
}

const IOC_FIELDS = [['hashes', 'ioc-hash'], ['domains', 'ioc-domain'], ['urls', 'ioc-url'], ['ips', 'ioc-ip']];

/**
 * `[{ type, value, sourceLinks }]` — one entry per value that >=2 of the
 * story's sources share. `type` is one of: cve, campaign, actor, malware,
 * ioc-hash, ioc-domain, ioc-url, ioc-ip, ttp, rare-term. A single-source
 * story has nothing to correlate, so it always returns [].
 */
export function explainCorrelation(story) {
    if (!story || !Array.isArray(story.sources) || story.sources.length < 2) return [];

    const evidence = [];

    // CVE, campaign and TTP ids, plus IOCs, all have real per-source tracking
    // (story.sources[].cves/campaigns/ttps/iocs) — so "shared by >=2 sources"
    // is literally checked, not assumed.
    const cvePairs = story.sources.flatMap((s) => (s.cves || []).map((cve) => ({ value: cve, link: s.link })));
    for (const hit of sharedValues(cvePairs)) evidence.push({ type: 'cve', ...hit });

    // Campaign ids are per-source, but the display name only lives on the
    // story-level union (newStory() keeps the full {id,name} object there,
    // same as actors/malware) — look it up for a readable chip value.
    const campaignNameById = new Map((story.campaigns || []).map((c) => [c.id, c.name]));
    const campaignPairs = story.sources.flatMap((s) => (s.campaigns || []).map((id) => ({ value: id, link: s.link })));
    for (const hit of sharedValues(campaignPairs)) {
        evidence.push({ type: 'campaign', ...hit, value: campaignNameById.get(hit.value) || hit.value });
    }

    for (const [field, type] of IOC_FIELDS) {
        const pairs = story.sources.flatMap((s) =>
            (s.iocs?.[field] || []).map((value) => ({ value: normIoc(value), link: s.link })));
        for (const hit of sharedValues(pairs)) evidence.push({ type, ...hit });
    }

    // Legacy stories without per-source attribution are not evidence that
    // every publication mentioned an entity. Only actual shared mentions count.
    const entities = [...(story.actors || []), ...(story.malware || []), ...(story.campaigns || [])];
    for (const [field, type] of [["actors", "actor"], ["malware", "malware"]]) {
        const names = new Map((story[field] || []).map((entity) => [entity.id, entity.name]));
        const pairs = story.sources.flatMap((source) => (source[field] || []).map((entity) => ({ value: entity.id, link: source.link })));
        for (const hit of sharedValues(pairs)) evidence.push({ type, ...hit, value: names.get(hit.value) || hit.value });
    }
    // TTP ids are per-source too (story.sources[].ttps) — real >=2-of-N count,
    // same precision as CVE/campaign/IOC.
    const ttpPairs = story.sources.flatMap((s) => (s.ttps || []).map((id) => ({ value: id, link: s.link })));
    for (const hit of sharedValues(ttpPairs)) evidence.push({ type: 'ttp', ...hit });

    // Rare-term fallback: the evidence behind a pure-Jaccard match with no
    // shared entity/CVE/IOC at all (the SilkParasite case in
    // newsStories.test.js). Excludes tokens that are themselves an actor's,
    // malware's or campaign's own name — those already have their own chip
    // above, and showing "shared word: lummac2" next to "malware: LummaC2" is
    // noise, not new information.
    const entityTokens = new Set(entities.flatMap((e) => rareTerms(`${e.name} ${e.matched || ''}`)));
    const termPairs = story.sources.flatMap((s) =>
        rareTerms(s.title).filter((term) => !entityTokens.has(term)).map((term) => ({ value: term, link: s.link })));
    for (const hit of sharedValues(termPairs)) evidence.push({ type: 'rare-term', ...hit });

    return evidence;
}
