import { scoreArticle, extractIOCs, ttpIdsFrom, isPureNoise, severityFromScore } from './ctiIntel.js';
import { contentHash } from './articleCollector.js';

export const EXTRACTION_VERSION = 'feed-v3';

export function enrichFeedItems(items, { texts = new Map(), actors, malware, campaigns, seller, categorize } = {}) {
    return items.map((item) => {
        const text = [item.title, item.text || item.description || '', texts.get(item.link) || ''].join('\n');
        const enriched = {
            ...item, ...scoreArticle(text, item.weight_boost),
            actors: actors(text), malware: malware(text), campaigns: campaigns(text),
            iocs: extractIOCs(text), sellerHandle: seller(text),
            contentHash: contentHash(text), extractionVersion: EXTRACTION_VERSION,
        };
        enriched.ttpIds = ttpIdsFrom(enriched.ttps);
        const result = categorize(enriched);
        enriched.newsCategories = result.categories;
        enriched.primaryCategory = result.primary;
        return enriched;
    }).filter((item) => !isPureNoise(item.categories));
}

export function applyVulnerabilityContext(items, kevMap, epssMap) {
    for (const item of items) {
        const hit = item.cves.find((cve) => kevMap.has(cve));
        if (hit) {
            const data = kevMap.get(hit);
            item.kev = true;
            item.kevDetails = { cve: hit, dateAdded: data.dateAdded, dueDate: data.dueDate, ransomware: data.ransomware };
            item.score = Math.min(100, item.score + 25);
            item.severity = severityFromScore(item.score);
            item.reasons.push('CISA KEV — Actively Exploited (' + hit + ')');
        }
        const values = item.cves.map((cve) => epssMap.get(cve)).filter((n) => typeof n === 'number');
        if (values.length) item.epss = Math.max(...values);
    }
    return items;
}
