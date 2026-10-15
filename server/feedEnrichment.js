import { scoreArticle, extractIOCs, ttpIdsFrom, isPureNoise, severityFromScore } from './ctiIntel.js';
import { contentHash } from './articleCollector.js';
import { analyzePhishing } from './phishingIntel.js';
import { setImmediate as yieldLoop } from 'node:timers/promises';
import { declaredRepositoryMalware } from './repositorySources.js';
import { removeVersionIndicators, isRelevantNews } from './newsQuality.js';

export const EXTRACTION_VERSION = 'feed-v13';

// Keep all mentioned CVEs for research/KEV, but use only the article's focus
// to group coverage. A patch report often recounts older, unrelated flaws.
export function topicCvesOf(title, feedText, bodyText = '') {
    const cves = (text) => [...new Set((String(text || '').match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map((cve) => cve.toUpperCase()))];
    const headline = cves(title);
    if (headline.length) return headline;
    for (const text of [bodyText, feedText]) {
        const blocks = String(text || '').split(/\n\s*\n|[\r\n]+/).filter(Boolean);
        const focus = blocks.slice(0, 8).find((block) => cves(block).length
            && /\b(?:tracked|identified|designated|assigned)\s+(?:as|under)\b/i.test(block)
            && !/\b(?:previous|earlier|older|last year)\b/i.test(block));
        if (focus) return cves(focus);
        for (const block of blocks) {
            const values = cves(block);
            if (values.length) return values;
        }
    }
    return [];
}

export const mergeIocEvidence = (...sets) => Object.fromEntries(['ips','domains','hashes','urls'].map(type => [type,[...new Set(sets.flatMap(set => set?.[type] || []))]]));

export function enrichFeedItems(items, { texts = new Map(), supplementalIocs = new Map(), actors, malware, campaigns, seller, categorize, extractionCache, catalogRevision } = {}) {
    return items.map((item) => {
        const compute = () => {
            const text = [item.title, item.text || item.description || '', texts.get(item.link) || ''].join('\n');
            const enriched = {
                ...scoreArticle(text, item.weight_boost),
                actors: actors(text), malware: [...new Map([...declaredRepositoryMalware(item),...malware(text)].map(family=>[family.name.toLowerCase(),family])).values()], campaigns: campaigns(text),
                iocs: removeVersionIndicators(mergeIocEvidence(item.repositoryReport ? item.iocs : extractIOCs(text), supplementalIocs.get(item.link)),text), sellerHandle: seller(text),
                contentHash: contentHash(text), extractionVersion: EXTRACTION_VERSION,
                articleTextAvailable: !!texts.get(item.link) || (item.text || '').length >= 1500 || item.repositoryReport === true,
                topicCves: topicCvesOf(item.title, item.text || item.description || '', texts.get(item.link) || ''),
            };
            enriched.phishingIntel = analyzePhishing({ title: item.title, description: item.text || item.description, bodyText: texts.get(item.link) });
            enriched.phishingTechniques = enriched.phishingIntel.techniques;
            enriched.threats = enriched.threats.filter(threat => threat !== 'Phishing');
            if (enriched.phishingIntel.detected) enriched.threats.push('Phishing');
            enriched.ttps = [...new Set([...enriched.ttps.filter(ttp => !/^T1566\b/.test(ttp)), ...enriched.phishingIntel.ttps.map(ttp => ttp.id)])];
            enriched.ttpIds = ttpIdsFrom(enriched.ttps);
            const result = categorize({ ...item, ...enriched, bodyText: texts.get(item.link) || '' });
            enriched.newsCategories = result.categories;
            enriched.primaryCategory = result.primary;
            return !isPureNoise(enriched.categories) && isRelevantNews({ ...item, ...enriched }) ? enriched : null;
        };
        const derived = extractionCache ? extractionCache.extract(item, {
            bodyText: texts.get(item.link) || '', supplementalIocs: supplementalIocs.get(item.link),
            extractionVersion: EXTRACTION_VERSION, catalogRevision,
        }, compute) : compute();
        return derived ? { ...item, ...derived } : null;
    }).filter(Boolean);
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

export async function enrichFeedItemsAsync(items, options) {
    const enriched = [];
    let lastYield = performance.now();
    for (const item of items) {
        enriched.push(...enrichFeedItems([item], options));
        if (performance.now() - lastYield >= 8) { await yieldLoop(); lastYield = performance.now(); }
    }
    return enriched;
}
