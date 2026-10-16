import crypto from 'node:crypto';
import { mapConcurrent } from './feedCollector.js';

export const contentHash = (text) => crypto.createHash('sha256').update(String(text || '')).digest('hex');
const ARTICLE_TEXT_VERSION = 2;

// Body cache is independent of IOC presence: a report with no IOCs may still
// contain the CVEs, actors and techniques required to correlate coverage.
export async function collectArticleTexts(items, { fetchText, cache, now = new Date(), maxFetches = 40, concurrency = 3, ttlMs = 24 * 3600000 } = {}) {
    const texts = new Map();
    const supplementalIocs = new Map();
    const candidates = [];
    const stats = { fetched: 0, cached: 0, failed: 0, deferred: 0 };
    const budget = Number.isFinite(Number(maxFetches)) ? Math.max(0, Math.min(200, Math.floor(Number(maxFetches)))) : 40;
    const seen = new Set();
    for (const item of [...items].sort((a, b) => String(b.pubDate).localeCompare(String(a.pubDate)) || a.link.localeCompare(b.link))) {
        if (![2, 3].includes(Number(item.layer)) || !item.link || seen.has(item.link)) continue;
        seen.add(item.link);
        if (item.repositoryReport) { item.articleCollectionStatus = 'repository-body'; continue; }
        const fingerprint = contentHash(item.title + '\n' + (item.text || item.description || ''));
        const previous = cache.get(item.link);
        const reusable = previous?.version === ARTICLE_TEXT_VERSION && previous?.fingerprint === fingerprint;
        if (reusable && previous.supplementalIocs) supplementalIocs.set(item.link, previous.supplementalIocs);
        if ((item.text || '').length >= 1500) {
            if (reusable && previous.supplementalIocs && previous.text) texts.set(item.link, previous.text);
            item.articleCollectionStatus = 'feed-body'; continue;
        }
        const age = now.getTime() - new Date(previous?.attemptedAt).getTime();
        const failures = Math.max(1, Math.min(6, Number(previous?.failures) || 1));
        const retryMs = Math.min(24 * 3600000, 3600000 * 2 ** (failures - 1));
        if (reusable && age >= 0 && age < (previous.error ? retryMs : ttlMs)) {
            if (previous.text) texts.set(item.link, previous.text);
            item.articleCollectionStatus = previous.error ? 'stale' : 'cached';
            stats.cached++;
            continue;
        }
        candidates.push({ item, fingerprint, previous: reusable ? previous : null });
    }
    // Unattempted/changed articles precede retries and routine body refreshes.
    // Round-robin publishers so one busy or blocked site cannot take all slots.
    const queue = [];
    for (const group of [candidates.filter(row => !row.previous), candidates.filter(row => row.previous?.error), candidates.filter(row => row.previous && !row.previous.error)]) {
        group.sort((a, b) => String(a.previous?.attemptedAt || '').localeCompare(String(b.previous?.attemptedAt || '')));
        const origins = new Map();
        for (const row of group) {
            let origin; try { origin = new URL(row.item.link).hostname; } catch { origin = row.item.link; }
            if (!origins.has(origin)) origins.set(origin, []);
            origins.get(origin).push(row);
        }
        while (origins.size) for (const [origin, rows] of origins) {
            const row = rows.shift();
            if (queue.length < budget) queue.push(row);
            else {
                if (row.previous?.text) texts.set(row.item.link, row.previous.text);
                row.item.articleCollectionStatus = row.previous?.text ? 'stale' : 'deferred';
                stats.deferred++;
            }
            if (!rows.length) origins.delete(origin);
        }
    }
    stats.publishers = new Set(queue.map(({ item }) => { try { return new URL(item.link).hostname; } catch { return item.link; } })).size;
    stats.firstAttempts = queue.filter(row => !row.previous).length;
    stats.retries = queue.filter(row => row.previous?.error).length;
    stats.refreshes = queue.length - stats.firstAttempts - stats.retries;
    await mapConcurrent(queue, concurrency, async ({ item, fingerprint, previous }) => {
        stats.fetched++;
        try {
            const collected = await fetchText(item.link);
            const text = String(typeof collected === 'string' ? collected : collected?.text || '').trim().slice(0, 64000);
            if (!text) throw new Error('Article returned no readable text');
            const supplements = previous?.contentHash === contentHash(text) ? previous?.supplementalIocs : undefined;
            if (supplements) supplementalIocs.set(item.link, supplements); else supplementalIocs.delete(item.link);
            cache.set(item.link, { version: ARTICLE_TEXT_VERSION, link: item.link, fingerprint, text, contentHash: contentHash(text), artifactLinks: collected?.artifactLinks || [], supplementalIocs: supplements, attemptedAt: now.toISOString(), collectedAt: now.toISOString(), error: null, failures: 0 });
            texts.set(item.link, text);
            item.articleCollectionStatus = 'fresh';
        } catch (error) {
            stats.failed++;
            if (previous?.text) texts.set(item.link, previous.text);
            item.articleCollectionStatus = previous?.text ? 'stale' : 'failed';
            // Cache failed attempts too, with a shorter retry window.
            try { cache.set(item.link, { ...previous, version: ARTICLE_TEXT_VERSION, link: item.link, fingerprint, attemptedAt: now.toISOString(), error: error.message, failures: Math.min(6, (Number(previous?.failures) || 0) + 1) }); } catch { /* source failure still does not stop the cycle */ }
        }
    });
    return { texts, supplementalIocs, stats };
}
