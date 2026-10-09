import crypto from 'node:crypto';
import { mapConcurrent } from './feedCollector.js';

export const contentHash = (text) => crypto.createHash('sha256').update(String(text || '')).digest('hex');

// Body cache is independent of IOC presence: a report with no IOCs may still
// contain the CVEs, actors and techniques required to correlate coverage.
export async function collectArticleTexts(items, { fetchText, cache, now = new Date(), maxFetches = 40, concurrency = 3, ttlMs = 24 * 3600000 } = {}) {
    const texts = new Map();
    const queue = [];
    const stats = { fetched: 0, cached: 0, failed: 0, deferred: 0 };
    const budget = Number.isFinite(Number(maxFetches)) ? Math.max(0, Math.min(200, Math.floor(Number(maxFetches)))) : 40;
    const seen = new Set();
    for (const item of [...items].sort((a, b) => String(b.pubDate).localeCompare(String(a.pubDate)) || a.link.localeCompare(b.link))) {
        if (![2, 3].includes(Number(item.layer)) || !item.link || seen.has(item.link)) continue;
        seen.add(item.link);
        if ((item.text || '').length >= 1500) { item.articleCollectionStatus = 'feed-body'; continue; }
        const fingerprint = contentHash(item.title + '\n' + (item.text || item.description || ''));
        const previous = cache.get(item.link);
        const reusable = previous?.fingerprint === fingerprint;
        const age = now.getTime() - new Date(previous?.attemptedAt).getTime();
        if (reusable && age >= 0 && age < (previous.error ? 3600000 : ttlMs)) {
            if (previous.text) texts.set(item.link, previous.text);
            item.articleCollectionStatus = previous.error ? 'stale' : 'cached';
            stats.cached++;
            continue;
        }
        if (queue.length >= budget) {
            if (reusable && previous.text) texts.set(item.link, previous.text);
            item.articleCollectionStatus = reusable && previous.text ? 'stale' : 'deferred';
            stats.deferred++;
            continue;
        }
        queue.push({ item, fingerprint, previous: reusable ? previous : null });
    }
    await mapConcurrent(queue, concurrency, async ({ item, fingerprint, previous }) => {
        stats.fetched++;
        try {
            const text = String(await fetchText(item.link) || '').trim().slice(0, 32000);
            if (!text) throw new Error('Article returned no readable text');
            cache.set(item.link, { version: 1, link: item.link, fingerprint, text, contentHash: contentHash(text), attemptedAt: now.toISOString(), collectedAt: now.toISOString(), error: null });
            texts.set(item.link, text);
            item.articleCollectionStatus = 'fresh';
        } catch (error) {
            stats.failed++;
            if (previous?.text) texts.set(item.link, previous.text);
            item.articleCollectionStatus = previous?.text ? 'stale' : 'failed';
            // Cache failed attempts too, with a shorter retry window.
            try { cache.set(item.link, { ...previous, version: 1, link: item.link, fingerprint, attemptedAt: now.toISOString(), error: error.message }); } catch { /* source failure still does not stop the cycle */ }
        }
    });
    return { texts, stats };
}
