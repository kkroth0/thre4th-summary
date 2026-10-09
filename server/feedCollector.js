import crypto from 'node:crypto';
import path from 'node:path';

export const canonicalArticleUrl = (value, base) => {
    try {
        if (!String(value || '').trim()) return null;
        const url = new URL(String(value || '').trim(), base);
        if (!['http:', 'https:'].includes(url.protocol)) return null;
        url.hash = '';
        for (const key of [...url.searchParams.keys()]) {
            if (/^(utm_.+|fbclid|gclid|mc_cid|mc_eid|feature)$/i.test(key)) url.searchParams.delete(key);
        }
        url.searchParams.sort();
        return url.toString();
    } catch { return null; }
};

export function createFeedCache({ directory, fs, writeJsonAtomic }) {
    fs.mkdirSync(directory, { recursive: true });
    const file = (key) => path.join(directory, crypto.createHash('sha256').update(key).digest('hex') + '.json');
    return {
        get(key) {
            try { return JSON.parse(fs.readFileSync(file(key), 'utf8')); } catch { return null; }
        },
        set(key, value) { writeJsonAtomic(file(key), value); },
        prune({ maxEntries = 1500 } = {}) {
            const files = fs.readdirSync(directory).filter((name) => /^[a-f0-9]{64}\.json$/.test(name))
                .map((name) => ({ name, time: fs.statSync(path.join(directory, name)).mtimeMs }))
                .sort((a, b) => b.time - a.time || a.name.localeCompare(b.name));
            for (const entry of files.slice(maxEntries)) fs.unlinkSync(path.join(directory, entry.name));
        },
    };
}

export async function mapConcurrent(values, concurrency, mapper) {
    const limit = Math.max(1, Math.min(16, Math.floor(Number(concurrency)) || 1));
    const results = new Array(values.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(limit, values.length) }, async () => {
        while (next < values.length) {
            const index = next++;
            results[index] = await mapper(values[index], index);
        }
    }));
    return results;
}

// Concurrent callers share one cycle; source edits queue one extra cycle.
export function singleFlightRefresh(run) {
    let pending = null;
    let rerun = false;
    return function refresh({ force = false } = {}) {
        if (pending) { if (force) rerun = true; return pending; }
        pending = (async () => {
            do { rerun = false; await run(); } while (rerun);
        })().finally(() => { pending = null; });
        return pending;
    };
}

export function createFeedCollector({ request, parse, cache, now = () => new Date(), concurrency = 6, retentionDays = 30, maxItems = 100 }) {
    const retained = (items, at) => (Array.isArray(items) ? items : []).filter((item) =>
        typeof item?.link === 'string' && typeof item.pubDate === 'string' && new Date(item.pubDate).getTime() >= at.getTime() - retentionDays * 86400000)
        .sort((a, b) => b.pubDate.localeCompare(a.pubDate) || a.link.localeCompare(b.link)).slice(0, maxItems);
    return {
        async collect(feeds) {
            const at = now();
            const rows = await mapConcurrent(feeds, concurrency, async (feed) => {
                const previous = cache.get(feed.url);
                const oldItems = retained(previous?.items, at);
                const headers = {};
                if (previous?.etag) headers['If-None-Match'] = previous.etag;
                if (previous?.lastModified) headers['If-Modified-Since'] = previous.lastModified;
                try {
                    const response = await request(feed.url, { headers });
                    if (response.status !== 304 && (response.status < 200 || response.status >= 300)) throw new Error('Feed HTTP ' + response.status);
                    if (response.status === 304 && !Array.isArray(previous?.items)) throw new Error('304 without a cached feed');
                    const parsed = response.status === 304 ? [] : parse(response.data, feed.source, feed.layer, { feedUrl: feed.url, now: at });
                    const byLink = new Map(oldItems.map((item) => [item.link, item]));
                    for (const item of parsed) {
                        const link = canonicalArticleUrl(item.link, feed.url);
                        if (!link) continue;
                        const old = byLink.get(link);
                        const pubDate = item.dateInferred && old ? old.pubDate : item.pubDate;
                        byLink.set(link, { ...item, link, pubDate, firstCollectedAt: old?.firstCollectedAt || at.toISOString(), collectedAt: at.toISOString() });
                    }
                    const items = retained([...byLink.values()], at);
                    const next = { version: 1, items, lastSuccessfulAt: at.toISOString(), etag: response.status === 304 ? previous.etag : response.headers?.etag || null, lastModified: response.status === 304 ? previous.lastModified : response.headers?.['last-modified'] || null };
                    cache.set(feed.url, next);
                    return { items: items.map((item) => ({ ...item, weight_boost: feed.weight_boost, feedUrl: feed.url, collectionStatus: response.status === 304 ? 'unchanged' : 'fresh' })), health: { ok: true, count: items.length, fetchedCount: parsed.length, status: response.status === 304 ? 'unchanged' : 'fresh', lastSuccessfulAt: next.lastSuccessfulAt, error: null, at: at.toISOString() } };
                } catch (error) {
                    return { items: oldItems.map((item) => ({ ...item, weight_boost: feed.weight_boost, feedUrl: feed.url, collectionStatus: 'stale' })), health: { ok: false, count: oldItems.length, fetchedCount: 0, status: oldItems.length ? 'stale' : 'failed', lastSuccessfulAt: previous?.lastSuccessfulAt || null, error: error.message, at: at.toISOString() } };
                }
            });
            return { items: rows.flatMap((row) => row.items), health: new Map(feeds.map((feed, i) => [feed.url, rows[i].health])) };
        },
    };
}
