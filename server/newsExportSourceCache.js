import { isRelevantNews } from './newsQuality.js';

// Read only enabled source keys. The combined newsletter snapshot may be
// weeks behind these files if a collection cycle failed before publication.
export function createNewsExportSourceCache(cache, now = Date.now) {
    let cached;
    return function readSources(sources) {
        const urls = [...new Set(sources.map(source => source.url))].sort();
        const key = JSON.stringify(urls);
        if (cached?.key === key && (cached.pending || cached.expires > now())) return cached.promise;
        const entry = { key, pending: true };
        entry.promise = (async () => {
            const rows = new Map();
            for (const url of urls) {
                const page = await cache.getAsync(url);
                for (const row of Array.isArray(page?.items) ? page.items : []) {
                    if (!row?.link || !row.title || !isRelevantNews(row)) continue;
                    const { link, title, source, pubDate, dateInferred, firstCollectedAt, description, layer, vendors } = row;
                    rows.set(link, { link, title, source, pubDate, dateInferred, firstCollectedAt, description, layer, vendors,
                        analysisStatus: 'Análise pendente' });
                }
            }
            entry.expires = now() + 60_000;
            return [...rows.values()];
        })().finally(() => { entry.pending = false; });
        cached = entry;
        return entry.promise;
    };
}
