// Passive reputation lookups. No URL is submitted for crawling or visited here.
export const PHISHING_LOOKUP_SOURCES = ['OpenPhish', 'PhishStats', 'PhishTank'];

export function parseOpenPhishFeed(text) {
    if (typeof text !== 'string') throw new Error('Invalid OpenPhish feed');
    const urls = text.split(/\r?\n/).map(value => value.trim()).filter(value => /^https?:\/\//i.test(value));
    if (!urls.length) throw new Error('Empty or invalid OpenPhish feed');
    return [...new Set(urls)];
}

export function matchOpenPhish(urls, query, type) {
    if (type === 'url') return urls.includes(query);
    const domain = query.toLowerCase();
    return urls.some(value => {
        try { const hostname = new URL(value).hostname.toLowerCase(); return hostname === domain || hostname.endsWith('.' + domain); }
        catch { return false; }
    });
}

export function validatePhishTank(data) {
    if (!data || typeof data.results?.in_database !== 'boolean') throw new Error('Invalid PhishTank response');
    return data;
}

export function createPhishingSources({ http, getKey = () => '', now = () => Date.now() }) {
    const activity = new Map(); let feed = null; let pendingFeed = null;
    const queryCache = new Map(); const pendingQueries = new Map();
    const observed = async (name, run) => {
        const previous = activity.get(name);
        try {
            const result = await run();
            activity.set(name, { state: 'healthy', lastChecked: new Date(now()).toISOString(), httpStatus: 200, requests: (previous?.requests || 0) + 1 });
            return result;
        } catch (error) {
            activity.set(name, { state: 'failed', lastChecked: new Date(now()).toISOString(), httpStatus: error.response?.status || 502, requests: (previous?.requests || 0) + 1 });
            throw error;
        }
    };
    return {
        activity: () => Object.fromEntries(PHISHING_LOOKUP_SOURCES.map(name => [name, { mode: 'on_demand', keyConfigured: name === 'OpenPhish' ? false : Boolean(getKey(name === 'PhishStats' ? 'phishstats' : 'phishtank')), ...(activity.get(name) || { state: 'unchecked', lastChecked: null, httpStatus: null, requests: 0 }) }])),
        async openPhish(query, type) {
            if (!feed || now() - feed.at >= 1800_000) {
                if (!pendingFeed) pendingFeed = observed('OpenPhish', async () => {
                    const response = await http.get('https://openphish.com/feed.txt', { timeout: 8000, maxContentLength: 5_000_000, maxRedirects: 3 });
                    feed = { urls: parseOpenPhishFeed(response.data), at: now() };
                }).finally(() => { pendingFeed = null; });
                await pendingFeed;
            }
            const listed = matchOpenPhish(feed.urls, query, type);
            return { listed, status: listed ? 'Listed as phishing' : 'Not found in OpenPhish feed' };
        },
        async phishStats(query) {
            // Never place the API key in a URL, cache key or returned activity data.
            const cached = queryCache.get(query);
            if (cached && now() - cached.at < 5400_000) return cached.rows;
            if (pendingQueries.has(query)) return pendingQueries.get(query);
            const pending = observed('PhishStats', async () => {
                const key = getKey('phishstats');
                // xmysql's _where grammar cannot safely represent arbitrary URL commas/parens.
                // Search by hostname, then enforce the exact URL or hostname boundary locally.
                const isUrl = /^https?:\/\//i.test(query);
                const hostname = isUrl ? new URL(query).hostname : query.toLowerCase();
                const response = await http.get('https://api.phishstats.info/api/phishing', {
                    headers: key ? { 'X-API-Key': key } : {}, timeout: 10_000, maxContentLength: 2_000_000, maxRedirects: 0,
                    params: { _where: `(url,like,${hostname})`, _sort: '-date', _size: 100 },
                });
                if (!Array.isArray(response.data)) throw new Error('Invalid PhishStats response');
                const rows = response.data.filter(row => row && typeof row.url === 'string' && (isUrl ? row.url === query : matchOpenPhish([row.url], query, 'domain'))).slice(0, 5);
                queryCache.set(query, { at: now(), rows });
                if (queryCache.size > 1000) queryCache.delete(queryCache.keys().next().value);
                return rows;
            }).finally(() => pendingQueries.delete(query));
            pendingQueries.set(query, pending); return pending;
        },
        phishTank(query) {
            return observed('PhishTank', async () => {
                const params = new URLSearchParams({ url: query, format: 'json' });
                const key = getKey('phishtank'); if (key) params.set('app_key', key);
                const response = await http.post('https://checkurl.phishtank.com/checkurl/', params.toString(), {
                    timeout: 10_000, maxContentLength: 2_000_000, maxRedirects: 0,
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'phishtank/threatsumm4ry' },
                });
                return validatePhishTank(response.data);
            });
        },
    };
}
