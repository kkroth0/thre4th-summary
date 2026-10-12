export function normalizeWhois(data) {
    if (!data || typeof data.domain !== 'string' || !Array.isArray(data.events)) throw new Error('Invalid Who.is response');
    const event = action => data.events.find(item => item.event_action === action)?.event_date || null;
    return { source: 'Who.is', WhoisRecord: {
        domainName: data.domain, registrarName: data.registrar || null,
        createdDate: event('registration'), expiresDate: event('expiration'), updatedDate: event('last changed'),
        status: Array.isArray(data.statuses) ? data.statuses.filter(value => typeof value === 'string') : [],
        nameServers: (data.nameservers || []).map(item => typeof item === 'string' ? item : item.ldh_name).filter(Boolean),
        snapshotTime: data.snapshot_time || null,
    } };
}

export function createWhoisLookup({ http, getKey, now = () => Date.now() }) {
    const cache = new Map(); const pending = new Map();
    return async domain => {
        const key = getKey();
        if (!key) throw new Error('Who.is API key missing');
        const saved = cache.get(domain); if (saved && now() - saved.at < 1800_000) return saved.data;
        if (pending.has(domain)) return pending.get(domain);
        const request = (async () => {
            const response = await http.get(`https://api.who.is/v1/whois/${encodeURIComponent(domain)}`, {
                headers: { Authorization: `Bearer ${key}` }, timeout: 10_000, maxContentLength: 2_000_000, maxRedirects: 0,
            });
            const data = normalizeWhois(response.data);
            cache.set(domain, { at: now(), data }); if (cache.size > 1000) cache.delete(cache.keys().next().value);
            return data;
        })().finally(() => pending.delete(domain));
        pending.set(domain, request); return request;
    };
}
