import { createHash } from 'node:crypto';

// Only passive provider lookups use this cache. Keys include the account and
// credential fingerprint; errors never become successful cached answers.
export function createLookupCache({ now = () => Date.now(), ttlMs = 300000, maxBytes = 16 * 1024 * 1024, maxEntries = 1000, maxPending = 128 } = {}) {
    const saved = new Map(), pending = new Map();
    let bytes = 0;
    const stats = { hits: 0, misses: 0, coalesced: 0, errors: 0 };
    const remove = key => { bytes -= saved.get(key)?.bytes || 0; saved.delete(key); };
    const reusable = value => value?.data && typeof value.data === 'object' && value.data.success !== false && !value.data.error && !value.data.errors && !/invalid|unauthorized|unknown_query/i.test(String(value.data.query_status || ''));
    return {
        async get({ provider, query, owner = '', credentials = '', fresh = false }, load) {
            const key = createHash('sha256').update(JSON.stringify([provider, query, owner, credentials])).digest('hex');
            const entry = saved.get(key);
            if (!fresh && entry && entry.expiresAt > now()) {
                stats.hits++; saved.delete(key); saved.set(key, entry);
                return { value: structuredClone(entry.value), state: 'hit', collectedAt: entry.collectedAt };
            }
            if (entry?.expiresAt <= now()) remove(key);
            if (pending.has(key)) { stats.coalesced++; return { ...await pending.get(key), state: 'shared' }; }
            if (pending.size >= maxPending) throw Object.assign(new Error('Lookup capacity reached'), { response: { status: 503 } });
            stats.misses++;
            const flight = Promise.resolve().then(load).then(value => {
                const collectedAt = new Date(now()).toISOString();
                if (reusable(value)) {
                    const size = Buffer.byteLength(JSON.stringify(value));
                    if (size <= Math.min(maxBytes, 1024 * 1024)) {
                        remove(key);
                        saved.set(key, { value: structuredClone(value), collectedAt, expiresAt: now() + ttlMs, bytes: size }); bytes += size;
                        while (bytes > maxBytes || saved.size > maxEntries) remove(saved.keys().next().value);
                    }
                }
                return { value, state: 'miss', collectedAt };
            }).catch(error => { stats.errors++; throw error; }).finally(() => pending.delete(key));
            pending.set(key, flight);
            return flight;
        },
        stats: () => ({ ...stats, entries: saved.size, pending: pending.size, bytes, ttlMs, maxBytes }),
    };
}
