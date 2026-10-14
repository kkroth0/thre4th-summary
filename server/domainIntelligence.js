import { parse } from 'tldts';
import { domainToASCII } from 'node:url';
import { createHash } from 'node:crypto';

const string = value => typeof value === 'string' ? value.slice(0, 4096) : '';
const date = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value.endsWith('Z') || /[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`).toISOString() : null;
export function domainTarget(value) {
    if (typeof value !== 'string' || value.length > 253 || /[\s/:@?#\\]/.test(value.trim())) throw new Error('Invalid domain');
    const hostname = domainToASCII(value.trim().toLowerCase().replace(/\.$/, ''));
    const info = parse(hostname);
    if (hostname.length > 253 || !info.domain || !info.isIcann || info.isIp || !/^[a-z0-9.-]+$/.test(hostname)
        || hostname.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('Invalid domain');
    return { hostname, apex: info.domain };
}
export const inDomain = (name, domain) => name === domain || name.endsWith(`.${domain}`);
export function normalizeSubdomains(raw, domain) {
    if (!Array.isArray(raw) || raw.some(row => !row || typeof row.sub !== 'string')) throw new Error('Invalid crt.name response');
    const found = new Map();
    for (const row of raw) {
        if (/[\s/:@?#\\]/.test(row.sub)) continue;
        const hostname = domainToASCII(row.sub.toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''));
        if (!inDomain(hostname, domain) || !/^[a-z0-9.-]+$/.test(hostname)) continue;
        try { domainTarget(hostname); } catch { continue; }
        const firstSeen = date(row.first_seen);
        const previous = found.get(hostname);
        if (!previous || firstSeen && (!previous.firstSeen || firstSeen < previous.firstSeen)) found.set(hostname, { hostname, firstSeen, source: 'crt.name' });
    }
    const hosts = [...found.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
    return { hosts: hosts.slice(0, 20_000), total: hosts.length, truncated: hosts.length > 20_000 };
}
export function normalizeCertificates(raw, domain) {
    if (!Array.isArray(raw) || raw.some(row => !row || !Number.isSafeInteger(Number(row.id)) || Number(row.id) <= 0 || typeof row.name_value !== 'string')) throw new Error('Invalid crt.sh response');
    const rows = new Map();
    for (const row of raw) {
        const names = [...new Set(row.name_value.split(/\r?\n/).map(name => name.trim().toLowerCase()).filter(Boolean))];
        if (!names.some(name => inDomain(name.replace(/^\*\./, ''), domain))) continue;
        rows.set(String(row.id), { id: String(row.id), names: names.slice(0, 100), issuer: string(row.issuer_name), commonName: string(row.common_name),
            notBefore: date(row.not_before), notAfter: date(row.not_after), loggedAt: date(row.entry_timestamp), serial: string(row.serial_number), source: 'crt.sh' });
    }
    const certificates = [...rows.values()].sort((a, b) => (b.notBefore || '').localeCompare(a.notBefore || ''));
    return { certificates: certificates.slice(0, 1000), total: certificates.length, truncated: certificates.length > 1000 };
}
const recordsOf = records => Object.fromEntries(Object.entries(records || {}).filter(([type, values]) => /^(A|AAAA|MX|NS|SOA|TXT|CNAME)$/.test(type) && Array.isArray(values))
    .map(([type, values]) => [type, values.filter(value => typeof value === 'string').slice(0, 100).map(string)]));
export function normalizeDnsHistory(raw, domain) {
    if (!raw || !Array.isArray(raw.changes) || typeof raw.domain !== 'string' || !inDomain(domain, raw.domain) || raw.pagination?.next_cursor != null && typeof raw.pagination.next_cursor !== 'string') throw new Error('Invalid Who.is DNS history');
    return { changes: raw.changes.filter(row => typeof row?.hostname === 'string' && inDomain(row.hostname, domain)).map(row => ({ hostname: row.hostname, firstSeen: date(row.first_seen), lastSeen: date(row.last_seen), current: row.current === true,
        provider: string(row.provider_name), records: recordsOf(row.records), source: 'Who.is' })), nextCursor: raw.pagination?.next_cursor || null, snapshotTime: date(raw.snapshot_time) };
}

// Passive lookups only. Cached per upstream credential; no browser challenges,
// certificate probing, downloads, paid live refresh or automatic page crawling.
export function createDomainIntelligence({ http, getWhoisKey, onQuota = () => {}, now = () => Date.now(), readObservations = () => ({}), saveObservations = () => {} }) {
    const cache = new Map(); const pending = new Map(); let observations; let cacheBytes = 0;
    try { observations = readObservations() || {}; } catch { observations = {}; }
    async function cached(key, ttl, run) {
        const saved = cache.get(key); if (saved && now() - saved.at < saved.ttl) return saved.result;
        if (pending.has(key)) return pending.get(key);
        const request = run().then(result => {
            const size = Buffer.byteLength(JSON.stringify(result));
            cacheBytes -= cache.get(key)?.size || 0;
            cache.set(key, { at: now(), ttl: result.status === 'available' ? ttl : 60_000, result, size }); cacheBytes += size;
            while (cache.size > 200 || cacheBytes > 64_000_000) { const first = cache.keys().next().value; cacheBytes -= cache.get(first).size; cache.delete(first); }
            return result;
        }).finally(() => pending.delete(key));
        pending.set(key, request); return request;
    }
    const unavailable = (source, error) => ({ source, status: 'unavailable', error: error.response?.status === 403 ? 'plan_required' : error.response?.status === 429 ? 'rate_limited' : 'upstream_unavailable' });
    const options = { timeout: 15_000, maxContentLength: 10_000_000, maxRedirects: 0 };
    return {
        observe(domain, records) {
            domain = domainTarget(domain).hostname; records = recordsOf(records);
            if (!Object.values(records).some(values => values.length)) return;
            const at = new Date(now()).toISOString();
            const history = Array.isArray(observations[domain]) ? observations[domain] : [];
            const signature = JSON.stringify(Object.entries(records).sort().map(([type, values]) => [type, [...values].sort()]));
            const previous = history.at(-1);
            if (previous?.signature === signature) previous.lastSeen = at;
            else history.push({ hostname: domain, firstSeen: at, lastSeen: at, records, signature, source: 'ThreatSumm4ry' });
            delete observations[domain]; observations[domain] = history.slice(-100);
            if (Object.keys(observations).length > 2000) delete observations[Object.keys(observations)[0]];
            try { saveObservations(observations); } catch { /* lookup still works if disk is unavailable */ }
        },
        async subdomains(value) {
            const { hostname, apex } = domainTarget(value);
            const result = await cached(`hosts:${apex}`, 86_400_000, async () => {
                try {
                    const response = await http.get('https://crt.name/v1/search', { ...options, params: { apex, format: 'json', dates: '1' } });
                    return { status: 'available', source: 'crt.name', apex, fetchedAt: new Date(now()).toISOString(), ...normalizeSubdomains(response.data, apex) };
                } catch (error) { return { ...unavailable('crt.name', error), apex, hosts: [] }; }
            });
            const hosts = result.hosts.filter(row => inDomain(row.hostname, hostname));
            return { ...result, hostname, hosts, total: hostname === apex ? result.total : hosts.length };
        },
        async certificates(value) {
            const { hostname } = domainTarget(value);
            return cached(`certs:${hostname}`, 3600_000, async () => {
                try {
                    const response = await http.get('https://crt.sh/', { ...options, params: { q: hostname, output: 'json' } });
                    return { status: 'available', source: 'crt.sh', fetchedAt: new Date(now()).toISOString(), ...normalizeCertificates(response.data, hostname) };
                } catch (error) { return { ...unavailable('crt.sh', error), certificates: [] }; }
            });
        },
        async history(value, cursor = '') {
            const { hostname } = domainTarget(value); const key = getWhoisKey();
            if (typeof cursor !== 'string' || cursor.length > 2048) throw new Error('Invalid cursor');
            const fingerprint = createHash('sha256').update(key || '').digest('hex');
            const remote = await cached(`history:${fingerprint}:${hostname}:${cursor}`, 600_000, async () => {
                if (!key) return { source: 'Who.is', status: 'unavailable', error: 'key_missing', changes: [] };
                try {
                    const response = await http.get(`https://api.who.is/v1/dns/${encodeURIComponent(hostname)}/changes`, { ...options, headers: { Authorization: `Bearer ${key}` }, params: { limit: 100, ...(cursor ? { cursor } : {}) } });
                    onQuota(response.headers, key);
                    return { source: 'Who.is', status: 'available', ...normalizeDnsHistory(response.data, hostname) };
                } catch (error) { if (error.response?.headers) onQuota(error.response.headers, key); return { ...unavailable('Who.is', error), changes: [] }; }
            });
            const local = (observations[hostname] || []).map((row, index, rows) => ({ hostname, firstSeen: row.firstSeen, lastSeen: row.lastSeen, records: row.records, current: index === rows.length - 1, provider: '', source: 'ThreatSumm4ry' }));
            return { ...remote, local, externalUrl: `https://dnshistory.org/`, fetchedAt: new Date(now()).toISOString() };
        },
    };
}
